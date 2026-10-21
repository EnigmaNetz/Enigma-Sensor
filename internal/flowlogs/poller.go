package flowlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
)

const (
	// trackWindow is how far before the last committed poll the poller looks for blobs that
	// changed, and how long a fully read blob stays tracked after its last change. On a first
	// start it is how far back the poller reads: the current and previous hour's blobs, and
	// Azure's late writes to them.
	trackWindow = 2 * time.Hour

	// maxLookback caps how far back a poll looks after the sensor has been stopped or failing.
	// Blobs older than that are skipped, and the skip is logged.
	maxLookback = 24 * time.Hour

	// lastPollEvery is how often LastPoll is moved forward when nothing else changed, so an
	// idle poller does not rewrite its state file every poll.
	lastPollEvery = 10 * time.Minute

	// failureLogEvery is how often a failure that keeps repeating is logged again.
	failureLogEvery = time.Hour

	// connLog is the file written in each poll's output directory.
	connLog = "conn.log"
)

// Uploader uploads a poll's conn.log. *api.LogUploader implements it. A nil Uploader (upload
// turned off) leaves each conn.log on disk and still moves on.
type Uploader interface {
	UploadLogs(ctx context.Context, files api.LogFiles) error
}

// PollerConfig configures a Poller.
type PollerConfig struct {
	Store     BlobStore
	Uploader  Uploader
	Converter Options
	// OutputDir holds each poll's zeek_out_flowlog_<time> directory, beside the capture
	// directories, so retention cleanup and support bundles cover it.
	OutputDir string
	StatePath string
	Interval  time.Duration
	// ExcludedSubnets are dropped from conn.log before upload, as from a capture.
	ExcludedSubnets []string
	// DeleteAfterUpload removes each poll's directory once it is uploaded.
	DeleteAfterUpload bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Poller reads new flow log records from a container every Interval, converts them and uploads
// the resulting conn.log through the sensor's uploader.
type Poller struct {
	cfg PollerConfig
	// committed is the encoded state as of the last poll whose records were safely uploaded or
	// buffered. Each poll starts from it and replaces it only on success.
	committed []byte
	roots     []string
	rootsAt   time.Time
	// noAddress holds the newest blobs that were read for a NIC's addresses but held none, so
	// they are not read again every poll; the NIC is tried again with its next blob. A NIC that
	// did teach one is known from the state instead, which survives only if the poll commits,
	// so a failed poll learns it again.
	noAddress map[string]bool
	// failure is the kind of the failure that keeps repeating, how often, and when it was last
	// logged
	failure       string
	failures      int
	failureLogged time.Time
}

// NewPoller returns a poller. Open loads its state; Run opens it if that has not been done.
func NewPoller(cfg PollerConfig) *Poller {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Poller{cfg: cfg, noAddress: map[string]bool{}}
}

// Open loads the state file. The sensor calls it before starting the poller, so a state file
// that cannot be read stops the sensor rather than leaving it running without the poller.
func (p *Poller) Open() error {
	data, err := loadState(p.cfg.StatePath)
	if err != nil {
		return err
	}
	p.committed = data
	return nil
}

// Run polls until ctx is cancelled, returning nil, or the API says the key is revoked,
// returning an error wrapping api.ErrAPIGone. Any other failure is logged and retried at the
// next poll.
func (p *Poller) Run(ctx context.Context) error {
	if p.committed == nil {
		if err := p.Open(); err != nil {
			return err
		}
	}
	for {
		res, err := p.Poll(ctx)
		switch {
		case errors.Is(err, api.ErrAPIGone):
			return err
		case err != nil:
			if ctx.Err() == nil {
				p.logFailure(err)
			}
		case res.ReadErr != nil:
			// The poll committed, but a blob could not be downloaded
			if ctx.Err() == nil {
				p.logFailure(res.ReadErr)
			}
		default:
			p.logRecovery()
		}
		wait := p.cfg.Interval
		if res.More && err == nil {
			wait = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// logFailure logs a failed poll with a hint for the fixable ones. The same kind of failure
// repeating every poll (a missing role assignment, say) is logged again only every
// failureLogEvery, with how often it happened.
func (p *Poller) logFailure(err error) {
	kind, hint := describeError(err)
	now := p.cfg.Now()
	if kind == p.failure && now.Sub(p.failureLogged) < failureLogEvery {
		p.failures++
		return
	}
	if hint != "" {
		hint = " (" + hint + ")"
	}
	if kind == p.failure {
		log.Printf("[flowlogs] Still failing after %d polls, retrying every poll: %v%s", p.failures+1, err, hint)
	} else {
		log.Printf("[flowlogs] Poll failed, retrying at the next poll: %v%s", err, hint)
		p.failures = 0
	}
	p.failure, p.failureLogged = kind, now
	p.failures++
}

func (p *Poller) logRecovery() {
	if p.failure != "" {
		log.Printf("[flowlogs] Polling works again after %d failed poll(s)", p.failures)
		p.failure, p.failures = "", 0
	}
}

// PollResult is what a committed poll reports.
type PollResult struct {
	// More is true when the poll stopped at the read budget with data left to read.
	More bool
	// ReadErr is the first blob download that failed; the poll committed the rest.
	ReadErr error
}

// Poll reads, converts and uploads once. The state is committed only when every record was
// uploaded, buffered or refused by the Publisher; otherwise Poll returns an error and the next
// poll starts over from the same place.
func (p *Poller) Poll(ctx context.Context) (res PollResult, err error) {
	if p.committed == nil {
		if p.committed, err = json.Marshal(newState()); err != nil {
			return res, err
		}
	}
	st, err := decodeState(p.committed)
	if err != nil {
		return res, fmt.Errorf("decode flow log state: %w", err)
	}
	now := p.cfg.Now().UTC()

	blobs, err := p.list(ctx, st, now)
	if err != nil {
		return res, err
	}
	out := &output{dir: filepath.Join(p.cfg.OutputDir, "zeek_out_flowlog_"+now.Format("20060102T150405.000000000Z"))}
	conv := NewConverter(p.cfg.Converter, st.Converter, out.write)
	budget := readBudget{left: pollReadBudget}

	// Learn every NIC's addresses before converting anything, so a flow logged by both its
	// NICs is deduplicated even when the destination NIC's blobs are converted first
	var recs []rawRecord
	read := 0
	if p.learnNewNICs(ctx, st, blobs, conv, &budget) {
		recs, read, res.More, res.ReadErr = p.read(ctx, st, blobs, now, &budget)
	} else {
		res.More = true // the budget ran out while learning; convert next poll
	}
	// Learn from what was read too; records are decoded again below rather than kept as
	// tuples, to hold only their bytes in memory
	for _, r := range recs {
		_, _ = parseRecord(r.data, r.pos, conv.Learn)
	}
	badRecords, otherVersions := 0, 0
	for _, r := range recs {
		ok, err := parseRecord(r.data, r.pos, conv.Add)
		if err != nil {
			if badRecords == 0 {
				log.Printf("[flowlogs] Skipping unreadable record %s: %v", r.pos, err)
			}
			badRecords++
		} else if !ok {
			otherVersions++
		}
	}
	// A NIC with blobs left to read is behind, not quiet
	reading := map[string]bool{}
	for _, b := range blobs {
		if !st.Blobs[b.Name].done() {
			reading[blobMAC(b.Name)] = true
		}
	}
	conv.Flush(reading)
	if err := out.close(); err != nil {
		return PollResult{}, err
	}
	if now.Sub(st.LastPoll) >= lastPollEvery {
		st.LastPoll = now
	}
	// Forget a finished blob against the same base list uses to pick up untracked ones, so a
	// forgotten blob can never look new and be read again from the start
	forget, floor := st.LastPoll.Add(-trackWindow), now.Add(-maxLookback)
	for name, bs := range st.Blobs {
		switch {
		case bs.done() && bs.LastModified.Before(forget):
			delete(st.Blobs, name)
		case bs.LastModified.Before(floor):
			if !bs.done() {
				log.Printf("[flowlogs] Giving up on %s: unchanged for %v and not read to the end, from byte %d of %d", name, maxLookback, bs.Offset, bs.Size)
			}
			delete(st.Blobs, name)
		}
	}

	s := conv.Stats
	if len(recs) > 0 || s.Records > 0 {
		log.Printf("[flowlogs] Read %d record(s) from %d blob(s): %d conn record(s), %d duplicate, %d health probe, %d IPv6, %d other-protocol, %d denied-from-outside tuple(s) dropped, %d open connection(s)",
			len(recs), read, s.Records, s.Duplicates, s.HealthProbes, s.IPv6, s.OtherProtocols, s.Denied, len(st.Converter.Sessions))
	}
	if badRecords > 0 || otherVersions > 0 {
		log.Printf("[flowlogs] Skipped %d unreadable record(s) and %d record(s) of a flowLogVersion other than %d", badRecords, otherVersions, SupportedVersion)
	}

	if out.records > 0 {
		if err := p.upload(ctx, out.dir); err != nil {
			return PollResult{}, err
		}
	}
	if err := p.commit(st); err != nil {
		return PollResult{}, err
	}
	return res, nil
}

// upload filters and uploads a poll's conn.log. It returns an error only when the state must
// not be committed. With DeleteAfterUpload the directory goes either way: a poll that is not
// committed writes its records again next time.
func (p *Poller) upload(ctx context.Context, dir string) error {
	if p.cfg.DeleteAfterUpload {
		defer func() {
			if err := os.RemoveAll(dir); err != nil {
				log.Printf("[flowlogs] Failed to delete %s: %v", dir, err)
			}
		}()
	}
	// Fail closed, as a capture does: excluded traffic never leaves the host
	if err := types.FilterExcludedSubnets(dir, []string{connLog}, p.cfg.ExcludedSubnets); err != nil {
		return fmt.Errorf("filter excluded subnets: %w", err)
	}
	if p.cfg.Uploader == nil {
		// Upload is off: the converted log stays on disk, as a capture's does
		return nil
	}
	err := p.cfg.Uploader.UploadLogs(ctx, api.LogFiles{ConnPath: filepath.Join(dir, connLog)})
	if errors.Is(err, api.ErrAPIGone) || errors.Is(err, api.ErrNotBuffered) {
		return fmt.Errorf("upload: %w", err)
	}
	if err != nil {
		// Every record was buffered for retry or refused; either way it is not read again
		log.Printf("[flowlogs] Upload did not complete; records are buffered or were refused: %v", err)
	}
	return nil
}

func (p *Poller) commit(st *State) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode flow log state: %w", err)
	}
	if bytes.Equal(data, p.committed) {
		return nil
	}
	if err := saveState(p.cfg.StatePath, data); err != nil {
		// The upload already happened, so keep going from the new state in memory; only a
		// restart before the next successful save rereads (and re-uploads) this poll's input
		p.committed = data
		return err
	}
	p.committed = data
	return nil
}
