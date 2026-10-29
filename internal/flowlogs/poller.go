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
	"sort"
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
	// Accounts are the storage accounts read, at least one. Their flows share one converter, so
	// a flow logged by NICs whose logs are in different accounts is deduplicated, and one read
	// budget, so memory does not grow with the number of accounts.
	Accounts  []Account
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

// Poller reads new flow log records from a container in each storage account every Interval,
// converts them and uploads the resulting conn.log through the sensor's uploader.
type Poller struct {
	cfg      PollerConfig
	accounts []*account
	// committed is the encoded state as of the last poll whose records were safely uploaded or
	// buffered. Each poll starts from it and replaces it only on success.
	committed []byte
	// noAddress holds the newest blobs that were read for a NIC's addresses but held none, so
	// they are not read again every poll; the NIC is tried again with its next blob. A NIC that
	// did teach one is known from the state instead, which survives only if the poll commits,
	// so a failed poll learns it again.
	noAddress map[string]bool
	// failures holds each failure that keeps repeating, by the account it is in ("" for one
	// that is not about an account)
	failures map[string]*failure
}

// failure is the kind of a failure that keeps repeating, how often, and when it was last logged.
type failure struct {
	kind   string
	count  int
	logged time.Time
}

// NewPoller returns a poller. Open loads its state; Run opens it if that has not been done.
func NewPoller(cfg PollerConfig) *Poller {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Poller{cfg: cfg, accounts: newAccounts(cfg.Accounts), noAddress: map[string]bool{}, failures: map[string]*failure{}}
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
		if errors.Is(err, api.ErrAPIGone) {
			return err
		}
		if ctx.Err() == nil {
			p.report(res, err)
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

// report logs a poll's failures, and recoveries from earlier ones.
func (p *Poller) report(res PollResult, err error) {
	if err != nil {
		for _, e := range splitErrors(err) {
			p.logFailure(e)
		}
		return
	}
	// The poll committed, though an account may not have been listed or a blob downloaded
	failing := map[string]bool{}
	for _, e := range res.Failures {
		p.logFailure(e)
		failing[failedAccount(e)] = true
	}
	p.logRecovery(failing)
}

// logFailure logs a failed poll with a hint for the fixable ones. The same kind of failure
// repeating every poll (a missing role assignment, say) is logged again only every
// failureLogEvery, with how often it happened. Each account's failures are tracked apart, so
// one account failing does not hide another's.
func (p *Poller) logFailure(err error) {
	source := failedAccount(err)
	kind, hint := describeError(err)
	now := p.cfg.Now()
	f := p.failures[source]
	if f == nil {
		f = &failure{}
		p.failures[source] = f
	}
	if kind == f.kind && now.Sub(f.logged) < failureLogEvery {
		f.count++
		return
	}
	if hint != "" {
		hint = " (" + hint + ")"
	}
	if kind == f.kind {
		log.Printf("[flowlogs] Still failing after %d polls, retrying every poll: %v%s", f.count+1, err, hint)
	} else {
		log.Printf("[flowlogs] Poll failed, retrying at the next poll: %v%s", err, hint)
		f.count = 0
	}
	f.kind, f.logged = kind, now
	f.count++
}

// logRecovery logs that polling works again for every failure source not in failing.
func (p *Poller) logRecovery(failing map[string]bool) {
	sources := make([]string, 0, len(p.failures))
	for source := range p.failures {
		if !failing[source] {
			sources = append(sources, source)
		}
	}
	sort.Strings(sources)
	for _, source := range sources {
		if source == "" {
			log.Printf("[flowlogs] Polling works again after %d failed poll(s)", p.failures[source].count)
		} else {
			log.Printf("[flowlogs] Storage account %s works again after %d failed poll(s)", source, p.failures[source].count)
		}
		delete(p.failures, source)
	}
}

// splitErrors returns the errors joined in err, or err alone.
func splitErrors(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

// PollResult is what a committed poll reports.
type PollResult struct {
	// More is true when the poll stopped at the read budget with data left to read.
	More bool
	// Failures holds, for each account that could not be listed or had a blob that could not
	// be downloaded, its first failure; the poll committed the rest.
	Failures []error
}

// Poll reads, converts and uploads once. The state is committed only when every record was
// uploaded, buffered or refused by the Publisher; otherwise Poll returns an error and the next
// poll starts over from the same place.
func (p *Poller) Poll(ctx context.Context) (res PollResult, err error) {
	if len(p.accounts) == 0 {
		return res, errors.New("no storage account to read")
	}
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

	blobs, down, err := p.list(ctx, st, now)
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
	readErrs := map[*account]error{}
	if p.learnNewNICs(ctx, st, blobs, conv, &budget) {
		recs, read, res.More, readErrs = p.read(ctx, st, blobs, now, &budget)
	} else {
		res.More = true // the budget ran out while learning; convert next poll
	}
	for _, a := range p.accounts {
		if err := down[a]; err != nil {
			res.Failures = append(res.Failures, err)
		} else if err := readErrs[a]; err != nil {
			res.Failures = append(res.Failures, err)
		}
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
	// A NIC with blobs left to read is behind, not quiet, and so is every NIC of an account that
	// could not be listed
	reading := map[string]bool{}
	for _, b := range blobs {
		if !st.Blobs[b.Name].done() {
			reading[blobMAC(b.Name)] = true
		}
	}
	for name := range st.Blobs {
		if a, _ := p.owner(name); down[a] != nil {
			reading[blobMAC(name)] = true
		}
	}
	conv.Flush(reading)
	if err := out.close(); err != nil {
		return PollResult{}, err
	}
	for _, a := range p.accounts {
		switch {
		case down[a] != nil:
			// An account that has never been listed (one just added, waiting for its role
			// assignment) looks back from its first try, so once it can be listed it is read back
			// to then, as after an outage
			if st.lastPoll(a).IsZero() {
				st.setLastPoll(a, now)
			}
		case now.Sub(st.lastPoll(a)) >= lastPollEvery:
			st.setLastPoll(a, now)
		}
	}
	// Forget a finished blob against the same base list uses to pick up untracked ones in its
	// account, so a forgotten blob can never look new and be read again from the start
	floor := now.Add(-maxLookback)
	for name, bs := range st.Blobs {
		a, _ := p.owner(name)
		forget := st.lastPoll(a).Add(-trackWindow)
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
