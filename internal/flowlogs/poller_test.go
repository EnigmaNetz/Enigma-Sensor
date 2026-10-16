package flowlogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/require"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
)

const testRoot = "flowLogResourceID=/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/NETWORKWATCHERRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKWATCHERS/NETWORKWATCHER_EASTUS/FLOWLOGS/TEST-FLOWLOG"

var pollNow = time.Date(2026, 10, 16, 13, 30, 0, 0, time.UTC)

func blobName(hour time.Time, mac string) string {
	return fmt.Sprintf("%s/y=%04d/m=%02d/d=%02d/h=%02d/m=00/macAddress=%s/PT1H.json",
		testRoot, hour.Year(), int(hour.Month()), hour.Day(), hour.Hour(), mac)
}

// fakeStore holds blobs the way Azure writes them: a header, records separated by commas, and
// a closing footer that new records are inserted before.
type fakeStore struct {
	mu       sync.Mutex
	blobs    map[string][]string // records
	modified map[string]time.Time
	listed   []string
	readErr  error
	failBlob map[string]error // read errors for one blob
	failNext int              // fail this many of the next reads, with failErr
	failErr  error
	reads    int
	readLog  []string // name@offset of each read
	bytes    int64    // bytes downloaded
}

func newFakeStore() *fakeStore {
	return &fakeStore{blobs: map[string][]string{}, modified: map[string]time.Time{}}
}

func (f *fakeStore) append(name string, at time.Time, recs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[name] = append(f.blobs[name], recs...)
	f.modified[name] = at
}

func (f *fakeStore) content(name string) []byte {
	return []byte(`{"records":[` + strings.Join(f.blobs[name], ",") + `]}`)
}

func (f *fakeStore) List(_ context.Context, prefix string) ([]BlobInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed = append(f.listed, prefix)
	var out []BlobInfo
	for name := range f.blobs {
		if strings.HasPrefix(name, prefix) {
			out = append(out, BlobInfo{Name: name, Size: int64(len(f.content(name))), LastModified: f.modified[name]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeStore) Read(_ context.Context, name string, offset, count int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	f.readLog = append(f.readLog, fmt.Sprintf("%s@%d", name, offset))
	if f.readErr != nil {
		return nil, f.readErr
	}
	if err := f.failBlob[name]; err != nil {
		return nil, err
	}
	if f.failNext > 0 {
		f.failNext--
		return nil, f.failErr
	}
	c := f.content(name)
	end := min(offset+count, int64(len(c)))
	f.bytes += end - offset
	return append([]byte(nil), c[offset:end]...), nil
}

// fakeUploader keeps each uploaded conn.log and returns the queued errors in turn.
type fakeUploader struct {
	uploads []string
	errs    []error
}

func (u *fakeUploader) UploadLogs(_ context.Context, files api.LogFiles) error {
	data, err := os.ReadFile(files.ConnPath)
	if err != nil {
		return err
	}
	u.uploads = append(u.uploads, string(data))
	if len(u.errs) > 0 {
		err, u.errs = u.errs[0], u.errs[1:]
		return err
	}
	return nil
}

// flowRecord is one blob record holding tuples logged by mac.
func flowRecord(mac string, tuples ...string) string {
	return fmt.Sprintf(`{"time":"2026-10-16T13:00:00Z","flowLogVersion":4,"macAddress":%q,"category":"FlowLogFlowEvent","flowRecords":{"flows":[{"aclID":"00000000-0000-0000-0000-000000000000","flowGroups":[{"rule":"DefaultRule_AllowInternetOutBound","flowTuples":["%s"]}]}]}}`,
		mac, strings.Join(tuples, `","`))
}

func ms(t time.Time) int64 { return t.UnixMilli() }

type pollerHarness struct {
	t        *testing.T
	store    *fakeStore
	uploader *fakeUploader
	cfg      PollerConfig
	now      time.Time
}

func newPollerHarness(t *testing.T) *pollerHarness {
	h := &pollerHarness{t: t, store: newFakeStore(), uploader: &fakeUploader{}, now: pollNow}
	dir := t.TempDir()
	h.cfg = PollerConfig{
		Store: h.store, Uploader: h.uploader,
		OutputDir: filepath.Join(dir, "captures"), StatePath: filepath.Join(dir, "state", "flowlogs.json"),
		Interval: time.Minute,
		Now:      func() time.Time { return h.now },
	}
	return h
}

func (h *pollerHarness) poll(p *Poller) bool {
	h.t.Helper()
	res, err := p.Poll(context.Background())
	require.NoError(h.t, err)
	return res.More
}

func TestPollerReadsOnlyNewRecords(t *testing.T) {
	h := newPollerHarness(t)
	name := blobName(pollNow, macA)
	k := vmA + "," + client + ",50000,443,6,O,"
	h.store.append(name, pollNow, flowRecord(macA,
		fmt.Sprintf("%d,%sB,NX,,,,", ms(pollNow), k),
		fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	p := NewPoller(h.cfg)
	h.poll(p)
	require.Len(t, h.uploader.uploads, 1)
	require.Equal(t, 1, strings.Count(h.uploader.uploads[0], "\n"), "the open connection is not emitted yet")
	require.Contains(t, h.uploader.uploads[0], `"id.orig_p":50001`)

	h.now = h.now.Add(time.Minute)
	h.store.append(name, h.now, flowRecord(macA, fmt.Sprintf("%d,%sE,NX,5,500,5,5000", ms(h.now), k)))
	h.poll(p)
	require.Len(t, h.uploader.uploads, 2)
	require.Equal(t, 1, strings.Count(h.uploader.uploads[1], "\n"))
	require.Contains(t, h.uploader.uploads[1], `"id.orig_p":50000`)
	require.Contains(t, h.uploader.uploads[1], `"history":"SF"`)

	h.now = h.now.Add(time.Minute)
	h.poll(p)
	require.Len(t, h.uploader.uploads, 2, "nothing new, nothing uploaded")
	require.FileExists(t, h.cfg.StatePath)
	info, err := os.Stat(h.cfg.StatePath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" { // Windows has no Unix permission bits
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestPollerRetriesWhenNotBuffered(t *testing.T) {
	h := newPollerHarness(t)
	name := blobName(pollNow, macA)
	h.store.append(name, pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	h.uploader.errs = []error{fmt.Errorf("failed to upload records: %w", fmt.Errorf("%w: disk full", api.ErrNotBuffered))}
	p := NewPoller(h.cfg)
	_, err := p.Poll(context.Background())
	require.ErrorIs(t, err, api.ErrNotBuffered)
	require.NoFileExists(t, h.cfg.StatePath, "nothing is committed")

	h.now = h.now.Add(time.Minute)
	h.poll(p)
	require.Len(t, h.uploader.uploads, 2)
	require.Equal(t, h.uploader.uploads[0], h.uploader.uploads[1], "the same records are sent again")

	h.poll(p)
	require.Len(t, h.uploader.uploads, 2, "and only once they are safe is the offset moved")
}

func TestPollerCommitsWhenBuffered(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	h.uploader.errs = []error{errors.New("upload failed every retry (payload buffered for retry)")}
	p := NewPoller(h.cfg)
	h.poll(p)
	h.poll(p)
	require.Len(t, h.uploader.uploads, 1, "buffered records are not read again")
}

func TestPollerStopsOnAPIGone(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	h.uploader.errs = []error{fmt.Errorf("failed to upload records: %w", fmt.Errorf("wrapped: %w", api.ErrAPIGone))}
	err := NewPoller(h.cfg).Run(context.Background())
	require.ErrorIs(t, err, api.ErrAPIGone)
	require.NoFileExists(t, h.cfg.StatePath)
}

func TestPollerRunStopsOnCancel(t *testing.T) {
	h := newPollerHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- NewPoller(h.cfg).Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// A sensor restarted between polls, loading the state file, uploads what one that kept running
// would have.
func TestPollerRestartMatchesUninterrupted(t *testing.T) {
	steps := func(h *pollerHarness, i int) {
		at := pollNow.Add(time.Duration(i) * time.Minute)
		k := fmt.Sprintf("%s,%s,52114,1433,6,", vmA, vmB)
		var tuples []string
		switch {
		case i == 0:
			tuples = append(tuples, fmt.Sprintf("%d,%sO,B,NX,,,,", ms(at), k))
		case i < 4:
			tuples = append(tuples, fmt.Sprintf("%d,%sO,C,NX,10,1000,5,500", ms(at), k))
		default:
			tuples = append(tuples, fmt.Sprintf("%d,%sO,E,NX,1,100,1,100", ms(at), k))
		}
		tuples = append(tuples, fmt.Sprintf("%d,%s,%s,%d,443,6,O,E,NX,3,300,3,3000", ms(at), vmA, client, 40000+i))
		h.store.append(blobName(pollNow, macA), at, flowRecord(macA, tuples...))
		// The destination NIC logs the same SQL flow; it must never be uploaded
		h.store.append(blobName(pollNow, macB), at, flowRecord(macB, strings.Replace(tuples[0], ",O,", ",I,", 1)))
		h.now = at
	}
	uninterrupted := newPollerHarness(t)
	p := NewPoller(uninterrupted.cfg)
	for i := 0; i < 5; i++ {
		steps(uninterrupted, i)
		uninterrupted.poll(p)
	}

	restarted := newPollerHarness(t)
	for i := 0; i < 5; i++ {
		steps(restarted, i)
		// A new poller each time, as after a restart, loading the state file in Run's way
		p := NewPoller(restarted.cfg)
		data, err := loadState(restarted.cfg.StatePath)
		require.NoError(t, err)
		p.committed = data
		restarted.poll(p)
	}
	require.Equal(t, strings.Join(uninterrupted.uploader.uploads, ""), strings.Join(restarted.uploader.uploads, ""))
	all := strings.Join(uninterrupted.uploader.uploads, "")
	require.Equal(t, 1, strings.Count(all, `"id.resp_p":1433`), "the SQL flow once, from the source NIC")
	require.Contains(t, all, `"orig_pkts":31`)
}

func TestPollerListsTodayAfterTheFullListing(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA))
	h.store.append("other/blob.txt", pollNow)
	p := NewPoller(h.cfg)
	h.poll(p)
	require.Equal(t, []string{""}, h.store.listed, "the first poll lists everything")

	h.now = pollNow.Add(time.Minute)
	h.poll(p)
	require.Equal(t, []string{"", testRoot + "/y=2026/m=10/d=16/"}, h.store.listed)

	// Just after midnight the window still reaches yesterday
	h.store.listed = nil
	h.now = time.Date(2026, 10, 17, 0, 30, 0, 0, time.UTC)
	p.rootsAt = h.now
	h.poll(p)
	require.Equal(t, []string{testRoot + "/y=2026/m=10/d=16/", testRoot + "/y=2026/m=10/d=17/"}, h.store.listed)

	h.store.listed = nil
	h.now = h.now.Add(rootRefresh)
	h.poll(p)
	require.Equal(t, []string{""}, h.store.listed, "the whole container is listed again every hour")
}

func TestPollerSkipsOldBlobsOnFirstStart(t *testing.T) {
	h := newPollerHarness(t)
	old := pollNow.Add(-3 * time.Hour)
	h.store.append(blobName(old, macA), old, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(old), vmA, client)))
	h.poll(NewPoller(h.cfg))
	require.Empty(t, h.uploader.uploads)
	require.Zero(t, h.store.reads)
}

func TestPollerFiltersExcludedSubnets(t *testing.T) {
	h := newPollerHarness(t)
	h.cfg.ExcludedSubnets = []string{"203.0.113.0/24"}
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA,
		fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client),
		fmt.Sprintf("%d,%s,198.51.100.7,50002,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA)))
	h.poll(NewPoller(h.cfg))
	require.Len(t, h.uploader.uploads, 1)
	require.NotContains(t, h.uploader.uploads[0], client)
	require.Contains(t, h.uploader.uploads[0], "198.51.100.7")
}

func TestPollerDeletesOutputAfterUpload(t *testing.T) {
	h := newPollerHarness(t)
	h.cfg.DeleteAfterUpload = true
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	h.poll(NewPoller(h.cfg))
	require.Len(t, h.uploader.uploads, 1)
	entries, err := os.ReadDir(h.cfg.OutputDir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestPollerOutputDirIsAZeekOutDir(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	h.poll(NewPoller(h.cfg))
	entries, err := os.ReadDir(h.cfg.OutputDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	// The capture loop's retention cleanup and the support bundle key off this prefix
	require.True(t, strings.HasPrefix(entries[0].Name(), "zeek_out_flowlog_"), entries[0].Name())
}

func TestPollerReadBudget(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	var recs []string
	for i := 0; i < 20; i++ {
		recs = append(recs, flowRecord(macA, fmt.Sprintf("%d,%s,%s,%d,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client, 40000+i)))
	}
	h.store.append(blobName(pollNow, macA), pollNow, recs...)
	pollReadBudget, maxBlobRead = int64(len(recs[0])*3), int64(len(recs[0])*3)
	p := NewPoller(h.cfg)
	polls := 0
	for more := true; more; polls++ {
		more = h.poll(p)
		require.Less(t, polls, 50)
	}
	require.Greater(t, polls, 5, "the blob is read over several polls")
	require.Equal(t, 20, strings.Count(strings.Join(h.uploader.uploads, ""), "\n"), "every record exactly once")
}

func TestPollerReadsARecordLargerThanTheReadLimit(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	pollReadBudget, maxBlobRead = 64, 64
	p := NewPoller(h.cfg)
	p.noAddress[blobName(pollNow, macA)] = true // isolate the read path from the up-front address read
	h.poll(p)
	require.Len(t, h.uploader.uploads, 1)
}

func TestPollerDoesNotSpinOnReadErrors(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	h.store.readErr = errors.New("403 AuthorizationPermissionMismatch")
	pollReadBudget, maxBlobRead = 64, 64
	require.False(t, h.poll(NewPoller(h.cfg)), "a failed read does not ask for an immediate poll")
	require.Empty(t, h.uploader.uploads)
}

func TestLoadStateSetsAsideACorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
	data, err := loadState(path)
	require.NoError(t, err)
	st, err := decodeState(data)
	require.NoError(t, err)
	require.Empty(t, st.Blobs)
	require.FileExists(t, path+".corrupt")
}

func TestPollerDeletesOutputWhenUploadFails(t *testing.T) {
	h := newPollerHarness(t)
	h.cfg.DeleteAfterUpload = true
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow), vmA, client)))
	h.uploader.errs = []error{fmt.Errorf("%w: disk full", api.ErrNotBuffered)}
	_, err := NewPoller(h.cfg).Poll(context.Background())
	require.ErrorIs(t, err, api.ErrNotBuffered)
	entries, err := os.ReadDir(h.cfg.OutputDir)
	require.NoError(t, err)
	require.Empty(t, entries, "the next poll writes these records again, so nothing is left behind")
}

func TestPollerSurvivesADamagedSession(t *testing.T) {
	h := newPollerHarness(t)
	st := newState()
	st.Converter.Sessions["x"] = &Session{MAC: macA, Proto: 6, Src: "garbage", Dst: "also garbage", Start: ms(pollNow), Last: ms(pollNow)}
	st.Converter.Watermarks[macA] = ms(pollNow)
	data, err := json.Marshal(st)
	require.NoError(t, err)
	require.NoError(t, saveState(h.cfg.StatePath, data))
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(pollNow.Add(time.Hour)), vmA, client)))
	p := NewPoller(h.cfg)
	p.committed, err = loadState(h.cfg.StatePath)
	require.NoError(t, err)
	require.NotPanics(t, func() { h.poll(p) })
	require.Len(t, h.uploader.uploads, 1)
}

func endTuple(at time.Time, src, dst string, port int) string {
	return fmt.Sprintf("%d,%s,%s,%d,443,6,O,E,NX,3,300,3,3000", ms(at), src, dst, port)
}

// A blob whose content has not changed since it was read to the end is not downloaded again,
// even though its closing ]} lies past the last record read.
func TestPollerDoesNotRereadAFinishedBlob(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	p := NewPoller(h.cfg)
	h.poll(p)
	reads := h.store.reads
	h.now = h.now.Add(time.Minute)
	h.poll(p)
	h.poll(p)
	require.Equal(t, reads, h.store.reads)
}

// The leftover budget must not pull down the rest of a large blob: past the budget, a poll
// reads only far enough to finish one record.
func TestPollerBudgetIsNotBypassed(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	small := flowRecord(macA, endTuple(pollNow, vmA, client, 50001))
	var bigRecs []string
	for r := 0; r < 5; r++ {
		var tuples []string
		for i := 0; i < 40; i++ {
			tuples = append(tuples, endTuple(pollNow, vmB, client, 40000+r*100+i))
		}
		bigRecs = append(bigRecs, flowRecord(macB, tuples...))
	}
	h.store.append(blobName(pollNow, macA), pollNow, small)
	h.store.append(blobName(pollNow, macB), pollNow, bigRecs...)
	pollReadBudget, maxBlobRead = int64(len(small)+100), 1<<20

	p := NewPoller(h.cfg)
	// Isolate the read path from the up-front address reads
	p.noAddress[blobName(pollNow, macA)], p.noAddress[blobName(pollNow, macB)] = true, true
	h.store.bytes = 0
	require.True(t, h.poll(p), "the rest of the big blob waits for the next poll")
	// The read doubles until the record is whole, so it can end up to twice the record's size
	whole := int64(len(h.store.content(blobName(pollNow, macB))))
	require.LessOrEqual(t, h.store.bytes, pollReadBudget+2*int64(len(bigRecs[0])+len(`{"records":[`)),
		"about one record past the budget at most")
	require.Less(t, h.store.bytes, int64(len(small))+whole, "not the whole blob")

	for more := true; more; {
		more = h.poll(p)
	}
	require.Equal(t, 201, strings.Count(strings.Join(h.uploader.uploads, ""), "\n"))
}

// Blobs written while the sensor was stopped for longer than trackWindow are read
// when it starts again.
func TestPollerReadsBlobsWrittenDuringAnOutage(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	h.poll(NewPoller(h.cfg))

	// Stopped for five hours; Azure kept writing
	during := pollNow.Add(90 * time.Minute)
	h.store.append(blobName(during, macA), during, flowRecord(macA, endTuple(during, vmA, client, 50002)))
	h.now = pollNow.Add(5 * time.Hour)
	p := NewPoller(h.cfg)
	require.NoError(t, p.Open())
	h.poll(p)
	require.Len(t, h.uploader.uploads, 2)
	require.Contains(t, h.uploader.uploads[1], `"id.orig_p":50002`)
}

// After more than maxLookback the oldest blobs are skipped, not read.
func TestPollerCapsTheLookback(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	h.poll(NewPoller(h.cfg))

	early, late := pollNow.Add(2*time.Hour), pollNow.Add(29*time.Hour)
	h.store.append(blobName(early, macA), early, flowRecord(macA, endTuple(early, vmA, client, 50002)))
	h.store.append(blobName(late, macA), late, flowRecord(macA, endTuple(late, vmA, client, 50003)))
	h.now = pollNow.Add(30 * time.Hour)
	p := NewPoller(h.cfg)
	require.NoError(t, p.Open())
	h.poll(p)
	require.Len(t, h.uploader.uploads, 2)
	require.NotContains(t, h.uploader.uploads[1], `"id.orig_p":50002`, "older than the lookback cap")
	require.Contains(t, h.uploader.uploads[1], `"id.orig_p":50003`)
}

// A blob the read budget cut short keeps its state until it is read to the end,
// however long that takes.
func TestPollerKeepsAPartlyReadBlob(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	var recs []string
	for i := 0; i < 10; i++ {
		recs = append(recs, flowRecord(macA, endTuple(pollNow, vmA, client, 40000+i)))
	}
	h.store.append(blobName(pollNow, macA), pollNow, recs...)
	pollReadBudget, maxBlobRead = int64(len(recs[0])*2), int64(len(recs[0])*2)
	p := NewPoller(h.cfg)
	require.True(t, h.poll(p))

	// Much later, with the blob unchanged since
	h.now = pollNow.Add(3 * time.Hour)
	for more := true; more; {
		more = h.poll(p)
	}
	require.Equal(t, 10, strings.Count(strings.Join(h.uploader.uploads, ""), "\n"))
}

// On a cold start whose backlog takes several polls, the destination NIC's blob
// sorts first and is converted before the source NIC's is read; the flow is still counted once.
func TestPollerColdStartBacklogDeduplicates(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	// macA's VM is the destination; macB's VM starts the SQL connection
	k := fmt.Sprintf("%s,%s,52114,1433,6,", vmB, vmA)
	start := pollNow.Add(-50 * time.Minute)
	var aRecs, bRecs []string
	for i := 0; i <= 6; i++ {
		at := start.Add(time.Duration(i) * 5 * time.Minute)
		state := "C,NX,10,1000,5,500"
		switch i {
		case 0:
			state = "B,NX,,,,"
		case 6:
			state = "E,NX,1,100,1,100"
		}
		aRecs = append(aRecs, flowRecord(macA, fmt.Sprintf("%d,%sI,%s", ms(at), k, state)))
		bRecs = append(bRecs, flowRecord(macB, fmt.Sprintf("%d,%sO,%s", ms(at), k, state)))
	}
	h.store.append(blobName(start, macA), pollNow, aRecs...)
	h.store.append(blobName(start, macB), pollNow, bRecs...)
	// Only macA's blob fits in the first poll
	size := int64(len(h.store.content(blobName(start, macA))))
	pollReadBudget, maxBlobRead = size, size

	p := NewPoller(h.cfg)
	for more := true; more; {
		more = h.poll(p)
	}
	all := strings.Join(h.uploader.uploads, "")
	require.Equal(t, 1, strings.Count(all, `"id.resp_p":1433`), all)
	require.Contains(t, all, `"orig_pkts":51`)
}

// When one of a NIC's blobs cannot be read, its later blobs wait, so the NIC's
// tuples are still converted in order.
func TestPollerHoldsANICAfterAFailedRead(t *testing.T) {
	h := newPollerHarness(t)
	h13, h14 := pollNow.Add(-time.Hour), pollNow
	k := vmA + "," + client + ",50000,443,6,O,"
	h.store.append(blobName(h13, macA), h13, flowRecord(macA, fmt.Sprintf("%d,%sB,NX,,,,", ms(h13), k)))
	h.store.append(blobName(h14, macA), h14, flowRecord(macA, fmt.Sprintf("%d,%sE,NX,3,300,3,3000", ms(h14.Add(-50*time.Minute)), k)))
	h.store.append(blobName(h14, macB), h14, flowRecord(macB, endTuple(h14, vmB, client, 50009)))
	h.store.failBlob = map[string]error{blobName(h13, macA): errors.New("connection reset")}

	p := NewPoller(h.cfg)
	h.poll(p)
	// The only read of macA's next hour is the up-front one that learns its addresses
	require.Equal(t, 1, strings.Count(strings.Join(h.store.readLog, " "), blobName(h14, macA)+"@"))
	require.NotContains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50000`, "macA's next hour waits")
	require.Contains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50009`, "other NICs carry on")

	h.store.failBlob = nil
	h.now = h.now.Add(time.Minute)
	h.poll(p)
	all := strings.Join(h.uploader.uploads, "")
	require.Equal(t, 1, strings.Count(all, `"id.orig_p":50000`))
	require.Contains(t, all, `"history":"SF"`, "the begin and the end are joined, in order")
}

// An unreadable record gives up on the rest of that blob, not on the NIC.
func TestPollerAbandonsABlobWithABadRecord(t *testing.T) {
	h := newPollerHarness(t)
	h13, h14 := pollNow.Add(-time.Hour), pollNow
	h.store.append(blobName(h13, macA), h13, flowRecord(macA, endTuple(h13, vmA, client, 50001)), `{"broken":}`)
	h.store.append(blobName(h14, macA), h14, flowRecord(macA, endTuple(h14, vmA, client, 50002)))
	p := NewPoller(h.cfg)
	h.poll(p)
	all := strings.Join(h.uploader.uploads, "")
	require.Contains(t, all, `"id.orig_p":50001`)
	require.Contains(t, all, `"id.orig_p":50002`)
	reads := h.store.reads
	h.now = h.now.Add(time.Minute)
	h.poll(p)
	require.Equal(t, reads, h.store.reads, "the bad blob is not downloaded every poll")
}

func TestPollerLogsARepeatedFailureOnce(t *testing.T) {
	var buf strings.Builder
	defer log.SetOutput(log.Writer())
	log.SetOutput(&buf)
	h := newPollerHarness(t)
	p := NewPoller(h.cfg)
	forbidden := &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationPermissionMismatch"}
	for i := 0; i < 5; i++ {
		p.logFailure(fmt.Errorf("list blobs: %w", forbidden))
		h.now = h.now.Add(time.Minute)
	}
	require.Equal(t, 1, strings.Count(buf.String(), "Poll failed"), buf.String())
	require.Contains(t, buf.String(), "Storage Blob Data Reader")

	h.now = h.now.Add(failureLogEvery)
	p.logFailure(fmt.Errorf("list blobs: %w", forbidden))
	require.Contains(t, buf.String(), "Still failing after 6 polls")
	p.logRecovery()
	require.Contains(t, buf.String(), "Polling works again after 6 failed poll(s)")
}

// A poll that learned NIC addresses and then failed to upload loses those addresses with its
// state, so the next poll must learn them again, or the destination NIC's view of a shared
// flow is uploaded as well as the source NIC's.
func TestPollerRelearnsAfterAFailedPoll(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	k := fmt.Sprintf("%s,%s,52114,1433,6,", vmB, vmA) // macB's VM starts it, macA's VM serves it
	start := pollNow.Add(-50 * time.Minute)
	var aRecs, bRecs []string
	for i, state := range []string{"B,NX,,,,", "C,NX,10,1000,5,500", "E,NX,1,100,1,100"} {
		at := start.Add(time.Duration(i) * 5 * time.Minute)
		aRecs = append(aRecs, flowRecord(macA, fmt.Sprintf("%d,%sI,%s", ms(at), k, state)))
		bRecs = append(bRecs, flowRecord(macB, fmt.Sprintf("%d,%sO,%s", ms(at), k, state)))
	}
	aRecs = append(aRecs, flowRecord(macA, endTuple(start, vmA, client, 50001))) // so the poll uploads
	h.store.append(blobName(start, macA), pollNow, aRecs...)
	h.store.append(blobName(start, macB), pollNow, bRecs...)
	sizeA := int64(len(h.store.content(blobName(start, macA))))
	sizeB := int64(len(h.store.content(blobName(start, macB))))
	// Enough to learn both NICs and read macA's blob, not macB's
	pollReadBudget, maxBlobRead = 2*sizeA+sizeB, 1<<20
	h.uploader.errs = []error{fmt.Errorf("%w: disk full", api.ErrNotBuffered)}

	p := NewPoller(h.cfg)
	_, err := p.Poll(context.Background())
	require.ErrorIs(t, err, api.ErrNotBuffered)

	// The next poll starts from the committed state, which never got macB's address; learning
	// must read macB again rather than treat it as done
	st, err := decodeState(p.committed)
	require.NoError(t, err)
	require.NotContains(t, st.Converter.PrivateIP, macB)
	blobs, err := h.store.List(context.Background(), "")
	require.NoError(t, err)
	budget := readBudget{left: pollReadBudget}
	conv := NewConverter(Options{}, st.Converter, func(ConnRecord) {})
	require.True(t, p.learnNewNICs(context.Background(), st, blobs, conv, &budget))
	require.Equal(t, vmB, st.Converter.PrivateIP[macB].IP)

	for more := true; more; {
		more = h.poll(p)
	}
	saved := strings.Join(h.uploader.uploads[1:], "") // the first upload failed
	require.Equal(t, 1, strings.Count(saved, `"id.resp_p":1433`), saved)
	require.Contains(t, saved, `"orig_pkts":11`, "from the source NIC")
}

// A busy NIC's first record can be larger than the first learning read; the read grows until
// it holds one.
func TestLearnReadGrowsForALargeFirstRecord(t *testing.T) {
	h := newPollerHarness(t)
	var tuples []string
	for i := 0; i < 6000; i++ {
		tuples = append(tuples, endTuple(pollNow, vmB, client, 10000+i))
	}
	big := flowRecord(macB, tuples...)
	require.Greater(t, len(big), learnReadBytes)
	h.store.append(blobName(pollNow, macB), pollNow, big)
	blobs, err := h.store.List(context.Background(), "")
	require.NoError(t, err)

	p := NewPoller(h.cfg)
	st := newState()
	budget := readBudget{left: pollReadBudget}
	conv := NewConverter(Options{}, st.Converter, func(ConnRecord) {})
	require.True(t, p.learnNewNICs(context.Background(), st, blobs, conv, &budget))
	require.Equal(t, vmB, st.Converter.PrivateIP[macB].IP)
	require.False(t, p.noAddress[macB])
}

// A NIC whose newest blob teaches no address is not read again every poll.
func TestLearnSkipsANICWithNoAddress(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macB), pollNow, flowRecord(macB, fmt.Sprintf("%d,2001:db8::1,2001:db8::2,50000,443,6,O,E,NX,1,60,1,60", ms(pollNow))))
	blobs, err := h.store.List(context.Background(), "")
	require.NoError(t, err)
	p := NewPoller(h.cfg)
	st := newState()
	conv := NewConverter(Options{}, st.Converter, func(ConnRecord) {})
	for i := 0; i < 3; i++ {
		budget := readBudget{left: pollReadBudget}
		require.True(t, p.learnNewNICs(context.Background(), st, blobs, conv, &budget))
	}
	require.Equal(t, 1, h.store.reads)
}

// A blob that is gone is given up on at once, so its NIC's later blobs are read.
func TestPollerGivesUpOnABlobThatIsGone(t *testing.T) {
	h := newPollerHarness(t)
	h13, h14 := pollNow.Add(-time.Hour), pollNow
	h.store.append(blobName(h13, macA), h13, flowRecord(macA, endTuple(h13, vmA, client, 50001)))
	h.store.append(blobName(h14, macA), h14, flowRecord(macA, endTuple(h14, vmA, client, 50002)))
	h.store.failBlob = map[string]error{blobName(h13, macA): &azcore.ResponseError{StatusCode: 404, ErrorCode: "BlobNotFound"}}
	p := NewPoller(h.cfg)
	res, err := p.Poll(context.Background())
	require.NoError(t, err, "a download failure does not fail the poll")
	require.Error(t, res.ReadErr, "but it is reported")
	h.now = h.now.Add(time.Minute)
	h.poll(p)
	require.Contains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50002`)
}

// Errors that hit every blob, such as a missing role assignment or a service outage, never give
// a blob up, however long they last: once they clear, nothing has been lost. During a catch-up
// polls run back to back, so a count of failed polls would give up within seconds.
func TestPollerKeepsBlobsThroughFailuresThatAreNotAboutThem(t *testing.T) {
	for _, failure := range []error{
		&azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationPermissionMismatch"},
		&azcore.ResponseError{StatusCode: 503, ErrorCode: "ServerBusy"},
		errors.New("dial tcp: i/o timeout"),
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			h := newPollerHarness(t)
			name := blobName(pollNow, macA)
			h.store.append(name, pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
			h.store.readErr = failure
			p := NewPoller(h.cfg)
			for i := 0; i < 200; i++ { // three hours and more of polls a minute apart
				res, err := p.Poll(context.Background())
				require.NoError(t, err)
				require.ErrorIs(t, res.ReadErr, failure)
				h.now = h.now.Add(time.Minute)
			}
			h.store.readErr = nil
			h.poll(p)
			require.Contains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50001`)
		})
	}
}

// An error about the blob itself that does not clear gives the blob up after giveUpAfter, not
// before.
func TestPollerGivesUpOnABlobThatKeepsFailing(t *testing.T) {
	h := newPollerHarness(t)
	h13, h14 := pollNow.Add(-time.Hour), pollNow
	h.store.append(blobName(h13, macA), h13, flowRecord(macA, endTuple(h13, vmA, client, 50001)))
	h.store.append(blobName(h14, macA), h14, flowRecord(macA, endTuple(h14, vmA, client, 50002)))
	h.store.failBlob = map[string]error{blobName(h13, macA): &azcore.ResponseError{StatusCode: 409, ErrorCode: "InvalidBlobType"}}
	p := NewPoller(h.cfg)
	for elapsed := time.Duration(0); elapsed < giveUpAfter; elapsed += 10 * time.Minute {
		h.poll(p)
		require.NotContains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50002`, "held after %v", elapsed)
		h.now = h.now.Add(10 * time.Minute)
	}
	h.poll(p)
	h.now = h.now.Add(time.Minute)
	h.poll(p)
	require.Contains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50002`)
}

func TestDescribeErrorKeysNetworkErrorsByKind(t *testing.T) {
	a, _ := describeError(fmt.Errorf("download %s: %w", blobName(pollNow, macA), &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}))
	b, _ := describeError(fmt.Errorf("download %s: %w", blobName(pollNow, macB), &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}))
	require.Equal(t, "network timeout", a)
	require.Equal(t, a, b, "the same failure on two blobs is one kind")
}

func TestDescribeErrorKeysIdentityErrorsByMessage(t *testing.T) {
	a, hint := describeError(errors.New("ManagedIdentityCredential: no default identity is assigned to this resource"))
	require.Contains(t, hint, "managed identity")
	b, _ := describeError(errors.New("ManagedIdentityCredential: the requested identity isn't assigned to this resource"))
	require.NotEqual(t, a, b)
}

// countPorts returns how many times each originator port appears in the uploads.
func countPorts(uploads []string) map[string]int {
	counts := map[string]int{}
	for _, line := range strings.Split(strings.Join(uploads, ""), "\n") {
		if _, rest, ok := strings.Cut(line, `"id.orig_p":`); ok {
			port, _, _ := strings.Cut(rest, ",")
			counts[port]++
		}
	}
	return counts
}

// A backlog read over several polls, hit by a burst of server errors part way through: every
// record arrives exactly once.
func TestPollerCatchUpThroughABurstOfServerErrors(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	want := map[string]int{}
	for hr := 3; hr >= 0; hr-- {
		at := pollNow.Add(-time.Duration(hr) * 30 * time.Minute)
		for _, nic := range []struct{ mac, ip string }{{macA, vmA}, {macB, vmB}} {
			var recs []string
			for i := 0; i < 8; i++ {
				port := 10000 + hr*1000 + i
				if nic.mac == macB {
					port += 500
				}
				recs = append(recs, flowRecord(nic.mac, endTuple(at, nic.ip, client, port)))
				want[fmt.Sprint(port)] = 1
			}
			h.store.append(blobName(at, nic.mac), at, recs...)
		}
	}
	pollReadBudget, maxBlobRead = 4096, 4096
	p := NewPoller(h.cfg)
	for i := 0; i < 400 && !reflect.DeepEqual(countPorts(h.uploader.uploads), want); i++ {
		if i == 3 {
			// Well past the 30 failed polls an earlier version gave a blob up after
			h.store.failNext, h.store.failErr = 150, &azcore.ResponseError{StatusCode: 503, ErrorCode: "ServerBusy"}
		}
		_, err := p.Poll(context.Background())
		require.NoError(t, err)
		h.now = h.now.Add(time.Second) // catch-up polls run back to back
	}
	require.Equal(t, want, countPorts(h.uploader.uploads))
}

// Critical case from review: after a long outage, new NICs whose address reads use up the
// first poll's budget must not let the outage's blobs fall out of the next poll's lookback.
func TestPollerOutageWithNewNICsLosesNothing(t *testing.T) {
	defer func(b, m int64) { pollReadBudget, maxBlobRead = b, m }(pollReadBudget, maxBlobRead)
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	h.poll(NewPoller(h.cfg))

	// Five hours later, after the sensor was stopped; three NICs appeared meanwhile
	want := map[string]int{"50001": 1}
	nics := []struct{ mac, ip string }{{"00224800CCCC", "10.0.3.4"}, {"00224800DDDD", "10.0.3.5"}, {"00224800EEEE", "10.0.3.6"}}
	for hr := 1; hr <= 5; hr++ {
		at := pollNow.Add(time.Duration(hr) * time.Hour)
		for n, nic := range nics {
			port := 20000 + hr*10 + n
			h.store.append(blobName(at, nic.mac), at, flowRecord(nic.mac, endTuple(at, nic.ip, client, port)))
			want[fmt.Sprint(port)] = 1
		}
	}
	h.now = pollNow.Add(5*time.Hour + 5*time.Minute)
	// Room to learn about one NIC per poll, so learning alone uses up the first polls
	pollReadBudget = int64(len(h.store.content(blobName(h.now.Add(-5*time.Minute), nics[0].mac))))
	p := NewPoller(h.cfg)
	require.NoError(t, p.Open())
	for i := 0; i < 100 && !reflect.DeepEqual(countPorts(h.uploader.uploads), want); i++ {
		h.poll(p)
		h.now = h.now.Add(lastPollEvery) // LastPoll moves on every poll
	}
	require.Equal(t, want, countPorts(h.uploader.uploads))
}

// A NIC whose newest blob taught nothing is tried again with its next blob, and the old entry
// is forgotten.
func TestLearnTriesANICAgainWithItsNextBlob(t *testing.T) {
	h := newPollerHarness(t)
	h13, h14 := pollNow.Add(-time.Hour), pollNow
	h.store.append(blobName(h13, macB), h13, flowRecord(macB, fmt.Sprintf("%d,2001:db8::1,2001:db8::2,50000,443,6,O,E,NX,1,60,1,60", ms(h13))))
	p := NewPoller(h.cfg)
	st := newState()
	conv := NewConverter(Options{}, st.Converter, func(ConnRecord) {})
	learn := func() {
		blobs, err := h.store.List(context.Background(), "")
		require.NoError(t, err)
		budget := readBudget{left: pollReadBudget}
		require.True(t, p.learnNewNICs(context.Background(), st, blobs, conv, &budget))
	}
	learn()
	require.True(t, p.noAddress[blobName(h13, macB)])

	h.store.append(blobName(h14, macB), h14, flowRecord(macB, endTuple(h14, vmB, client, 50001)))
	learn()
	require.Equal(t, vmB, st.Converter.PrivateIP[macB].IP)
	require.Empty(t, p.noAddress, "the older blob's entry is forgotten")
}

// A damaged state file with null entries loads; the entries are dropped.
func TestDecodeStateDropsNullEntries(t *testing.T) {
	st, err := decodeState([]byte(`{"version":1,"blobs":{"a":null,"b":{"offset":5}},"converter":{"sessions":{"x":null}}}`))
	require.NoError(t, err)
	require.Len(t, st.Blobs, 1)
	require.Empty(t, st.Converter.Sessions)
}

// Only a missing blob is about that blob; a missing container affects every blob.
func TestBlobFaultSeparatesBlobFromContainer(t *testing.T) {
	gone, about := blobFault(&azcore.ResponseError{StatusCode: 404, ErrorCode: "BlobNotFound"})
	require.True(t, gone)
	require.True(t, about)
	gone, about = blobFault(&azcore.ResponseError{StatusCode: 404, ErrorCode: "ContainerNotFound"})
	require.False(t, gone)
	require.False(t, about)
	_, about = blobFault(&azcore.ResponseError{StatusCode: 409, ErrorCode: "InvalidBlobType"})
	require.True(t, about)
	_, about = blobFault(&azcore.ResponseError{StatusCode: 503, ErrorCode: "ServerBusy"})
	require.False(t, about)
}
