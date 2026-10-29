package flowlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/require"
)

const westRoot = "flowLogResourceID=/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/NETWORKWATCHERRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKWATCHERS/NETWORKWATCHER_WESTUS/FLOWLOGS/TEST-FLOWLOG"

func westBlobName(hour time.Time, mac string) string {
	return strings.Replace(blobName(hour, mac), testRoot, westRoot, 1)
}

// newTwoAccountHarness reads h.store as flowlogseast and returns west, read as flowlogswest.
func newTwoAccountHarness(t *testing.T) (*pollerHarness, *fakeStore) {
	h := newPollerHarness(t)
	west := newFakeStore()
	h.cfg.Accounts = append(h.cfg.Accounts, Account{Name: "flowlogswest", Store: west})
	return h, west
}

func TestPollerReadsEveryAccount(t *testing.T) {
	h, west := newTwoAccountHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	west.append(westBlobName(pollNow, macB), pollNow, flowRecord(macB, endTuple(pollNow, vmB, client, 50002)))
	p := NewPoller(h.cfg)
	h.poll(p)
	require.Len(t, h.uploader.uploads, 1, "one upload for both accounts")
	require.Contains(t, h.uploader.uploads[0], `"id.orig_p":50001`)
	require.Contains(t, h.uploader.uploads[0], `"id.orig_p":50002`)

	st, err := decodeState(p.committed)
	require.NoError(t, err)
	require.Contains(t, st.Blobs, blobName(pollNow, macA), "the first account's blobs keep their names")
	require.Contains(t, st.Blobs, "@flowlogswest/"+westBlobName(pollNow, macB))
	require.Equal(t, pollNow, st.LastPoll)
	require.Equal(t, pollNow, st.AccountPolls["flowlogswest"])

	h.now = h.now.Add(time.Minute)
	reads := h.store.reads + west.reads
	h.poll(p)
	require.Equal(t, reads, h.store.reads+west.reads, "nothing new in either account")
}

// A flow between two VMs whose NICs' logs are in different accounts, peered VNets in two
// regions, is logged by both NICs and uploaded once, from the source NIC.
func TestPollerDeduplicatesAFlowLoggedInTwoAccounts(t *testing.T) {
	k := fmt.Sprintf("%s,%s,52114,1433,6,", vmB, vmA) // macB's VM starts it, macA's VM serves it
	start := pollNow.Add(-50 * time.Minute)
	var aRecs, bRecs []string
	for i, state := range []string{"B,NX,,,,", "C,NX,10,1000,5,500", "E,NX,1,100,1,100"} {
		at := start.Add(time.Duration(i) * 5 * time.Minute)
		aRecs = append(aRecs, flowRecord(macA, fmt.Sprintf("%d,%sI,%s", ms(at), k, state)))
		bRecs = append(bRecs, flowRecord(macB, fmt.Sprintf("%d,%sO,%s", ms(at), k, state)))
	}

	h, west := newTwoAccountHarness(t)
	h.store.append(blobName(start, macA), pollNow, aRecs...)
	west.append(westBlobName(start, macB), pollNow, bRecs...)
	h.poll(NewPoller(h.cfg))
	all := strings.Join(h.uploader.uploads, "")
	require.Equal(t, 1, strings.Count(all, `"id.resp_p":1433`), all)
	require.Contains(t, all, `"orig_pkts":11`, "from the source NIC")

	// Read by two pollers, one per account, the same flow is uploaded twice: the reason
	// accounts share one poller
	separate := &fakeUploader{}
	for _, store := range []*fakeStore{h.store, west} {
		cfg := h.cfg
		cfg.Accounts = []Account{{Name: "only", Store: store}}
		cfg.Uploader = separate
		cfg.StatePath = filepath.Join(t.TempDir(), "state.json")
		_, err := NewPoller(cfg).Poll(context.Background())
		require.NoError(t, err)
	}
	require.Equal(t, 2, strings.Count(strings.Join(separate.uploads, ""), `"id.resp_p":1433`))
}

// The accounts share one poll's read budget, so a poll holds no more in memory with two
// accounts than with one.
func TestPollerSharesTheReadBudgetAcrossAccounts(t *testing.T) {
	defer func(b int64) { pollReadBudget = b }(pollReadBudget)
	h, west := newTwoAccountHarness(t)
	var aRecs, bRecs []string
	for i := 0; i < 20; i++ {
		aRecs = append(aRecs, flowRecord(macA, endTuple(pollNow, vmA, client, 50000+i)))
		bRecs = append(bRecs, flowRecord(macB, endTuple(pollNow, vmB, client, 51000+i)))
	}
	h.store.append(blobName(pollNow, macA), pollNow, aRecs...)
	west.append(westBlobName(pollNow, macB), pollNow, bRecs...)
	blobSize := int64(len(h.store.content(blobName(pollNow, macA))))
	pollReadBudget = blobSize / 2

	p := NewPoller(h.cfg)
	require.True(t, h.poll(p), "the budget ran out")
	require.LessOrEqual(t, h.store.bytes+west.bytes, pollReadBudget, "both accounts together stay in one budget")
	polls := 1
	for more := true; more; polls++ {
		bytes := h.store.bytes + west.bytes
		more = h.poll(p)
		require.LessOrEqual(t, h.store.bytes+west.bytes-bytes, pollReadBudget)
	}
	require.Greater(t, polls, 3)
	all := strings.Join(h.uploader.uploads, "")
	for i := 0; i < 20; i++ {
		require.Contains(t, all, fmt.Sprintf(`"id.orig_p":%d,`, 50000+i))
		require.Contains(t, all, fmt.Sprintf(`"id.orig_p":%d,`, 51000+i))
	}
}

// While one account cannot be listed the others are read and uploaded, the failure names the
// account, and once it can be listed again its flows from the outage are read with nothing
// lost: neither the blobs written meanwhile, though the outage outlasts trackWindow, nor its
// connections that were open, though the other account's tuples outran staleTimeout.
func TestPollerKeepsReadingWhileOneAccountIsDown(t *testing.T) {
	var buf strings.Builder
	defer log.SetOutput(log.Writer())
	log.SetOutput(&buf)

	h, west := newTwoAccountHarness(t)
	long := fmt.Sprintf("%s,%s,51000,443,6,O,", vmB, client)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50000)))
	west.append(westBlobName(pollNow, macB), pollNow, flowRecord(macB, fmt.Sprintf("%d,%sB,NX,,,,", ms(pollNow), long)))
	p := NewPoller(h.cfg)
	pollAndReport := func() PollResult {
		res, err := p.Poll(context.Background())
		require.NoError(t, err)
		p.report(res, err)
		return res
	}
	pollAndReport()

	west.listErr = &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationPermissionMismatch"}
	outage := 3 * time.Hour
	require.Greater(t, outage, trackWindow)
	require.Greater(t, outage, staleTimeout)
	port := 50001
	for elapsed := 10 * time.Minute; elapsed <= outage; elapsed += 10 * time.Minute {
		h.now = pollNow.Add(elapsed)
		hour := h.now.Truncate(time.Hour)
		h.store.append(blobName(hour, macA), h.now, flowRecord(macA, endTuple(h.now, vmA, client, port)))
		west.append(westBlobName(hour, macB), h.now,
			flowRecord(macB, fmt.Sprintf("%d,%sC,NX,1,100,1,100", ms(h.now), long)),
			flowRecord(macB, endTuple(h.now, vmB, client, port+1000)))
		res := pollAndReport()
		require.Len(t, res.Failures, 1)
		require.Contains(t, res.Failures[0].Error(), "storage account flowlogswest")
		require.Contains(t, strings.Join(h.uploader.uploads, ""), fmt.Sprintf(`"id.orig_p":%d,`, port), "east is read during the outage")
		port++
	}
	require.Equal(t, 1, strings.Count(buf.String(), "Poll failed"), buf.String())
	require.Contains(t, buf.String(), "storage account flowlogswest: ")
	require.Contains(t, buf.String(), "Storage Blob Data Reader")
	st, err := decodeState(p.committed)
	require.NoError(t, err)
	require.Equal(t, pollNow, st.AccountPolls["flowlogswest"], "the account's lookback stays where its outage began")

	west.listErr = nil
	h.now = h.now.Add(time.Minute)
	west.append(westBlobName(h.now.Truncate(time.Hour), macB), h.now, flowRecord(macB, fmt.Sprintf("%d,%sE,NX,1,100,1,100", ms(h.now), long)))
	res := pollAndReport()
	require.Empty(t, res.Failures)
	for more := res.More; more; {
		more = h.poll(p)
	}
	require.Contains(t, buf.String(), "Storage account flowlogswest works again after")
	require.NotContains(t, buf.String(), "Skipping")

	all := strings.Join(h.uploader.uploads, "")
	for i := 50001; i < port; i++ {
		require.Contains(t, all, fmt.Sprintf(`"id.orig_p":%d,`, i+1000), "west's flows from the outage")
	}
	// The open connection is uploaded whole: hourly segments (max_flow_age) of one uid, with
	// every tuple's packets, ending in the E tuple, not closed as stale during the outage
	uids := map[string]bool{}
	pkts, last := 0, ""
	for _, line := range strings.Split(all, "\n") {
		if !strings.Contains(line, `"id.orig_p":51000,`) {
			continue
		}
		var rec struct {
			UID       string `json:"uid"`
			OrigPkts  int    `json:"orig_pkts"`
			ConnState string `json:"conn_state"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		uids[rec.UID] = true
		pkts += rec.OrigPkts
		last = rec.ConnState
	}
	require.Len(t, uids, 1)
	require.Equal(t, outage/(10*time.Minute)+1, time.Duration(pkts), "one per C tuple and one for the E")
	require.Equal(t, "SF", last)
}

func TestPollerFailsWhenNoAccountCanBeListed(t *testing.T) {
	var buf strings.Builder
	defer log.SetOutput(log.Writer())
	log.SetOutput(&buf)
	h, west := newTwoAccountHarness(t)
	// The same failure in both, so only tracking each account apart logs both
	forbidden := &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationPermissionMismatch"}
	h.store.listErr, west.listErr = forbidden, forbidden
	p := NewPoller(h.cfg)
	res, err := p.Poll(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage account flowlogseast")
	require.Contains(t, err.Error(), "storage account flowlogswest")
	require.NoFileExists(t, h.cfg.StatePath, "nothing is committed")
	p.report(res, err)
	require.Equal(t, 2, strings.Count(buf.String(), "Poll failed"), "each account's failure is logged")
	require.Contains(t, buf.String(), "Poll failed, retrying at the next poll: storage account flowlogseast")
	require.Contains(t, buf.String(), "Poll failed, retrying at the next poll: storage account flowlogswest")

	// Repeated, each is throttled on its own
	for i := 0; i < 5; i++ {
		h.now = h.now.Add(time.Minute)
		res, err = p.Poll(context.Background())
		p.report(res, err)
	}
	require.Equal(t, 2, strings.Count(buf.String(), "Poll failed"), buf.String())
}

// A blob that cannot be downloaded in one account is reported for that account, and the other
// account's blobs are uploaded.
func TestPollerReportsADownloadFailureForItsAccount(t *testing.T) {
	h, west := newTwoAccountHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	west.append(westBlobName(pollNow, macB), pollNow, flowRecord(macB, endTuple(pollNow, vmB, client, 50002)))
	west.readErr = &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationPermissionMismatch"}
	p := NewPoller(h.cfg)
	res, err := p.Poll(context.Background())
	require.NoError(t, err)
	require.Len(t, res.Failures, 1)
	require.Contains(t, res.Failures[0].Error(), "storage account flowlogswest")
	_, hint := describeError(res.Failures[0])
	require.Contains(t, hint, "Storage Blob Data Reader")
	require.Contains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50001`)

	west.readErr = nil
	h.now = h.now.Add(time.Minute)
	res, err = p.Poll(context.Background())
	require.NoError(t, err)
	require.Empty(t, res.Failures)
	require.Contains(t, strings.Join(h.uploader.uploads, ""), `"id.orig_p":50002`, "read once the download works")
}

// While polls run back to back through a backlog, a failing account is tried again once per
// interval, not every poll.
func TestPollerRetriesAFailingAccountOncePerInterval(t *testing.T) {
	defer func(b int64) { pollReadBudget = b }(pollReadBudget)
	h, west := newTwoAccountHarness(t)
	var recs []string
	for i := 0; i < 20; i++ {
		recs = append(recs, flowRecord(macA, endTuple(pollNow, vmA, client, 50000+i)))
	}
	h.store.append(blobName(pollNow, macA), pollNow, recs...)
	pollReadBudget = int64(len(h.store.content(blobName(pollNow, macA)))) / 4
	west.listErr = &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationPermissionMismatch"}
	p := NewPoller(h.cfg)
	polls := 0
	for more := true; more && polls < 50; polls++ {
		res, err := p.Poll(context.Background())
		require.NoError(t, err)
		require.Len(t, res.Failures, 1, "still reported every poll")
		more = res.More
	}
	require.Greater(t, polls, 3)
	require.Len(t, west.listed, 1, "listed once, not every catch-up poll")

	h.now = h.now.Add(h.cfg.Interval)
	_, err := p.Poll(context.Background())
	require.NoError(t, err)
	require.Len(t, west.listed, 2, "tried again after an interval")
}

// An account added while it cannot be listed yet (its role assignment not applied) is read back
// to when the sensor first tried it, once it can be, as after an outage.
func TestPollerReadsANewAccountBackToItsFirstTry(t *testing.T) {
	h, west := newTwoAccountHarness(t)
	west.listErr = &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationPermissionMismatch"}
	p := NewPoller(h.cfg)
	outage := 4 * time.Hour
	require.Greater(t, outage, trackWindow)
	port := 50000
	for elapsed := time.Duration(0); elapsed <= outage; elapsed += 30 * time.Minute {
		h.now = pollNow.Add(elapsed)
		west.append(westBlobName(h.now.Truncate(time.Hour), macB), h.now, flowRecord(macB, endTuple(h.now, vmB, client, port)))
		_, err := p.Poll(context.Background())
		require.NoError(t, err)
		port++
	}
	west.listErr = nil
	h.now = h.now.Add(time.Minute)
	for more := true; more; {
		more = h.poll(p)
	}
	all := strings.Join(h.uploader.uploads, "")
	for i := 50000; i < port; i++ {
		require.Contains(t, all, fmt.Sprintf(`"id.orig_p":%d,`, i), "written while the account could not be read")
	}
}

// Adding an account to a sensor that read one keeps the first account's place: nothing it
// already read is downloaded again, and its lookback is unchanged.
func TestPollerKeepsTheStateOfASingleAccountSensor(t *testing.T) {
	h := newPollerHarness(t)
	h.store.append(blobName(pollNow, macA), pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	h.poll(NewPoller(h.cfg))
	require.Len(t, h.uploader.uploads, 1)

	west := newFakeStore()
	west.append(westBlobName(pollNow, macB), pollNow, flowRecord(macB, endTuple(pollNow, vmB, client, 50002)))
	h.cfg.Accounts = append(h.cfg.Accounts, Account{Name: "flowlogswest", Store: west})
	h.now = h.now.Add(time.Minute)
	p := NewPoller(h.cfg)
	require.NoError(t, p.Open())
	reads := h.store.reads
	h.poll(p)
	require.Equal(t, reads, h.store.reads, "the first account's finished blob is not downloaded again")
	require.Len(t, h.uploader.uploads, 2)
	require.Contains(t, h.uploader.uploads[1], `"id.orig_p":50002`)
	require.NotContains(t, h.uploader.uploads[1], `"id.orig_p":50001`)
	st, err := decodeState(p.committed)
	require.NoError(t, err)
	require.Equal(t, pollNow, st.LastPoll, "moved forward only every lastPollEvery, as before")
}

func TestPollerReadsEachBlobFromItsOwnAccount(t *testing.T) {
	h, west := newTwoAccountHarness(t)
	// The same blob name in both accounts is two blobs
	name := blobName(pollNow, macA)
	h.store.append(name, pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50001)))
	west.append(name, pollNow, flowRecord(macA, endTuple(pollNow, vmA, client, 50002)))
	h.poll(NewPoller(h.cfg))
	require.NotEmpty(t, west.readLog)
	for _, read := range append(h.store.readLog, west.readLog...) {
		require.True(t, strings.HasPrefix(read, name+"@"), "read by its name in the account: %s", read)
	}
	require.Contains(t, h.uploader.uploads[0], `"id.orig_p":50001`)
	require.Contains(t, h.uploader.uploads[0], `"id.orig_p":50002`)
}
