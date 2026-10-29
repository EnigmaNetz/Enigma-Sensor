package flowlogs

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/stretchr/testify/require"
)

// TestAzurite runs the poller against Azurite, the Azure Storage emulator, through the real
// Azure SDK. It writes a blob the way Network Watcher does, as committed blocks: a header, one
// block per record, and a footer that new records are committed in front of. It is skipped
// unless Azurite is configured (see azuriteContainer).
func TestAzurite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cc, account := azuriteContainer(ctx, t)

	now := time.Now().UTC()
	name := blobName(now, macA)
	bb := cc.NewBlockBlobClient(name)
	var ids []string
	stage := func(content string) string {
		id := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("block-%06d", len(ids))))
		_, err := bb.StageBlock(ctx, id, streaming.NopCloser(bytes.NewReader([]byte(content))), nil)
		require.NoError(t, err)
		ids = append(ids, id)
		return id
	}
	commit := func(blocks []string) {
		_, err := bb.CommitBlockList(ctx, blocks, &blockblob.CommitBlockListOptions{})
		require.NoError(t, err)
	}
	k := vmA + "," + client + ",50000,443,6,O,"
	header := stage(`{"records":[`)
	footer := stage(`]}`)
	first := stage(flowRecord(macA,
		fmt.Sprintf("%d,%sB,NX,,,,", ms(now), k),
		fmt.Sprintf("%d,%s,%s,50001,443,6,O,E,NX,3,300,3,3000", ms(now), vmA, client)))
	commit([]string{header, first, footer})

	// The sensor signs in only with a managed identity; the account key is for the emulator
	store := &azureStore{client: cc}
	uploader := &fakeUploader{}
	dir := t.TempDir()
	p := NewPoller(PollerConfig{
		Accounts: []Account{{Name: account, Store: store}}, Uploader: uploader,
		OutputDir: filepath.Join(dir, "captures"), StatePath: filepath.Join(dir, "state.json"),
		Interval: time.Minute,
	})
	_, err := p.Poll(ctx)
	require.NoError(t, err)
	require.Len(t, uploader.uploads, 1)
	require.Contains(t, uploader.uploads[0], `"id.orig_p":50001`)
	require.NotContains(t, uploader.uploads[0], `"id.orig_p":50000`, "still open")

	// Network Watcher commits the next record in front of the footer
	second := stage("," + flowRecord(macA, fmt.Sprintf("%d,%sE,NX,5,500,5,5000", ms(now.Add(time.Minute)), k)))
	commit([]string{header, first, second, footer})
	_, err = p.Poll(ctx)
	require.NoError(t, err)
	require.Len(t, uploader.uploads, 2)
	require.Contains(t, uploader.uploads[1], `"id.orig_p":50000`)
	require.Contains(t, uploader.uploads[1], `"history":"SF"`)
	require.NotContains(t, uploader.uploads[1], `"id.orig_p":50001`, "already uploaded")

	_, err = p.Poll(ctx)
	require.NoError(t, err)
	require.Len(t, uploader.uploads, 2, "nothing new")
}

// TestAzuriteTwoAccounts reads two containers through the real Azure SDK as two storage
// accounts: both are read, a flow logged in both is uploaded once, and when one cannot be read
// the other still is, with the failure naming its account. It is skipped like TestAzurite.
func TestAzuriteTwoAccounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	east, _ := azuriteContainer(ctx, t)
	west, _ := azuriteContainer(ctx, t)

	now := time.Now().UTC()
	k := fmt.Sprintf("%s,%s,52114,1433,6,", vmB, vmA) // macB's VM starts it, macA's VM serves it
	upload := func(cc *container.Client, name string, recs ...string) {
		_, err := cc.NewBlockBlobClient(name).UploadBuffer(ctx, []byte(`{"records":[`+strings.Join(recs, ",")+`]}`), nil)
		require.NoError(t, err)
	}
	upload(east, blobName(now, macA),
		flowRecord(macA, fmt.Sprintf("%d,%sI,E,NX,3,300,3,3000", ms(now), k)),
		flowRecord(macA, endTuple(now, vmA, client, 50001)))
	upload(west, westBlobName(now, macB),
		flowRecord(macB, fmt.Sprintf("%d,%sO,E,NX,3,300,3,3000", ms(now), k)),
		flowRecord(macB, endTuple(now, vmB, client, 50002)))

	uploader := &fakeUploader{}
	dir := t.TempDir()
	p := NewPoller(PollerConfig{
		Accounts: []Account{
			{Name: "flowlogseast", Store: &azureStore{client: east}},
			{Name: "flowlogswest", Store: &azureStore{client: west}},
		},
		Uploader:  uploader,
		OutputDir: filepath.Join(dir, "captures"), StatePath: filepath.Join(dir, "state.json"),
		Interval: time.Minute,
	})
	res, err := p.Poll(ctx)
	require.NoError(t, err)
	require.Empty(t, res.Failures)
	require.Len(t, uploader.uploads, 1)
	require.Contains(t, uploader.uploads[0], `"id.orig_p":50001`)
	require.Contains(t, uploader.uploads[0], `"id.orig_p":50002`)
	require.Equal(t, 1, strings.Count(uploader.uploads[0], `"id.resp_p":1433`), "logged in both accounts, uploaded once")

	// The west account's container goes away; east keeps being read
	_, err = west.Delete(ctx, nil)
	require.NoError(t, err)
	upload(east, blobName(now, macA),
		flowRecord(macA, fmt.Sprintf("%d,%sI,E,NX,3,300,3,3000", ms(now), k)),
		flowRecord(macA, endTuple(now, vmA, client, 50001)),
		flowRecord(macA, endTuple(now.Add(time.Minute), vmA, client, 50003)))
	res, err = p.Poll(ctx)
	require.NoError(t, err, "one account failing does not fail the poll")
	require.Len(t, res.Failures, 1)
	require.Contains(t, res.Failures[0].Error(), "storage account flowlogswest")
	kind, hint := describeError(res.Failures[0])
	require.Contains(t, kind, "404")
	require.Contains(t, hint, "azure_flow_logs.container")
	require.Len(t, uploader.uploads, 2)
	require.Contains(t, uploader.uploads[1], `"id.orig_p":50003`)
	require.NotContains(t, uploader.uploads[1], `"id.orig_p":50001`, "already uploaded")
}

// azuriteContainer creates a container in Azurite for one test and returns it, or skips the
// test unless these are set (see DEVELOPMENT.md); the account key is never committed:
//
//	AZURITE_BLOB_ENDPOINT  for example http://127.0.0.1:10000/devstoreaccount1
//	AZURITE_ACCOUNT        the emulator's account name
//	AZURITE_ACCOUNT_KEY    the emulator's account key
func azuriteContainer(ctx context.Context, t *testing.T) (*container.Client, string) {
	t.Helper()
	endpoint, account, key := os.Getenv("AZURITE_BLOB_ENDPOINT"), os.Getenv("AZURITE_ACCOUNT"), os.Getenv("AZURITE_ACCOUNT_KEY")
	if endpoint == "" || account == "" || key == "" {
		t.Skip("set AZURITE_BLOB_ENDPOINT, AZURITE_ACCOUNT and AZURITE_ACCOUNT_KEY to run against Azurite")
	}
	containerName := fmt.Sprintf("flowlogs-test-%d", time.Now().UnixNano())
	cred, err := container.NewSharedKeyCredential(account, key)
	require.NoError(t, err)
	cc, err := container.NewClientWithSharedKeyCredential(containerURL(endpoint, containerName), cred, nil)
	require.NoError(t, err)
	_, err = cc.Create(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = cc.Delete(context.Background(), nil) })
	return cc, account
}
