package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingClient never answers: it waits until the RPC's context ends, like a
// hung or half-open connection.
type blockingClient struct{}

func (blockingClient) uploadExcelMethod(ctx context.Context, _ []byte, _ string, _ map[string]string) (string, int32, string, error) {
	<-ctx.Done()
	return "", 0, "", ctx.Err()
}

// countingClient succeeds after a short delay and counts uploads per payload.
// It is safe for concurrent use.
type countingClient struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *countingClient) uploadExcelMethod(_ context.Context, data []byte, _ string, _ map[string]string) (string, int32, string, error) {
	time.Sleep(5 * time.Millisecond) // widen the window in which workers overlap
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[string(data)]++
	return "success", 200, "ok", nil
}

func writeTestLogs(t *testing.T) LogFiles {
	t.Helper()
	dir := t.TempDir()
	files := LogFiles{DNSPath: filepath.Join(dir, "dns.log"), ConnPath: filepath.Join(dir, "conn.log")}
	require.NoError(t, os.WriteFile(files.DNSPath, []byte("h\na\n"), 0o600))
	require.NoError(t, os.WriteFile(files.ConnPath, []byte("h\nb\n"), 0o600))
	return files
}

func TestUpload_RPCHasDeadline(t *testing.T) {
	uploader := &LogUploader{
		client:        blockingClient{},
		apiKey:        "k",
		networkID:     "Test-Network-01",
		uploadTimeout: 50 * time.Millisecond,
	}

	start := time.Now()
	err := uploader.upload(context.Background(), []byte("payload"))

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second, "a hung RPC must not block past its deadline")
}

func TestUpload_DefaultDeadline(t *testing.T) {
	var deadline time.Time
	var ok bool
	client := clientFunc(func(ctx context.Context) {
		deadline, ok = ctx.Deadline()
	})
	uploader := &LogUploader{client: client, apiKey: "k", networkID: "Test-Network-01"}

	require.NoError(t, uploader.upload(context.Background(), []byte("payload")))
	require.True(t, ok, "the RPC context must carry a deadline")
	assert.WithinDuration(t, time.Now().Add(defaultUploadTimeout), deadline, 5*time.Second)
}

// clientFunc answers 200 after passing the RPC context to fn.
type clientFunc func(ctx context.Context)

func (f clientFunc) uploadExcelMethod(ctx context.Context, _ []byte, _ string, _ map[string]string) (string, int32, string, error) {
	f(ctx)
	return "success", 200, "ok", nil
}

func TestUploadLogs_CancelledChunkedUploadBuffersEveryChunk(t *testing.T) {
	dir := t.TempDir()
	// Twenty lines of 60 KB make a file over 1 MB, so with max_payload_size_mb 0
	// it is chunked, one line per chunk.
	const lines = 20
	line := strings.Repeat("x", 60*1024)
	connPath := filepath.Join(dir, "conn.log")
	require.NoError(t, os.WriteFile(connPath, []byte("h\n"+strings.Repeat(line+"\n", lines)), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bufDir := filepath.Join(dir, "buffer")
	uploader := &LogUploader{
		client:       cancelThenFailClient{cancel: cancel},
		apiKey:       "k",
		networkID:    "Test-Network-01",
		retryCount:   3,
		retryDelay:   time.Hour,
		compressFunc: compressData,
		bufferDir:    bufDir,
	}

	err := uploader.UploadLogs(ctx, LogFiles{ConnPath: connPath})

	require.ErrorIs(t, err, context.Canceled)
	entries, readErr := os.ReadDir(bufDir)
	require.NoError(t, readErr)
	assert.Len(t, entries, lines, "every chunk is buffered after cancellation, not just the first")
}

func TestRetryBackoff_DoublesWithJitter(t *testing.T) {
	uploader := &LogUploader{retryDelay: 100 * time.Millisecond}
	for retry := 1; retry <= 4; retry++ {
		full := uploader.retryDelay << (retry - 1)
		seen := map[time.Duration]bool{}
		for i := 0; i < 200; i++ {
			d := uploader.retryBackoff(retry)
			require.GreaterOrEqual(t, d, full/2, "retry %d", retry)
			require.LessOrEqual(t, d, full, "retry %d", retry)
			seen[d] = true
		}
		assert.Greater(t, len(seen), 1, "retry %d backoff is not jittered", retry)
	}
}

// failThenCancelClient fails each upload with a 500 and cancels the caller's
// context on the first one, so the upload loop is cancelled while it waits to
// retry, without depending on timing.
type failThenCancelClient struct {
	cancel context.CancelFunc
	calls  int
}

func (c *failThenCancelClient) uploadExcelMethod(_ context.Context, _ []byte, _ string, _ map[string]string) (string, int32, string, error) {
	c.calls++
	c.cancel()
	return "fail", 500, "server error", nil
}

func TestUploadLogs_CancelStopsRetryWaitAndBuffers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &failThenCancelClient{cancel: cancel}
	bufDir := filepath.Join(t.TempDir(), "buffer")
	uploader := &LogUploader{
		client:       client,
		apiKey:       "k",
		networkID:    "Test-Network-01",
		retryCount:   3,
		retryDelay:   time.Hour, // the wait must end on cancellation, not on this timer
		compressFunc: compressData,
		bufferDir:    bufDir,
	}

	start := time.Now()
	err := uploader.UploadLogs(ctx, writeTestLogs(t))

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, 1, client.calls, "no retry after cancellation")
	entries, readErr := os.ReadDir(bufDir)
	require.NoError(t, readErr)
	require.Len(t, entries, 1, "a cancelled upload is buffered, not dropped")
	assert.Regexp(t, `\.bin$`, entries[0].Name())
}

func TestUploadLogs_CancelDuringRPCBuffers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bufDir := filepath.Join(t.TempDir(), "buffer")
	uploader := &LogUploader{
		client:       cancelThenFailClient{cancel: cancel},
		apiKey:       "k",
		networkID:    "Test-Network-01",
		retryCount:   3,
		retryDelay:   time.Hour,
		compressFunc: compressData,
		bufferDir:    bufDir,
	}

	err := uploader.UploadLogs(ctx, writeTestLogs(t))

	require.ErrorIs(t, err, context.Canceled)
	entries, readErr := os.ReadDir(bufDir)
	require.NoError(t, readErr)
	assert.Len(t, entries, 1, "a payload whose RPC was cancelled is buffered")
}

// cancelThenFailClient cancels the caller's context and fails the RPC the way
// gRPC does when its context is cancelled mid-call.
type cancelThenFailClient struct{ cancel context.CancelFunc }

func (c cancelThenFailClient) uploadExcelMethod(ctx context.Context, _ []byte, _ string, _ map[string]string) (string, int32, string, error) {
	c.cancel()
	<-ctx.Done()
	return "", 0, "", ctx.Err()
}

func TestUploadLogs_NoWaitAfterLastAttempt(t *testing.T) {
	mock := &mockPublishClient{uploadResponses: []uploadResponse{
		{status: "fail", statusCode: 500, message: "server error"},
	}}
	uploader := &LogUploader{
		client:       mock,
		apiKey:       "k",
		networkID:    "Test-Network-01",
		retryCount:   1,
		retryDelay:   time.Hour,
		compressFunc: compressData,
	}

	start := time.Now()
	err := uploader.UploadLogs(context.Background(), writeTestLogs(t))

	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "the last failed attempt must not be followed by a backoff")
}

func TestFlushBuffer_ConcurrentWorkersUploadEachFileOnce(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))
	const files = 20
	for i := 0; i < files; i++ {
		name := fmt.Sprintf("buf_20260101T000000Z_%03d.bin", i)
		require.NoError(t, os.WriteFile(filepath.Join(bufDir, name), []byte(name), 0o600))
	}

	client := &countingClient{counts: map[string]int{}}
	uploader := &LogUploader{
		client:       client,
		apiKey:       "k",
		networkID:    "Test-Network-01",
		bufferDir:    bufDir,
		bufferMaxAge: time.Hour,
	}

	// As many concurrent flushes as the sensor has upload workers by default.
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			assert.NoError(t, uploader.flushBuffer(context.Background()))
		}()
	}
	close(start)
	wg.Wait()
	// A flush skipped because another was running leaves nothing behind once
	// that one finishes; a final flush must find the directory empty.
	require.NoError(t, uploader.flushBuffer(context.Background()))

	client.mu.Lock()
	defer client.mu.Unlock()
	require.Len(t, client.counts, files, "every buffered payload is uploaded")
	for payload, n := range client.counts {
		assert.Equal(t, 1, n, "%s uploaded %d times", payload, n)
	}
	entries, err := os.ReadDir(bufDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFlushBuffer_PurgesAbandonedTmpFiles(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))
	abandoned := filepath.Join(bufDir, "buf_20000101T000000Z_1.bin"+bufferTmpSuffix)
	require.NoError(t, os.WriteFile(abandoned, []byte("half a payl"), 0o600))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(abandoned, old, old))

	client := &countingClient{counts: map[string]int{}}
	uploader := &LogUploader{client: client, apiKey: "k", networkID: "Test-Network-01", bufferDir: bufDir, bufferMaxAge: time.Hour}

	require.NoError(t, uploader.flushBuffer(context.Background()))

	assert.Empty(t, client.counts)
	assert.NoFileExists(t, abandoned, "a .tmp left by a crash is purged once past buffering.max_age_hours")
}

func TestFlushBuffer_SkipsPartlyWrittenFiles(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))
	partial := filepath.Join(bufDir, "buf_20260101T000000Z_1.bin"+bufferTmpSuffix)
	require.NoError(t, os.WriteFile(partial, []byte("half a payl"), 0o600))

	client := &countingClient{counts: map[string]int{}}
	uploader := &LogUploader{client: client, apiKey: "k", networkID: "Test-Network-01", bufferDir: bufDir}

	require.NoError(t, uploader.flushBuffer(context.Background()))

	assert.Empty(t, client.counts, "a payload still being written must not be uploaded")
	assert.FileExists(t, partial)
}

func TestBufferSave_LeavesNoTemporaryFile(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	uploader := &LogUploader{bufferDir: bufDir}

	require.NoError(t, uploader.bufferSave([]byte("payload")))

	entries, err := os.ReadDir(bufDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Regexp(t, `^buf_\d{8}T\d{6}Z_\d+\.bin$`, entries[0].Name())
}

func TestUpload_WrapsRPCError(t *testing.T) {
	sentinel := errors.New("connection reset")
	mock := &mockPublishClient{uploadResponses: []uploadResponse{{err: sentinel}}}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01"}

	assert.ErrorIs(t, uploader.upload(context.Background(), []byte("payload")), sentinel)
}
