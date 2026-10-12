package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api/ingest"
)

// Test buffering on temporary errors and flushing on recovery
func TestLogUploader_BufferAndFlush(t *testing.T) {
	// First call returns 500 (cause buffer), second and third succeed (flush + current)
	mock := &mockPublishClient{uploadResponses: []uploadResponse{
		{status: "fail", statusCode: 500, message: "server error", err: nil},
		{status: "success", statusCode: 200, message: "ok", err: nil},
		{status: "success", statusCode: 200, message: "ok", err: nil},
	}}

	uploader := &LogUploader{
		client:           mock,
		apiKey:           "k",
		networkID:        "Test-Network-01",
		retryCount:       1,
		retryDelay:       time.Millisecond,
		maxPayloadSizeMB: 25,
		bufferDir:        filepath.Join(t.TempDir(), "buffer"),
		bufferMaxAge:     2 * time.Hour,
	}

	// First upload should buffer and return error
	err := uploader.UploadLogs(context.Background(), writeJSONLogs(t))
	require.Error(t, err)

	// One buffered request, saved without the API key
	entries, err := os.ReadDir(uploader.bufferDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	data, err := os.ReadFile(filepath.Join(uploader.bufferDir, entries[0].Name()))
	require.NoError(t, err)
	var buffered ingest.UploadRecordsRequest
	require.NoError(t, proto.Unmarshal(data, &buffered))
	assert.Empty(t, buffered.ApiKey, "the API key must never be written to the buffer")
	assert.NotEmpty(t, buffered.Records)

	// Second upload should flush buffered first, then upload current
	err = uploader.UploadLogs(context.Background(), writeJSONLogs(t))
	require.NoError(t, err)
	require.Len(t, mock.requests, 3)
	assert.Equal(t, "k", mock.requests[1].ApiKey, "the key is added back when the buffered request is sent")
	assert.Equal(t, buffered.Records, mock.requests[1].Records)

	// Buffer dir should be empty after successful flush
	entries, err = os.ReadDir(uploader.bufferDir)
	require.NoError(t, err)
	require.Equal(t, 0, len(entries))
}

// Test that old buffered files are purged based on max age
func TestLogUploader_BufferPurgeOld(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))

	uploader := &LogUploader{
		apiKey:       "k",
		networkID:    "Test-Network-01",
		retryCount:   1,
		retryDelay:   time.Millisecond,
		bufferDir:    bufDir,
		bufferMaxAge: time.Hour, // 1 hour
	}

	// Create a fake buffered file and age it
	f := filepath.Join(bufDir, "buf_20000101T000000Z_1.bin")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(f, old, old))

	// Flush should purge the old file even without a client
	require.NoError(t, uploader.flushBuffer(context.Background()))

	entries, err := os.ReadDir(bufDir)
	require.NoError(t, err)
	require.Equal(t, 0, len(entries))
}

// Test that a 410 is neither retried nor buffered
func TestLogUploader_410NotRetriedOrBuffered(t *testing.T) {
	// Only one response: a retry would hit the mock's "unexpected call" error
	mock := &mockPublishClient{uploadResponses: []uploadResponse{
		{status: "gone", statusCode: 410, message: "gone", err: nil},
	}}

	uploader := &LogUploader{
		client:           mock,
		apiKey:           "k",
		networkID:        "Test-Network-01",
		retryCount:       3,
		retryDelay:       time.Millisecond,
		maxPayloadSizeMB: 25,
		bufferDir:        filepath.Join(t.TempDir(), "buffer"),
		bufferMaxAge:     2 * time.Hour,
	}

	err := uploader.UploadLogs(context.Background(), writeJSONLogs(t))
	require.True(t, errors.Is(err, ErrAPIGone), "expected ErrAPIGone, got: %v", err)
	require.Equal(t, 1, mock.currentCall)

	_, err = os.Stat(uploader.bufferDir)
	require.True(t, os.IsNotExist(err), "a 410 payload must not be buffered")
}

// A payload an older sensor version buffered before the upgrade is still sent the old way, and
// a 410 while flushing it stops before sending the current payload.
func TestLogUploader_410DuringLegacyFlushStops(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bufDir, "buf_20000101T000000Z_1.bin"), []byte("x"), 0o600))

	mock := &mockPublishClient{uploadResponses: []uploadResponse{
		{status: "gone", statusCode: 410, message: "gone", err: nil},
	}}

	uploader := &LogUploader{
		client:           mock,
		apiKey:           "k",
		networkID:        "Test-Network-01",
		retryCount:       3,
		retryDelay:       time.Millisecond,
		maxPayloadSizeMB: 25,
		bufferDir:        bufDir,
		bufferMaxAge:     2 * time.Hour,
	}

	err := uploader.UploadLogs(context.Background(), writeJSONLogs(t))
	require.True(t, errors.Is(err, ErrAPIGone), "expected ErrAPIGone, got: %v", err)
	require.Equal(t, 1, mock.legacyCalls, "the legacy payload goes through uploadExcelMethod")
	require.Equal(t, []string{"k"}, mock.legacyKeys, "with the API key in employeeId")
	require.Equal(t, [][]byte{[]byte("x")}, mock.legacyData, "and the buffered bytes unchanged")
	require.Empty(t, mock.requests)

	// The buffered payload stays for a later run, and the current payload is not added
	entries, err := os.ReadDir(bufDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "buf_20000101T000000Z_1.bin", entries[0].Name())
}

// A legacy payload the Publisher refuses with a 400 is deleted like a typed one, and a file that
// is neither kind is left alone.
func TestFlushBuffer_LegacyRefusedAndUnknownFiles(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bufDir, "buf_20000101T000000Z_1.bin"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(bufDir, "notes.txt"), []byte("not a payload"), 0o600))

	mock := &mockPublishClient{uploadResponses: []uploadResponse{{status: "error", statusCode: 400, message: "bad payload"}}}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", bufferDir: bufDir}

	require.NoError(t, uploader.flushBuffer(context.Background()))

	assert.Equal(t, 1, mock.legacyCalls)
	entries, err := os.ReadDir(bufDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "notes.txt", entries[0].Name())
}

// A buffered request the Publisher refuses with a 400 can never succeed: it is deleted and the
// flush carries on with the next one.
func TestFlushBuffer_DropsRefusedRequest(t *testing.T) {
	bufDir := filepath.Join(t.TempDir(), "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))
	req, err := proto.Marshal(&ingest.UploadRecordsRequest{SchemaVersion: 1, Records: []byte("r")})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bufDir, "buf_20000101T000000Z_1.rec"), req, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(bufDir, "buf_20000101T000000Z_2.rec"), req, 0o600))

	mock := &mockPublishClient{uploadResponses: []uploadResponse{
		{status: "error", statusCode: 400, message: "Unsupported schemaVersion 1"},
		{status: "success", statusCode: 200},
	}}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", bufferDir: bufDir}

	require.NoError(t, uploader.flushBuffer(context.Background()))

	assert.Equal(t, 2, mock.currentCall)
	entries, err := os.ReadDir(bufDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
