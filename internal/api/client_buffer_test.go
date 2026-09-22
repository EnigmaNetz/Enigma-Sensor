package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Test buffering on temporary errors and flushing on recovery
func TestLogUploader_BufferAndFlush(t *testing.T) {
	tmpDir := t.TempDir()

	// Create small test files
	dnsPath := filepath.Join(tmpDir, "dns.csv")
	connPath := filepath.Join(tmpDir, "conn.csv")
	require.NoError(t, os.WriteFile(dnsPath, []byte("h\na\n"), 0600))
	require.NoError(t, os.WriteFile(connPath, []byte("h\nb\n"), 0600))

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
		compressFunc:     compressData,
		maxPayloadSizeMB: 25,
		bufferDir:        filepath.Join(tmpDir, "buffer"),
		bufferMaxAge:     2 * time.Hour,
	}

	// First upload should buffer and return error
	err := uploader.UploadLogs(context.Background(), LogFiles{DNSPath: dnsPath, ConnPath: connPath})
	require.Error(t, err)

	// Ensure a buffer file exists
	entries, err := os.ReadDir(uploader.bufferDir)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(entries), 1)

	// Second upload should flush buffered first, then upload current
	require.NoError(t, os.WriteFile(connPath, []byte("h\nc\n"), 0600))
	err = uploader.UploadLogs(context.Background(), LogFiles{DNSPath: dnsPath, ConnPath: connPath})
	require.NoError(t, err)

	// Buffer dir should be empty after successful flush
	entries, err = os.ReadDir(uploader.bufferDir)
	require.NoError(t, err)
	require.Equal(t, 0, len(entries))
}

// Test that old buffered files are purged based on max age
func TestLogUploader_BufferPurgeOld(t *testing.T) {
	tmpDir := t.TempDir()
	bufDir := filepath.Join(tmpDir, "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))

	uploader := &LogUploader{
		apiKey:       "k",
		networkID:    "Test-Network-01",
		retryCount:   1,
		retryDelay:   time.Millisecond,
		compressFunc: compressData,
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
	tmpDir := t.TempDir()

	dnsPath := filepath.Join(tmpDir, "dns.csv")
	connPath := filepath.Join(tmpDir, "conn.csv")
	require.NoError(t, os.WriteFile(dnsPath, []byte("h\na\n"), 0600))
	require.NoError(t, os.WriteFile(connPath, []byte("h\nb\n"), 0600))

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
		compressFunc:     compressData,
		maxPayloadSizeMB: 25,
		bufferDir:        filepath.Join(tmpDir, "buffer"),
		bufferMaxAge:     2 * time.Hour,
	}

	err := uploader.UploadLogs(context.Background(), LogFiles{DNSPath: dnsPath, ConnPath: connPath})
	require.True(t, errors.Is(err, ErrAPIGone), "expected ErrAPIGone, got: %v", err)
	require.Equal(t, 1, mock.currentCall)

	_, err = os.Stat(uploader.bufferDir)
	require.True(t, os.IsNotExist(err), "a 410 payload must not be buffered")
}

// Test that a 410 while flushing the buffer stops before sending the current payload
func TestLogUploader_410DuringFlushStops(t *testing.T) {
	tmpDir := t.TempDir()
	bufDir := filepath.Join(tmpDir, "buffer")
	require.NoError(t, os.MkdirAll(bufDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bufDir, "buf_20000101T000000Z_1.bin"), []byte("x"), 0o600))

	dnsPath := filepath.Join(tmpDir, "dns.csv")
	connPath := filepath.Join(tmpDir, "conn.csv")
	require.NoError(t, os.WriteFile(dnsPath, []byte("h\na\n"), 0600))
	require.NoError(t, os.WriteFile(connPath, []byte("h\nb\n"), 0600))

	mock := &mockPublishClient{uploadResponses: []uploadResponse{
		{status: "gone", statusCode: 410, message: "gone", err: nil},
	}}

	uploader := &LogUploader{
		client:           mock,
		apiKey:           "k",
		networkID:        "Test-Network-01",
		retryCount:       3,
		retryDelay:       time.Millisecond,
		compressFunc:     compressData,
		maxPayloadSizeMB: 25,
		bufferDir:        bufDir,
		bufferMaxAge:     2 * time.Hour,
	}

	err := uploader.UploadLogs(context.Background(), LogFiles{DNSPath: dnsPath, ConnPath: connPath})
	require.True(t, errors.Is(err, ErrAPIGone), "expected ErrAPIGone, got: %v", err)
	require.Equal(t, 1, mock.currentCall)

	// The buffered payload stays for a later run, and the current payload is not added
	entries, err := os.ReadDir(bufDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "buf_20000101T000000Z_1.bin", entries[0].Name())
}
