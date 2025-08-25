package api

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Test helper functions
func decompressData(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	zlibReader, err := zlib.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer zlibReader.Close()

	return io.ReadAll(zlibReader)
}

func base64DecodeAndDecompress(data string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return decompressData(decoded)
}

// mockPublishClient implements the grpcClient interface for testing
type mockPublishClient struct {
	uploadResponses []uploadResponse
	currentCall     int
}

type uploadResponse struct {
	status     string
	statusCode int32
	message    string
	err        error
}

func (m *mockPublishClient) uploadExcelMethod(ctx context.Context, data []byte, employeeId string) (string, int32, string, error) {
	if m.currentCall >= len(m.uploadResponses) {
		return "", 0, "", status.Error(codes.Internal, "unexpected call")
	}
	resp := m.uploadResponses[m.currentCall]
	m.currentCall++
	return resp.status, resp.statusCode, resp.message, resp.err
}

// TestLogUploader_UploadLogs verifies the LogUploader's UploadLogs method for various scenarios:
// - Successful upload
// - Retry on failure and eventual success
// - All retries fail and error is returned
func TestLogUploader_UploadLogs(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	dnsPath := filepath.Join(tmpDir, "dns.xlsx")
	connPath := filepath.Join(tmpDir, "conn.log")

	// Write test data
	require.NoError(t, os.WriteFile(dnsPath, []byte("test dns data"), 0644))
	require.NoError(t, os.WriteFile(connPath, []byte("test conn data"), 0644))

	tests := []struct {
		name            string
		uploadResponses []uploadResponse
		wantErr         bool
		retryCount      int
	}{
		{
			name: "successful upload",
			uploadResponses: []uploadResponse{
				{
					status:     "success",
					statusCode: 200,
					message:    "ok",
					err:        nil,
				},
			},
			wantErr:    false,
			retryCount: 1,
		},
		{
			name: "retry success",
			uploadResponses: []uploadResponse{
				{
					status:     "",
					statusCode: 0,
					message:    "",
					err:        status.Error(codes.Unavailable, "server unavailable"),
				},
				{
					status:     "success",
					statusCode: 200,
					message:    "ok",
					err:        nil,
				},
			},
			wantErr:    false,
			retryCount: 2,
		},
		{
			name: "all retries fail",
			uploadResponses: []uploadResponse{
				{
					status:     "",
					statusCode: 0,
					message:    "",
					err:        status.Error(codes.Unavailable, "server unavailable"),
				},
				{
					status:     "",
					statusCode: 0,
					message:    "",
					err:        status.Error(codes.Unavailable, "server unavailable"),
				},
				{
					status:     "",
					statusCode: 0,
					message:    "",
					err:        status.Error(codes.Unavailable, "server unavailable"),
				},
			},
			wantErr:    true,
			retryCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock client
			mock := &mockPublishClient{
				uploadResponses: tt.uploadResponses,
			}

			// Create uploader with mock
			uploader := &LogUploader{
				client:       mock,
				apiKey:       "test-key",
				retryCount:   3,
				retryDelay:   time.Millisecond, // Short delay for tests
				compressFunc: compressData,
			}

			// Test upload
			err := uploader.UploadLogs(context.Background(), LogFiles{
				DNSPath:  dnsPath,
				ConnPath: connPath,
			})

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify retry count
			assert.Equal(t, tt.retryCount, mock.currentCall)
		})
	}
}

// TestLogUploader_PrepareLogData verifies that log data is correctly prepared, compressed, and can be decompressed and validated.
func TestLogUploader_PrepareLogData(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	dnsPath := filepath.Join(tmpDir, "dns.xlsx")
	connPath := filepath.Join(tmpDir, "conn.log")

	dnsData := []byte("test dns data")
	connData := []byte("test conn data")

	require.NoError(t, os.WriteFile(dnsPath, dnsData, 0644))
	require.NoError(t, os.WriteFile(connPath, connData, 0644))

	uploader := &LogUploader{
		apiKey:       "test-key",
		retryCount:   3,
		retryDelay:   time.Second,
		compressFunc: compressData,
	}

	// Test data preparation
	compressed, err := uploader.prepareLogData(LogFiles{
		DNSPath:  dnsPath,
		ConnPath: connPath,
	})
	require.NoError(t, err)

	// Decompress and verify
	decompressed, err := decompressData(compressed)
	require.NoError(t, err)

	var combined CombinedLogs
	require.NoError(t, json.Unmarshal(decompressed, &combined))

	// Decode and decompress DNS data
	dnsDecoded, err := base64DecodeAndDecompress(combined.DNS)
	require.NoError(t, err)
	assert.Equal(t, dnsData, dnsDecoded)

	// Decode and decompress conn data
	connDecoded, err := base64DecodeAndDecompress(combined.Conn)
	require.NoError(t, err)
	assert.Equal(t, connData, connDecoded)
}

// TestUploadLogs_ReadFileError simulates a failure to read one of the log files and expects an error from UploadLogs.
func TestUploadLogs_ReadFileError(t *testing.T) {
	mock := &mockPublishClient{
		uploadResponses: []uploadResponse{{status: "success", statusCode: 200, message: "ok", err: nil}},
	}
	uploader := &LogUploader{
		client:       mock,
		apiKey:       "test-key",
		retryCount:   1,
		retryDelay:   time.Millisecond,
		compressFunc: compressData,
	}
	// Provide non-existent file paths for both logs (should error)
	err := uploader.UploadLogs(context.Background(), LogFiles{
		DNSPath:  "nonexistent_dns.log",
		ConnPath: "nonexistent_conn.log",
	})
	assert.Error(t, err)

	// Provide only missing DNS log (should succeed)
	tmpDir := t.TempDir()
	connPath := filepath.Join(tmpDir, "conn.log")
	assert.NoError(t, os.WriteFile(connPath, []byte("conn data"), 0644))
	err = uploader.UploadLogs(context.Background(), LogFiles{
		DNSPath:  filepath.Join(tmpDir, "missing_dns.log"),
		ConnPath: connPath,
	})
	assert.NoError(t, err)
}

// TestUploadLogs_CompressError simulates a compression failure and expects an error from UploadLogs.
func TestUploadLogs_CompressError(t *testing.T) {
	uploader := &LogUploader{
		apiKey:       "test-key",
		retryCount:   1,
		retryDelay:   time.Millisecond,
		compressFunc: func(_ []byte) ([]byte, error) { return nil, fmt.Errorf("compress error") },
	}
	// Create temp files with valid data
	tmpDir := t.TempDir()
	dnsPath := filepath.Join(tmpDir, "dns.xlsx")
	connPath := filepath.Join(tmpDir, "conn.log")
	assert.NoError(t, os.WriteFile(dnsPath, []byte("dns"), 0644))
	assert.NoError(t, os.WriteFile(connPath, []byte("conn"), 0644))
	err := uploader.UploadLogs(context.Background(), LogFiles{
		DNSPath:  dnsPath,
		ConnPath: connPath,
	})
	assert.Error(t, err)
}

// TestUploadLogs_UploadNon200 simulates a non-200 status code from the upload and expects an error from UploadLogs.
func TestUploadLogs_UploadNon200(t *testing.T) {
	tmpDir := t.TempDir()
	dnsPath := filepath.Join(tmpDir, "dns.xlsx")
	connPath := filepath.Join(tmpDir, "conn.log")
	assert.NoError(t, os.WriteFile(dnsPath, []byte("dns"), 0644))
	assert.NoError(t, os.WriteFile(connPath, []byte("conn"), 0644))
	mock := &mockPublishClient{
		uploadResponses: []uploadResponse{{status: "fail", statusCode: 500, message: "server error", err: nil}},
	}
	uploader := &LogUploader{
		client:       mock,
		apiKey:       "test-key",
		retryCount:   1,
		retryDelay:   time.Millisecond,
		compressFunc: compressData,
	}
	err := uploader.UploadLogs(context.Background(), LogFiles{
		DNSPath:  dnsPath,
		ConnPath: connPath,
	})
	assert.Error(t, err)
}

// TestUploadLogs_ContextCancelled simulates context cancellation before upload and expects an error from UploadLogs.
func TestUploadLogs_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	dnsPath := filepath.Join(tmpDir, "dns.xlsx")
	connPath := filepath.Join(tmpDir, "conn.log")
	assert.NoError(t, os.WriteFile(dnsPath, []byte("dns"), 0644))
	assert.NoError(t, os.WriteFile(connPath, []byte("conn"), 0644))
	mock := &mockPublishClient{
		uploadResponses: []uploadResponse{{status: "success", statusCode: 200, message: "ok", err: nil}},
	}
	uploader := &LogUploader{
		client:       mock,
		apiKey:       "test-key",
		retryCount:   1,
		retryDelay:   time.Millisecond,
		compressFunc: compressData,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := uploader.UploadLogs(ctx, LogFiles{
		DNSPath:  dnsPath,
		ConnPath: connPath,
	})
	assert.Error(t, err)
}

// TestUploadLogs_410Gone simulates the API returning 410 Gone and expects an error from UploadLogs.
func TestUploadLogs_410Gone(t *testing.T) {
	tmpDir := t.TempDir()
	dnsPath := filepath.Join(tmpDir, "dns.xlsx")
	connPath := filepath.Join(tmpDir, "conn.log")
	assert.NoError(t, os.WriteFile(dnsPath, []byte("dns"), 0644))
	assert.NoError(t, os.WriteFile(connPath, []byte("conn"), 0644))
	mock := &mockPublishClient{
		uploadResponses: []uploadResponse{{status: "gone", statusCode: 410, message: "gone", err: nil}},
	}
	uploader := &LogUploader{
		client:       mock,
		apiKey:       "test-key",
		retryCount:   1,
		retryDelay:   time.Millisecond,
		compressFunc: compressData,
	}
	err := uploader.UploadLogs(context.Background(), LogFiles{
		DNSPath:  dnsPath,
		ConnPath: connPath,
	})
	if !errors.Is(err, ErrAPIGone) {
		t.Fatalf("expected error to be ErrAPIGone, got: %v", err)
	}
}

// TestCalculateTotalFileSize tests the file size calculation functionality
func TestCalculateTotalFileSize(t *testing.T) {
	// Create temporary test files
	tempDir := t.TempDir()

	dnsFile := filepath.Join(tempDir, "dns.csv")
	connFile := filepath.Join(tempDir, "conn.csv")

	// Write test data
	dnsData := "header1,header2\nvalue1,value2\n"
	connData := "header1,header2\nvalue1,value2\nvalue3,value4\n"

	require.NoError(t, os.WriteFile(dnsFile, []byte(dnsData), 0600))
	require.NoError(t, os.WriteFile(connFile, []byte(connData), 0600))

	uploader := &LogUploader{maxPayloadSizeMB: 25}

	files := LogFiles{
		DNSPath:  dnsFile,
		ConnPath: connFile,
	}

	sizeMB, err := uploader.calculateTotalFileSize(files)
	require.NoError(t, err)

	// Should be 0 MB for small test files
	assert.Equal(t, int64(0), sizeMB)

	// Test with missing DNS file
	files.DNSPath = ""
	sizeMB, err = uploader.calculateTotalFileSize(files)
	require.NoError(t, err)

	assert.Equal(t, int64(0), sizeMB)
}

// TestSplitCSVFile tests the CSV file splitting functionality
func TestSplitCSVFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.csv")

	// Create test CSV with header and multiple rows
	content := "timestamp,src_ip,dst_ip,protocol\n"
	for i := 0; i < 100; i++ {
		content += "2023-01-01,192.168.1.1,10.0.0.1,tcp\n"
	}

	require.NoError(t, os.WriteFile(testFile, []byte(content), 0600))

	tests := []struct {
		name              string
		maxSizeBytes      int64
		minExpectedChunks int
	}{
		{"no_split", 10000, 1},     // Large enough to fit everything
		{"split_multiple", 500, 2}, // Small enough to force splitting
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks, err := splitCSVFile(testFile, tt.maxSizeBytes)
			require.NoError(t, err)

			assert.GreaterOrEqual(t, len(chunks), tt.minExpectedChunks)

			// Verify each chunk has header
			for i, chunkPath := range chunks {
				data, err := os.ReadFile(chunkPath)
				require.NoError(t, err)

				lines := strings.Split(string(data), "\n")
				assert.GreaterOrEqual(t, len(lines), 2, "Chunk %d should have at least header and one data line", i)

				assert.Equal(t, "timestamp,src_ip,dst_ip,protocol", lines[0], "Chunk %d missing correct header", i)

				// Clean up chunk files (except original)
				if chunkPath != testFile {
					os.Remove(chunkPath)
				}
			}
		})
	}
}

// TestUploadLogsChunking tests that large files trigger chunking behavior
func TestUploadLogsChunking(t *testing.T) {
	tempDir := t.TempDir()

	// Create large test files that will exceed threshold
	dnsFile := filepath.Join(tempDir, "dns.csv")
	connFile := filepath.Join(tempDir, "conn.csv")

	// Create files with enough data to trigger chunking (>1MB each)
	largeContent := "timestamp,src_ip,dst_ip,protocol\n"
	for i := 0; i < 50000; i++ {
		largeContent += "2023-01-01,192.168.1.1,10.0.0.1,tcp\n"
	}

	require.NoError(t, os.WriteFile(dnsFile, []byte(largeContent), 0600))
	require.NoError(t, os.WriteFile(connFile, []byte(largeContent), 0600))

	// Mock client that records upload calls
	// Need more responses now that we support 4 log types (HTTP/SSL added)
	var responses []uploadResponse
	for i := 0; i < 20; i++ { // Provide enough responses for multiple chunks
		responses = append(responses, uploadResponse{"success", 200, "ok", nil})
	}
	mockClient := &mockPublishClient{
		uploadResponses: responses,
	}

	uploader := &LogUploader{
		client:           mockClient,
		apiKey:           "test-key",
		retryCount:       1,
		retryDelay:       time.Millisecond,
		compressFunc:     compressData,
		maxPayloadSizeMB: 1, // 1MB threshold to force chunking
	}

	files := LogFiles{
		DNSPath:  dnsFile,
		ConnPath: connFile,
	}

	ctx := context.Background()
	err := uploader.UploadLogs(ctx, files)
	require.NoError(t, err)

	// Should have made multiple upload calls due to chunking
	assert.GreaterOrEqual(t, mockClient.currentCall, 2, "Expected multiple upload calls due to chunking")
}

// TestUploadLogsSinglePath tests that small files use the single upload path
func TestUploadLogsSinglePath(t *testing.T) {
	tempDir := t.TempDir()

	// Create small test files that won't trigger chunking
	dnsFile := filepath.Join(tempDir, "dns.csv")
	connFile := filepath.Join(tempDir, "conn.csv")

	smallContent := "timestamp,src_ip,dst_ip,protocol\nvalue1,value2,value3,value4\n"

	require.NoError(t, os.WriteFile(dnsFile, []byte(smallContent), 0600))
	require.NoError(t, os.WriteFile(connFile, []byte(smallContent), 0600))

	mockClient := &mockPublishClient{
		uploadResponses: []uploadResponse{
			{"success", 200, "ok", nil},
		},
	}

	uploader := &LogUploader{
		client:           mockClient,
		apiKey:           "test-key",
		retryCount:       1,
		retryDelay:       time.Millisecond,
		compressFunc:     compressData,
		maxPayloadSizeMB: 25, // Large threshold, won't trigger chunking
	}

	files := LogFiles{
		DNSPath:  dnsFile,
		ConnPath: connFile,
	}

	ctx := context.Background()
	err := uploader.UploadLogs(ctx, files)
	require.NoError(t, err)

	// Should have made exactly one upload call
	assert.Equal(t, 1, mockClient.currentCall)
}
