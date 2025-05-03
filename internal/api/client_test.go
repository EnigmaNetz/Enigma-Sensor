package api

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

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
				client:     mock,
				apiKey:     "test-key",
				retryCount: 3,
				retryDelay: time.Millisecond, // Short delay for tests
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
		apiKey:     "test-key",
		retryCount: 3,
		retryDelay: time.Second,
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
