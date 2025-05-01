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

	"EnigmaNetz/Enigma-Go-Agent/internal/api/publish"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

// mockPublishClient implements publish.PublishServiceClient for testing
type mockPublishClient struct {
	uploadResponses []uploadResponse
	currentCall     int
}

type uploadResponse struct {
	resp *publish.UploadExcelResponse
	err  error
}

func (m *mockPublishClient) UploadExcelMethod(ctx context.Context, in *publish.UploadExcelRequest, opts ...grpc.CallOption) (*publish.UploadExcelResponse, error) {
	if m.currentCall >= len(m.uploadResponses) {
		return nil, status.Error(codes.Internal, "unexpected call")
	}
	resp := m.uploadResponses[m.currentCall]
	m.currentCall++
	return resp.resp, resp.err
}

func (m *mockPublishClient) GetMethod(ctx context.Context, in *publish.GetRequest, opts ...grpc.CallOption) (*publish.GetResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

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
					resp: &publish.UploadExcelResponse{
						Status:     "success",
						StatusCode: 200,
						Message:    "ok",
					},
					err: nil,
				},
			},
			wantErr:    false,
			retryCount: 1,
		},
		{
			name: "retry success",
			uploadResponses: []uploadResponse{
				{
					resp: nil,
					err:  status.Error(codes.Unavailable, "server unavailable"),
				},
				{
					resp: &publish.UploadExcelResponse{
						Status:     "success",
						StatusCode: 200,
						Message:    "ok",
					},
					err: nil,
				},
			},
			wantErr:    false,
			retryCount: 2,
		},
		{
			name: "all retries fail",
			uploadResponses: []uploadResponse{
				{
					resp: nil,
					err:  status.Error(codes.Unavailable, "server unavailable"),
				},
				{
					resp: nil,
					err:  status.Error(codes.Unavailable, "server unavailable"),
				},
				{
					resp: nil,
					err:  status.Error(codes.Unavailable, "server unavailable"),
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
