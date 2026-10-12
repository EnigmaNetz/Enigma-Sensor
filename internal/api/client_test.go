package api

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api/ingest"
)

// mockPublishClient implements the grpcClient interface for testing. Both methods answer from
// the same list of responses, in call order, and typed requests are kept for inspection.
type mockPublishClient struct {
	uploadResponses []uploadResponse
	currentCall     int
	requests        []*ingest.UploadRecordsRequest
	legacyCalls     int
	legacyKeys      []string
	legacyData      [][]byte
}

type uploadResponse struct {
	status     string
	statusCode int32
	message    string
	err        error
}

func (m *mockPublishClient) next() (string, int32, string, error) {
	if m.currentCall >= len(m.uploadResponses) {
		return "", 0, "", status.Error(codes.Internal, "unexpected call")
	}
	resp := m.uploadResponses[m.currentCall]
	m.currentCall++
	return resp.status, resp.statusCode, resp.message, resp.err
}

func (m *mockPublishClient) uploadRecords(_ context.Context, req *ingest.UploadRecordsRequest) (string, int32, string, error) {
	m.requests = append(m.requests, proto.Clone(req).(*ingest.UploadRecordsRequest))
	return m.next()
}

func (m *mockPublishClient) uploadExcelMethod(_ context.Context, data []byte, employeeID string, _ map[string]string) (string, int32, string, error) {
	m.legacyCalls++
	m.legacyKeys = append(m.legacyKeys, employeeID)
	m.legacyData = append(m.legacyData, append([]byte(nil), data...))
	return m.next()
}

// writeJSONLogs writes small Zeek JSON logs and returns their paths.
func writeJSONLogs(t *testing.T) LogFiles {
	t.Helper()
	dir := t.TempDir()
	files := LogFiles{
		ConnPath: filepath.Join(dir, "conn.xlsx"),
		DNSPath:  filepath.Join(dir, "dns.xlsx"),
	}
	require.NoError(t, os.WriteFile(files.ConnPath, []byte(
		`{"ts":1.0,"uid":"C1","id.orig_h":"10.0.0.1","id.orig_p":5000,"id.resp_h":"10.0.0.2","id.resp_p":443,"proto":"tcp"}`+"\n"+
			`{"ts":2.0,"uid":"C2","id.orig_h":"10.0.0.1","id.orig_p":5001,"id.resp_h":"10.0.0.2","id.resp_p":53,"proto":"udp"}`+"\n"), 0o600))
	require.NoError(t, os.WriteFile(files.DNSPath, []byte(
		`{"ts":2.0,"uid":"C2","id.orig_h":"10.0.0.1","id.orig_p":5001,"id.resp_h":"10.0.0.2","id.resp_p":53,"proto":"udp","query":"example.com"}`+"\n"), 0o600))
	return files
}

// decodeRecords inflates and decodes a request's records, as the Subscriber does.
func decodeRecords(t *testing.T, req *ingest.UploadRecordsRequest) *ingest.RecordBatch {
	t.Helper()
	r, err := zlib.NewReader(bytes.NewReader(req.Records))
	require.NoError(t, err)
	raw, err := io.ReadAll(r)
	require.NoError(t, err)
	var batch ingest.RecordBatch
	require.NoError(t, proto.Unmarshal(raw, &batch))
	return &batch
}

func TestNewLogUploaderCACertFile(t *testing.T) {
	tests := []struct {
		name       string
		certFile   func(t *testing.T) string
		wantErr    bool
		errContain string
	}{
		{
			name: "empty cert file uses system trust store",
			certFile: func(t *testing.T) string {
				return ""
			},
		},
		{
			name: "valid cert file succeeds",
			certFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "ca.pem")
				require.NoError(t, os.WriteFile(path, generateTestCACertPEM(t), 0644))
				return path
			},
		},
		{
			name: "missing cert file errors",
			certFile: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.pem")
			},
			wantErr:    true,
			errContain: "failed to read CA certificate file",
		},
		{
			name: "invalid cert file errors",
			certFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "ca.pem")
				require.NoError(t, os.WriteFile(path, []byte("not a PEM certificate"), 0644))
				return path
			},
			wantErr:    true,
			errContain: "failed to parse CA certificate file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uploader, err := NewLogUploader("api.example.test:443", "test-key", "Test-Network-01", "any", 25, t.TempDir(), 24, tt.certFile(t))
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContain)
				assert.Nil(t, uploader)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, uploader)
		})
	}
}

func generateTestCACertPEM(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// TestLogUploader_UploadLogs verifies UploadLogs for a successful upload, a retry that then
// succeeds, and retries that all fail.
func TestLogUploader_UploadLogs(t *testing.T) {
	unavailable := uploadResponse{err: status.Error(codes.Unavailable, "server unavailable")}
	ok := uploadResponse{status: "success", statusCode: 200, message: "ok"}
	tests := []struct {
		name            string
		uploadResponses []uploadResponse
		wantErr         bool
		calls           int
	}{
		{name: "successful upload", uploadResponses: []uploadResponse{ok}, calls: 1},
		{name: "retry success", uploadResponses: []uploadResponse{unavailable, ok}, calls: 2},
		{name: "all retries fail", uploadResponses: []uploadResponse{unavailable, unavailable, unavailable}, wantErr: true, calls: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPublishClient{uploadResponses: tt.uploadResponses}
			uploader := &LogUploader{
				client:     mock,
				apiKey:     "test-key",
				networkID:  "Test-Network-01",
				retryCount: 3,
				retryDelay: time.Millisecond,
			}

			err := uploader.UploadLogs(context.Background(), writeJSONLogs(t))

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.calls, mock.currentCall)
			assert.Zero(t, mock.legacyCalls, "new uploads never use uploadExcelMethod")
		})
	}
}

// The request carries the envelope the Publisher checks, and the records decode back.
func TestUploadLogs_SendsTypedEnvelope(t *testing.T) {
	mock := &mockPublishClient{uploadResponses: []uploadResponse{{status: "success", statusCode: 200}}}
	uploader := &LogUploader{client: mock, apiKey: "test-key", networkID: "Test-Network-01", retryCount: 1}

	require.NoError(t, uploader.UploadLogs(context.Background(), writeJSONLogs(t)))

	require.Len(t, mock.requests, 1)
	req := mock.requests[0]
	assert.Equal(t, "test-key", req.ApiKey)
	assert.EqualValues(t, 1, req.SchemaVersion)
	assert.Equal(t, ingest.Compression_COMPRESSION_ZLIB, req.Compression)
	assert.NotEmpty(t, req.SensorVersion)
	assert.Equal(t, req.Metadata["sensor_version"], req.SensorVersion)
	assert.Equal(t, "Test-Network-01", req.Metadata["network_id"])
	assert.EqualValues(t, 2, req.Counts.Conn)
	assert.EqualValues(t, 1, req.Counts.Dns)

	batch := decodeRecords(t, req)
	require.Len(t, batch.Conn, 2)
	assert.Equal(t, "10.0.0.1", batch.Conn[0].OrigH)
	assert.Equal(t, "example.com", batch.Dns[0].GetQuery())
}

// Logs larger than max_payload_size_mb go up in several requests, every record once.
func TestUploadLogs_SplitsIntoBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn.xlsx")
	pad := strings.Repeat("x", 60*1024)
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, fmt.Sprintf(`{"ts":%d.0,"uid":"C%d","history":"%s"}`, i, i, pad))
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	var responses []uploadResponse
	for i := 0; i < 10; i++ {
		responses = append(responses, uploadResponse{status: "success", statusCode: 200})
	}
	mock := &mockPublishClient{uploadResponses: responses}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 1, maxPayloadSizeMB: 1}

	require.NoError(t, uploader.UploadLogs(context.Background(), LogFiles{ConnPath: path}))

	require.Greater(t, len(mock.requests), 1)
	total := 0
	for _, req := range mock.requests {
		total += len(decodeRecords(t, req).Conn)
		assert.LessOrEqual(t, int(req.Counts.Conn), 40)
	}
	assert.Equal(t, 40, total)
}

func TestUploadLogs_NoRecordsUploadsNothing(t *testing.T) {
	mock := &mockPublishClient{}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 1}

	require.NoError(t, uploader.UploadLogs(context.Background(), LogFiles{ConnPath: filepath.Join(t.TempDir(), "missing.xlsx")}))
	assert.Zero(t, mock.currentCall)
}

// A log that cannot be read is an error, not an empty upload.
func TestUploadLogs_ReadError(t *testing.T) {
	mock := &mockPublishClient{}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 1}

	err := uploader.UploadLogs(context.Background(), LogFiles{ConnPath: t.TempDir()}) // a directory, not a file
	assert.Error(t, err)
	assert.Zero(t, mock.currentCall)
}

// An unreadable record is skipped and the rest are uploaded (internal/records).
func TestUploadLogs_UnreadableRecordIsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn.xlsx")
	require.NoError(t, os.WriteFile(path, []byte(`{"ts":1.0,"uid":"C1"}`+"\nnot a record\n"+`{"ts":2.0,"uid":"C2"}`+"\n"), 0o600))
	mock := &mockPublishClient{uploadResponses: []uploadResponse{{status: "success", statusCode: 200}}}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 1}

	require.NoError(t, uploader.UploadLogs(context.Background(), LogFiles{ConnPath: path}))
	require.Len(t, mock.requests, 1)
	assert.EqualValues(t, 2, mock.requests[0].Counts.Conn)
}

// A log where nothing decodes (Zeek writing tab-separated logs, say) is an error, not a quiet
// success with nothing uploaded.
func TestUploadLogs_LogWithNoReadableRecordFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn.xlsx")
	require.NoError(t, os.WriteFile(path, []byte("#separator \\x09\n#fields\tts\tuid\n1.0\tC1\n"), 0o600))
	mock := &mockPublishClient{}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 1}

	err := uploader.UploadLogs(context.Background(), LogFiles{ConnPath: path})
	require.ErrorContains(t, err, "none of its 3 record(s)")
	assert.Zero(t, mock.currentCall)
}

// writeBatchedLog writes n conn records of about 60 KB each, so max_payload_size_mb 1 makes
// batches of 17.
func writeBatchedLog(t *testing.T, n int) string {
	t.Helper()
	pad := strings.Repeat("x", 60*1024)
	var lines []string
	for i := 0; i < n; i++ {
		lines = append(lines, fmt.Sprintf(`{"ts":%d.0,"uid":"C%d","history":"%s"}`, i, i, pad))
	}
	path := filepath.Join(t.TempDir(), "conn.xlsx")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	return path
}

// Once a batch fails every retry, the rest of the window is buffered without trying, so an
// outage does not hold the worker for a full set of retries per batch.
func TestUploadLogs_OutageBuffersRemainingBatchesWithoutTrying(t *testing.T) {
	unavailable := uploadResponse{err: status.Error(codes.Unavailable, "down")}
	mock := &mockPublishClient{uploadResponses: []uploadResponse{unavailable, unavailable, unavailable}}
	bufDir := filepath.Join(t.TempDir(), "buffer")
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 3,
		retryDelay: time.Millisecond, maxPayloadSizeMB: 1, bufferDir: bufDir}

	err := uploader.UploadLogs(context.Background(), LogFiles{ConnPath: writeBatchedLog(t, 40)})

	require.ErrorIs(t, err, errRetriesExhausted)
	assert.Equal(t, 3, mock.currentCall, "only the first batch is tried")
	entries, readErr := os.ReadDir(bufDir)
	require.NoError(t, readErr)
	assert.Len(t, entries, 3, "every batch is buffered")
}

// A Publisher without uploadRecords is not retried: the batch is buffered on the first attempt
// and the rest of the window with it.
func TestUploadLogs_PublisherWithoutUploadRecordsBuffersAtOnce(t *testing.T) {
	mock := &mockPublishClient{uploadResponses: []uploadResponse{{err: status.Error(codes.Unimplemented, "unknown method uploadRecords")}}}
	bufDir := filepath.Join(t.TempDir(), "buffer")
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 3,
		retryDelay: time.Hour, maxPayloadSizeMB: 1, bufferDir: bufDir}

	start := time.Now()
	err := uploader.UploadLogs(context.Background(), LogFiles{ConnPath: writeBatchedLog(t, 40)})

	require.ErrorIs(t, err, errRetriesExhausted)
	assert.Less(t, time.Since(start), 5*time.Second, "no retry wait")
	assert.Equal(t, 1, mock.currentCall)
	entries, readErr := os.ReadDir(bufDir)
	require.NoError(t, readErr)
	assert.Len(t, entries, 3)
}

// A refusal on a later batch is reported too, not only the first failure.
func TestUploadLogs_ReportsEveryFailedBatch(t *testing.T) {
	mock := &mockPublishClient{uploadResponses: []uploadResponse{
		{status: "success", statusCode: 200},
		{status: "error", statusCode: 400, message: "Invalid counts"},
		{status: "success", statusCode: 200},
	}}
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 3, maxPayloadSizeMB: 1}

	err := uploader.UploadLogs(context.Background(), LogFiles{ConnPath: writeBatchedLog(t, 40)})

	require.ErrorIs(t, err, errUploadRefused)
	assert.ErrorContains(t, err, "batch 2")
	assert.Equal(t, 3, mock.currentCall, "batch 3 is still sent")
}

func TestUploadLogs_UploadNon200(t *testing.T) {
	mock := &mockPublishClient{
		uploadResponses: []uploadResponse{{status: "fail", statusCode: 500, message: "server error"}},
	}
	uploader := &LogUploader{client: mock, apiKey: "test-key", networkID: "Test-Network-01", retryCount: 1, retryDelay: time.Millisecond}
	assert.Error(t, uploader.UploadLogs(context.Background(), writeJSONLogs(t)))
}

// A 400 means the Publisher refused the request itself, so it is neither retried nor buffered.
func TestUploadLogs_400NotRetriedOrBuffered(t *testing.T) {
	mock := &mockPublishClient{
		uploadResponses: []uploadResponse{{status: "error", statusCode: 400, message: "Unsupported schemaVersion 1; supported: 2"}},
	}
	bufDir := filepath.Join(t.TempDir(), "buffer")
	uploader := &LogUploader{client: mock, apiKey: "k", networkID: "Test-Network-01", retryCount: 3, retryDelay: time.Millisecond, bufferDir: bufDir}

	err := uploader.UploadLogs(context.Background(), writeJSONLogs(t))

	require.ErrorIs(t, err, errUploadRefused)
	assert.Equal(t, 1, mock.currentCall)
	assert.NoDirExists(t, bufDir, "a refused upload must not be buffered")
}

// TestUploadLogs_ContextCancelled cancels before upload and expects an error from UploadLogs.
func TestUploadLogs_ContextCancelled(t *testing.T) {
	mock := &mockPublishClient{uploadResponses: []uploadResponse{{status: "success", statusCode: 200, message: "ok"}}}
	uploader := &LogUploader{client: mock, apiKey: "test-key", networkID: "Test-Network-01", retryCount: 1, retryDelay: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Error(t, uploader.UploadLogs(ctx, writeJSONLogs(t)))
}

// TestUploadLogs_410Gone simulates the API returning 410 Gone and expects ErrAPIGone.
func TestUploadLogs_410Gone(t *testing.T) {
	mock := &mockPublishClient{uploadResponses: []uploadResponse{{status: "gone", statusCode: 410, message: "gone"}}}
	uploader := &LogUploader{client: mock, apiKey: "test-key", networkID: "Test-Network-01", retryCount: 1, retryDelay: time.Millisecond}
	err := uploader.UploadLogs(context.Background(), writeJSONLogs(t))
	if !errors.Is(err, ErrAPIGone) {
		t.Fatalf("expected error to be ErrAPIGone, got: %v", err)
	}
}

func TestBatchBytes(t *testing.T) {
	for mb, want := range map[int64]int{0: 25 << 20, 25: 25 << 20, 96: 96 << 20, 500: maxBatchBytes} {
		assert.Equal(t, want, (&LogUploader{maxPayloadSizeMB: mb}).batchBytes(), "max_payload_size_mb %d", mb)
	}
}
