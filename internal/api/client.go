package api

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api/ingest"
	pb "EnigmaNetz/Enigma-Go-Sensor/internal/api/publish"
	"EnigmaNetz/Enigma-Go-Sensor/internal/metadata"
	"EnigmaNetz/Enigma-Go-Sensor/internal/records"
)

// grpcClient defines the interface for gRPC operations
type grpcClient interface {
	// uploadRecords sends typed records through SensorIngest.uploadRecords (B1CF-2108).
	uploadRecords(ctx context.Context, req *ingest.UploadRecordsRequest) (string, int32, string, error)
	// uploadExcelMethod is the old Zeek-log upload, used only to flush payloads an older sensor
	// version buffered before an upgrade.
	uploadExcelMethod(ctx context.Context, data []byte, employeeId string, metadata map[string]string) (string, int32, string, error)
}

const (
	// defaultUploadTimeout bounds one upload RPC. It is generous because a
	// payload of up to max_payload_size_mb of logs (compressed on the wire) over
	// a slow customer uplink can take minutes; its job is to free a worker stuck
	// on a hung connection, not to police slow ones. It is under Cloud Run's
	// 300 s request timeout so the client's deadline, not the server's, fires.
	defaultUploadTimeout = 4*time.Minute + 30*time.Second

	// Keepalive pings only while an upload is in flight (PermitWithoutStream is
	// false), so a half-open connection fails the RPC instead of hanging it.
	keepaliveTime    = time.Minute
	keepaliveTimeout = 20 * time.Second

	// bufferTmpSuffix marks a buffered payload still being written; flushBuffer
	// skips it so it never uploads half a file.
	bufferTmpSuffix = ".tmp"

	// bufferRecordsExt marks a buffered UploadRecordsRequest, saved without its API key.
	// bufferLegacyExt marks an old Zeek-log payload buffered by a sensor version before typed
	// uploads; it is still flushed through uploadExcelMethod after an upgrade.
	bufferRecordsExt = ".rec"
	bufferLegacyExt  = ".bin"

	// maxRecordsPerUpload is the Publisher's limit (MAX_RECORDS_PER_UPLOAD in
	// Enigma-Publisher's record-envelope.ts); it refuses a larger upload with a 400.
	maxRecordsPerUpload = 1_000_000

	// maxBatchBytes caps one batch's uncompressed size whatever max_payload_size_mb says. The
	// Subscriber drops a batch that inflates past 128 MiB, and the Publisher refuses compressed
	// records over 99 MiB.
	maxBatchBytes = 96 * 1024 * 1024

	// defaultPayloadSizeMB applies when max_payload_size_mb is unset (config validation sets 25).
	defaultPayloadSizeMB = 25
)

// errUploadRefused marks a 400 from the Publisher: the request itself is invalid (for example
// a schema version it does not accept), so retrying or buffering it can never succeed.
var errUploadRefused = errors.New("upload refused by the Publisher")

// errRetriesExhausted marks a batch that failed every retry and was buffered.
var errRetriesExhausted = errors.New("upload failed every retry")

// LogUploader handles uploading logs to the gRPC server
type LogUploader struct {
	client           grpcClient
	apiKey           string
	networkID        string
	captureInterface string
	retryCount       int
	retryDelay       time.Duration // base delay; doubles after each failed attempt, with jitter
	uploadTimeout    time.Duration // per-RPC deadline; 0 means defaultUploadTimeout
	maxPayloadSizeMB int64         // maximum uncompressed batch size before splitting
	bufferDir        string
	bufferMaxAge     time.Duration
	// flushMu lets one worker at a time flush the buffer directory, so a
	// buffered payload is never read and uploaded by two workers at once.
	flushMu sync.Mutex
}

// LogFiles contains paths to the log files to upload
type LogFiles struct {
	DNSPath    string
	ConnPath   string
	DHCPPath   string
	JA3JA4Path string
	JA4SPath   string
}

// ErrAPIGone is returned when the API responds with HTTP 410 (Gone), indicating the sensor should stop.
var ErrAPIGone = errors.New("API returned 410 Gone: sensor should stop sending data and terminate")

// grpcClientImpl implements the grpcClient interface
type grpcClientImpl struct {
	client pb.PublishServiceClient
	ingest ingest.SensorIngestClient
}

// NewLogUploader creates a new log uploader instance
func NewLogUploader(serverAddr string, apiKey string, networkID string, captureInterface string, maxPayloadSizeMB int64, bufferDir string, bufferMaxAgeHours int, caCertFile string) (*LogUploader, error) {
	var opts []grpc.DialOption

	host := serverAddr
	if idx := strings.LastIndex(serverAddr, ":"); idx >= 0 {
		host = serverAddr[:idx]
	}
	var creds credentials.TransportCredentials
	if caCertFile == "" {
		creds = credentials.NewClientTLSFromCert(nil, host)
	} else {
		pem, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file %s: %w", caCertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("failed to parse CA certificate file %s", caCertFile)
		}
		creds = credentials.NewClientTLSFromCert(pool, host)
	}
	opts = append(opts, grpc.WithTransportCredentials(creds))

	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:    keepaliveTime,
		Timeout: keepaliveTimeout,
	}))
	opts = append(opts, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`))

	// NewClient does not connect until the first RPC, as grpc.Dial without
	// WithBlock did before. Unlike Dial, it resolves serverAddr through DNS
	// itself, which round_robin above expects.
	conn, err := grpc.NewClient(serverAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return &LogUploader{
		client:           &grpcClientImpl{client: pb.NewPublishServiceClient(conn), ingest: ingest.NewSensorIngestClient(conn)},
		apiKey:           apiKey,
		networkID:        networkID,
		captureInterface: captureInterface,
		retryCount:       3,
		retryDelay:       5 * time.Second,
		maxPayloadSizeMB: maxPayloadSizeMB,
		bufferDir:        bufferDir,
		bufferMaxAge:     time.Duration(bufferMaxAgeHours) * time.Hour,
	}, nil
}

func (c *grpcClientImpl) uploadExcelMethod(ctx context.Context, data []byte, employeeId string, metadata map[string]string) (string, int32, string, error) {
	req := &pb.UploadExcelRequest{
		Data:       data,
		EmployeeId: employeeId,
		Metadata:   metadata,
	}

	// Ensure the message implements proto.Message
	if _, ok := interface{}(req).(proto.Message); !ok {
		return "", 0, "", fmt.Errorf("request does not implement proto.Message")
	}

	resp, err := c.client.UploadExcelMethod(ctx, req)
	if err != nil {
		return "", 0, "", fmt.Errorf("gRPC call failed: %w", err)
	}

	return resp.Status, resp.StatusCode, resp.Message, nil
}

func (c *grpcClientImpl) uploadRecords(ctx context.Context, req *ingest.UploadRecordsRequest) (string, int32, string, error) {
	resp, err := c.ingest.UploadRecords(ctx, req)
	if err != nil {
		return "", 0, "", fmt.Errorf("gRPC call failed: %w", err)
	}
	return resp.Status, resp.StatusCode, resp.Message, nil
}

// UploadLogs maps the Zeek JSON logs into typed records and uploads them through
// uploadRecords, split into batches no larger than max_payload_size_mb uncompressed. A batch is
// retried and then buffered. Once one batch has failed every retry, the Publisher is treated as
// down for the rest of the window: the remaining batches are buffered without trying, so an
// outage does not hold the worker for a full set of retries per batch. A failure or
// cancellation part way through loses none of the remaining batches. Every failed batch is
// logged and returned. Logs with no records are not uploaded.
func (u *LogUploader) UploadLogs(ctx context.Context, files LogFiles) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Best-effort flush of any buffered payloads first. A 410 during the flush
	// means the key is revoked, so there is no point sending this payload either.
	if err := u.flushBuffer(ctx); errors.Is(err, ErrAPIGone) {
		return err
	}

	paths := records.LogPaths{
		Conn:   files.ConnPath,
		DNS:    files.DNSPath,
		DHCP:   files.DHCPPath,
		JA3JA4: files.JA3JA4Path,
		JA4S:   files.JA4SPath,
	}
	limits := records.Limits{MaxBytes: u.batchBytes(), MaxRecords: maxRecordsPerUpload}

	batches := 0
	publisherDown := false
	var failures []error
	err := records.Read(paths, limits, func(b records.Batch) error {
		batches++
		var err error
		if publisherDown {
			if err = u.bufferRecords(u.newRecordsRequest(b)); err == nil {
				err = errors.New("buffered without trying: an earlier batch failed every retry")
			}
		} else {
			err = u.uploadBatch(ctx, b)
		}
		if err == nil {
			return nil
		}
		// A 410 is final for every remaining batch too
		if errors.Is(err, ErrAPIGone) {
			return err
		}
		if errors.Is(err, errRetriesExhausted) {
			publisherDown = true
		}
		err = fmt.Errorf("batch %d (%d records): %w", batches, b.Total(), err)
		log.Printf("[upload] %v", err)
		failures = append(failures, err)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to upload records: %w", err)
	}
	if batches == 0 {
		log.Printf("[upload] No records in this capture window; nothing to upload")
	}
	return errors.Join(failures...)
}

// batchBytes is the uncompressed size limit for one batch.
func (u *LogUploader) batchBytes() int {
	mb := u.maxPayloadSizeMB
	if mb <= 0 {
		mb = defaultPayloadSizeMB
	}
	if mb*1024*1024 > maxBatchBytes {
		return maxBatchBytes
	}
	return int(mb * 1024 * 1024)
}

// newRecordsRequest builds the request for one batch, without the API key: the key is added
// only for the RPC, so a buffered request never holds it on disk.
func (u *LogUploader) newRecordsRequest(b records.Batch) *ingest.UploadRecordsRequest {
	md := metadata.GenerateMetadata(u.networkID, u.captureInterface)
	return &ingest.UploadRecordsRequest{
		SchemaVersion: records.SchemaVersion,
		SensorVersion: md["sensor_version"],
		Counts:        b.Counts,
		Compression:   ingest.Compression_COMPRESSION_ZLIB,
		Metadata:      md,
		Records:       b.Records,
	}
}

// uploadBatch uploads one batch with retries, and buffers it when every attempt fails or the
// upload is cancelled. A 410 or a 400 is final: neither is retried nor buffered.
func (u *LogUploader) uploadBatch(ctx context.Context, b records.Batch) error {
	req := u.newRecordsRequest(b)
	log.Printf("[upload] Sending %d records (%d bytes compressed) with metadata: %+v", b.Total(), len(b.Records), req.Metadata)

	var lastErr error
	for i := 0; i < u.retryCount; i++ {
		if i > 0 {
			if err := u.waitBeforeRetry(ctx, i); err != nil {
				return u.bufferCancelled(req, err)
			}
		}
		if ctx.Err() != nil {
			return u.bufferCancelled(req, ctx.Err())
		}
		err := u.sendRecords(ctx, req)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrAPIGone) || errors.Is(err, errUploadRefused) {
			return err
		}
		if ctx.Err() != nil {
			return u.bufferCancelled(req, ctx.Err())
		}
		lastErr = err
		// A Publisher without uploadRecords will not have it on the next attempt either
		if status.Code(err) == codes.Unimplemented {
			break
		}
	}

	// If we reach here, upload failed after retries. Buffer the payload for later. Either way
	// the batch counts as exhausted, so the rest of the window is not retried batch by batch.
	if err := u.bufferRecords(req); err != nil {
		return fmt.Errorf("%w and buffering failed too: %v; upload error: %w", errRetriesExhausted, err, lastErr)
	}
	return fmt.Errorf("%w (payload buffered for retry): %w", errRetriesExhausted, lastErr)
}

// bufferCancelled saves a request whose upload was interrupted by cancellation,
// so shutting down does not lose it. Writing to local disk needs no context.
func (u *LogUploader) bufferCancelled(req *ingest.UploadRecordsRequest, ctxErr error) error {
	if err := u.bufferRecords(req); err != nil {
		return fmt.Errorf("upload cancelled and failed to buffer payload: %v: %w", err, ctxErr)
	}
	return fmt.Errorf("upload cancelled; payload buffered for retry: %w", ctxErr)
}

// retryBackoff is the wait before retry number retry (1 for the first retry):
// retryDelay doubled per earlier retry, then jittered to between half and all
// of that, so workers that failed together do not retry together.
func (u *LogUploader) retryBackoff(retry int) time.Duration {
	d := u.retryDelay << (retry - 1)
	if d <= 0 {
		return 0
	}
	return d/2 + rand.N(d/2+1)
}

// waitBeforeRetry sleeps for the backoff before retry number retry, returning
// early with ctx's error if ctx is cancelled.
func (u *LogUploader) waitBeforeRetry(ctx context.Context, retry int) error {
	t := time.NewTimer(u.retryBackoff(retry))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// rpcContext bounds one upload RPC.
func (u *LogUploader) rpcContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := u.uploadTimeout
	if timeout <= 0 {
		timeout = defaultUploadTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

// sendRecords sends one UploadRecordsRequest, adding the API key for the call only.
func (u *LogUploader) sendRecords(ctx context.Context, req *ingest.UploadRecordsRequest) error {
	rpcCtx, cancel := u.rpcContext(ctx)
	defer cancel()

	req.ApiKey = u.apiKey
	_, statusCode, message, err := u.client.uploadRecords(rpcCtx, req)
	req.ApiKey = ""
	if err != nil {
		// An un-upgraded Publisher (on-prem in particular) has no uploadRecords. Say so plainly:
		// the batches are buffered and would otherwise age out without an obvious cause.
		if status.Code(err) == codes.Unimplemented {
			log.Printf("[upload] The Publisher does not support uploadRecords; it needs the B1CF-2107 upgrade. Batches are buffered until it has it or they age out.")
		}
		return fmt.Errorf("gRPC call failed: %w", err)
	}
	return statusError(statusCode, message)
}

// statusError maps the statusCode in a Publisher response to an error.
func statusError(statusCode int32, message string) error {
	switch statusCode {
	case 200:
		return nil
	case 410:
		return fmt.Errorf("API returned 410 Gone: sensor should stop sending data and terminate: %w", ErrAPIGone)
	case 400:
		return fmt.Errorf("%w: %s (code: 400)", errUploadRefused, message)
	default:
		return fmt.Errorf("upload failed: %s (code: %d)", message, statusCode)
	}
}

// uploadLegacy sends an old Zeek-log payload buffered by a sensor version before typed uploads.
func (u *LogUploader) uploadLegacy(ctx context.Context, data []byte) error {
	metadataMap := metadata.GenerateMetadata(u.networkID, u.captureInterface)
	log.Printf("[upload] Sending buffered legacy payload with metadata: %+v", metadataMap)

	rpcCtx, cancel := u.rpcContext(ctx)
	defer cancel()

	_, statusCode, message, err := u.client.uploadExcelMethod(rpcCtx, data, u.apiKey, metadataMap)
	if err != nil {
		return fmt.Errorf("gRPC call failed: %w", err)
	}
	return statusError(statusCode, message)
}

// bufferRecords writes a request, without its API key, to disk for later retry.
func (u *LogUploader) bufferRecords(req *ingest.UploadRecordsRequest) error {
	req.ApiKey = ""
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to encode buffered request: %w", err)
	}
	return u.bufferSave(data, bufferRecordsExt)
}

// bufferSave writes a payload to disk for later retry, named for its time so the oldest is
// flushed first and with ext marking its format.
func (u *LogUploader) bufferSave(data []byte, ext string) error {
	if u.bufferDir == "" {
		return nil
	}
	if err := os.MkdirAll(u.bufferDir, 0o755); err != nil {
		return fmt.Errorf("failed to create buffer dir: %w", err)
	}
	// Name encoded with timestamp for ordering
	ts := time.Now().UTC().Format("20060102T150405Z")
	// Include monotonic nsec to avoid collisions
	fname := fmt.Sprintf("buf_%s_%d%s", ts, time.Now().UTC().UnixNano(), ext)
	path := filepath.Join(u.bufferDir, fname)
	// Write under a temporary name and rename, so a concurrent flush never
	// sees a partly written payload.
	tmp := path + bufferTmpSuffix
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to write buffer file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to finalize buffer file: %w", err)
	}
	return nil
}

// sendBuffered uploads one buffered file in the format its extension names.
func (u *LogUploader) sendBuffered(ctx context.Context, name string, data []byte) error {
	if strings.HasSuffix(name, bufferRecordsExt) {
		var req ingest.UploadRecordsRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			return fmt.Errorf("%w: unreadable buffered request: %v", errUploadRefused, err)
		}
		return u.sendRecords(ctx, &req)
	}
	return u.uploadLegacy(ctx, data)
}

// isBufferedPayload reports whether name is a buffered payload this sensor can send. Anything
// else in the buffer directory is left alone, and purged only by age.
func isBufferedPayload(name string) bool {
	return strings.HasSuffix(name, bufferRecordsExt) || strings.HasSuffix(name, bufferLegacyExt)
}

// flushBuffer attempts to send buffered payloads oldest-first and purges old
// entries. If another worker is already flushing, it returns at once and leaves
// the buffer to that worker.
func (u *LogUploader) flushBuffer(ctx context.Context) error {
	if u.bufferDir == "" {
		return nil
	}
	if !u.flushMu.TryLock() {
		return nil
	}
	defer u.flushMu.Unlock()
	entries, err := os.ReadDir(u.bufferDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	now := time.Now()
	// Sort entries by name ascending (timestamp-leading names)
	// Simple insertion sort due to small expected counts
	for i := 1; i < len(entries); i++ {
		j := i
		for j > 0 && entries[j-1].Name() > entries[j].Name() {
			entries[j-1], entries[j] = entries[j], entries[j-1]
			j--
		}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(u.bufferDir, e.Name())
		info, statErr := os.Stat(full)
		if statErr != nil {
			continue
		}
		// Purge old files beyond retention, including a .tmp left by a crash
		// between write and rename
		if u.bufferMaxAge > 0 && info.ModTime().Add(u.bufferMaxAge).Before(now) {
			_ = os.Remove(full)
			continue
		}
		// A .tmp file is still being written (or was abandoned), and any other file is not
		// ours; never upload either
		if !isBufferedPayload(e.Name()) {
			continue
		}
		// Try upload
		data, readErr := os.ReadFile(full)
		if readErr != nil {
			// If unreadable, remove to avoid blocking
			_ = os.Remove(full)
			continue
		}
		if err := u.sendBuffered(ctx, e.Name(), data); err != nil {
			// A refused payload can never succeed; drop it and carry on
			if errors.Is(err, errUploadRefused) {
				log.Printf("[upload] Dropping buffered payload %s: %v", e.Name(), err)
				_ = os.Remove(full)
				continue
			}
			// Stop on first failure (likely still down); keep file
			log.Printf("[upload] Buffered payload %s not sent, kept for the next flush: %v", e.Name(), err)
			return err
		}
		// Success: remove file
		_ = os.Remove(full)
	}
	return nil
}
