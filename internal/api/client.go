package api

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	pb "EnigmaNetz/Enigma-Go-Sensor/internal/api/publish"
	"EnigmaNetz/Enigma-Go-Sensor/internal/metadata"
)

// grpcClient defines the interface for gRPC operations
type grpcClient interface {
	uploadExcelMethod(ctx context.Context, data []byte, employeeId string, metadata map[string]string) (string, int32, string, error)
}

// LogUploader handles uploading logs to the gRPC server
type LogUploader struct {
	client           grpcClient
	apiKey           string
	sensorID         string
	retryCount       int
	retryDelay       time.Duration
	compressFunc     func([]byte) ([]byte, error) // for DI/testing
	maxPayloadSizeMB int64                        // maximum payload size before chunking
	bufferDir        string
	bufferMaxAge     time.Duration
}

// LogFiles contains paths to the log files to upload
type LogFiles struct {
	DNSPath    string
	ConnPath   string
	DHCPPath   string
	JA3JA4Path string
	JA4SPath   string
}

// CombinedLogs represents the compressed log data
type CombinedLogs struct {
	DNS    string `json:"dns"`    // base64 encoded compressed data
	Conn   string `json:"conn"`   // base64 encoded compressed data
	JA3JA4 string `json:"ja3ja4"` // base64 encoded compressed data
	JA4S   string `json:"ja4s"`   // base64 encoded compressed data
	DHCP   string `json:"dhcp"`   // base64 encoded compressed data
}

// ErrAPIGone is returned when the API responds with HTTP 410 (Gone), indicating the sensor should stop.
var ErrAPIGone = errors.New("API returned 410 Gone: sensor should stop sending data and terminate")

// grpcClientImpl implements the grpcClient interface
type grpcClientImpl struct {
	client pb.PublishServiceClient
}

// NewLogUploader creates a new log uploader instance
func NewLogUploader(serverAddr string, apiKey string, sensorID string, maxPayloadSizeMB int64, bufferDir string, bufferMaxAgeHours int) (*LogUploader, error) {
	var opts []grpc.DialOption

	// Always use SSL credentials with system trust store
	host := serverAddr
	if idx := strings.LastIndex(serverAddr, ":"); idx >= 0 {
		host = serverAddr[:idx]
	}
	creds := credentials.NewClientTLSFromCert(nil, host)
	opts = append(opts, grpc.WithTransportCredentials(creds))

	// Add keepalive options
	opts = append(opts, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`))

	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %v", err)
	}

	return &LogUploader{
		client:           &grpcClientImpl{client: pb.NewPublishServiceClient(conn)},
		apiKey:           apiKey,
		sensorID:         sensorID,
		retryCount:       3,
		retryDelay:       5 * time.Second,
		compressFunc:     compressData,
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
		return "", 0, "", fmt.Errorf("gRPC call failed: %v", err)
	}

	return resp.Status, resp.StatusCode, resp.Message, nil
}

// UploadLogs uploads the DNS and connection logs to the server
func (u *LogUploader) UploadLogs(ctx context.Context, files LogFiles) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check if files need to be chunked
	totalSizeMB, err := u.calculateTotalFileSize(files)
	if err != nil {
		return fmt.Errorf("failed to calculate file size: %v", err)
	}

	if totalSizeMB > u.maxPayloadSizeMB {
		return u.uploadLogsChunked(ctx, files)
	}

	// Use existing upload path for smaller files
	return u.uploadLogsSingle(ctx, files)
}

// uploadLogsSingle uploads logs as a single payload (existing behavior)
func (u *LogUploader) uploadLogsSingle(ctx context.Context, files LogFiles) error {
	// Read and compress log files
	combinedData, err := u.prepareLogData(files)
	if err != nil {
		return fmt.Errorf("failed to prepare log data: %v", err)
	}

	// Best-effort flush of any buffered payloads first
	_ = u.flushBuffer(ctx)

	// Upload with retries
	var lastErr error
	for i := 0; i < u.retryCount; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := u.upload(ctx, combinedData); err != nil {
			lastErr = err
			time.Sleep(u.retryDelay)
			continue
		}
		return nil
	}

	// If we reach here, upload failed after retries. Buffer the payload for later.
	if err := u.bufferSave(combinedData); err != nil {
		return fmt.Errorf("failed to upload after %d retries and also failed to buffer payload: %v; original error: %v", u.retryCount, err, lastErr)
	}
	return fmt.Errorf("failed to upload after %d retries: %w (payload buffered for retry)", u.retryCount, lastErr)
}

// uploadLogsChunked splits files and uploads each chunk separately
func (u *LogUploader) uploadLogsChunked(ctx context.Context, files LogFiles) error {
	// Calculate chunk size (90% of max to leave room for compression variance)
	chunkSizeBytes := (u.maxPayloadSizeMB * 1024 * 1024 * 90) / 100

	// Split DNS file if present
	dnsChunks, err := splitCSVFile(files.DNSPath, chunkSizeBytes/5)
	if err != nil {
		return fmt.Errorf("failed to split DNS file: %v", err)
	}

	// Split connection file
	connChunks, err := splitCSVFile(files.ConnPath, chunkSizeBytes/5)
	if err != nil {
		return fmt.Errorf("failed to split connection file: %v", err)
	}

	// Split JA3JA4 file if present
	ja3ja4Chunks, err := splitCSVFile(files.JA3JA4Path, chunkSizeBytes/5)
	if err != nil {
		return fmt.Errorf("failed to split JA3JA4 file: %v", err)
	}

	// Split JA4S file if present
	ja4sChunks, err := splitCSVFile(files.JA4SPath, chunkSizeBytes/5)
	if err != nil {
		return fmt.Errorf("failed to split JA4S file: %v", err)
	}

	// Split DHCP file if present
	dhcpChunks, err := splitCSVFile(files.DHCPPath, chunkSizeBytes/5)
	if err != nil {
		return fmt.Errorf("failed to split DHCP file: %v", err)
	}

	// Determine maximum chunks needed
	maxChunks := len(connChunks)
	if len(dnsChunks) > maxChunks {
		maxChunks = len(dnsChunks)
	}
	if len(ja3ja4Chunks) > maxChunks {
		maxChunks = len(ja3ja4Chunks)
	}
	if len(ja4sChunks) > maxChunks {
		maxChunks = len(ja4sChunks)
	}
	if len(dhcpChunks) > maxChunks {
		maxChunks = len(dhcpChunks)
	}

	// Track temp files for cleanup
	var tempFiles []string
	defer func() {
		for _, file := range tempFiles {
			if file != files.DNSPath && file != files.ConnPath && file != files.JA3JA4Path && file != files.JA4SPath && file != files.DHCPPath {
				os.Remove(file)
			}
		}
	}()

	// Upload each chunk
	for i := 0; i < maxChunks; i++ {
		chunkFiles := LogFiles{}

		// Set DNS chunk path (or empty if no more chunks)
		if i < len(dnsChunks) && dnsChunks[i] != "" {
			chunkFiles.DNSPath = dnsChunks[i]
			if dnsChunks[i] != files.DNSPath {
				tempFiles = append(tempFiles, dnsChunks[i])
			}
		}

		// Set connection chunk path (or empty if no more chunks)
		if i < len(connChunks) && connChunks[i] != "" {
			chunkFiles.ConnPath = connChunks[i]
			if connChunks[i] != files.ConnPath {
				tempFiles = append(tempFiles, connChunks[i])
			}
		}

		// Set JA3JA4 chunk path (or empty if no more chunks)
		if i < len(ja3ja4Chunks) && ja3ja4Chunks[i] != "" {
			chunkFiles.JA3JA4Path = ja3ja4Chunks[i]
			if ja3ja4Chunks[i] != files.JA3JA4Path {
				tempFiles = append(tempFiles, ja3ja4Chunks[i])
			}
		}

		// Set JA4S chunk path (or empty if no more chunks)
		if i < len(ja4sChunks) && ja4sChunks[i] != "" {
			chunkFiles.JA4SPath = ja4sChunks[i]
			if ja4sChunks[i] != files.JA4SPath {
				tempFiles = append(tempFiles, ja4sChunks[i])
			}
		}

		// Set DHCP chunk path (or empty if no more chunks)
		if i < len(dhcpChunks) && dhcpChunks[i] != "" {
			chunkFiles.DHCPPath = dhcpChunks[i]
			if dhcpChunks[i] != files.DHCPPath {
				tempFiles = append(tempFiles, dhcpChunks[i])
			}
		}

		// Skip empty chunks
		if chunkFiles.DNSPath == "" && chunkFiles.ConnPath == "" && chunkFiles.JA3JA4Path == "" && chunkFiles.JA4SPath == "" && chunkFiles.DHCPPath == "" {
			continue
		}

		// Upload this chunk
		if err := u.uploadLogsSingle(ctx, chunkFiles); err != nil {
			return fmt.Errorf("failed to upload chunk %d: %v", i+1, err)
		}
	}

	return nil
}

// prepareLogData reads, compresses, and combines the log files
func (u *LogUploader) prepareLogData(files LogFiles) ([]byte, error) {
	// Read DNS log (allow missing)
	dnsData, err := os.ReadFile(files.DNSPath)
	if err != nil {
		if os.IsNotExist(err) {
			dnsData = []byte{} // treat missing DNS log as empty
		} else {
			return nil, fmt.Errorf("failed to read DNS log: %v", err)
		}
	}

	// Read connection log (required)
	connData, err := os.ReadFile(files.ConnPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read connection log: %v", err)
	}

	// Read JA3JA4 log (allow missing)
	ja3ja4Data, err := os.ReadFile(files.JA3JA4Path)
	if err != nil {
		if os.IsNotExist(err) {
			ja3ja4Data = []byte{} // treat missing JA3JA4 log as empty
		} else {
			return nil, fmt.Errorf("failed to read JA3JA4 log: %v", err)
		}
	}

	// Read JA4S log (allow missing)
	ja4sData, err := os.ReadFile(files.JA4SPath)
	if err != nil {
		if os.IsNotExist(err) {
			ja4sData = []byte{} // treat missing JA4S log as empty
		} else {
			return nil, fmt.Errorf("failed to read JA4S log: %v", err)
		}
	}

	// Read DHCP log (allow missing)
	dhcpData, err := os.ReadFile(files.DHCPPath)
	if err != nil {
		if os.IsNotExist(err) {
			dhcpData = []byte{} // treat missing DHCP log as empty
		} else {
			return nil, fmt.Errorf("failed to read DHCP log: %v", err)
		}
	}

	// Compress DNS data
	dnsCompressed, err := u.compressFunc(dnsData)
	if err != nil {
		return nil, fmt.Errorf("failed to compress DNS data: %v", err)
	}

	// Compress connection data
	connCompressed, err := u.compressFunc(connData)
	if err != nil {
		return nil, fmt.Errorf("failed to compress connection data: %v", err)
	}

	// Compress JA3JA4 data
	ja3ja4Compressed, err := u.compressFunc(ja3ja4Data)
	if err != nil {
		return nil, fmt.Errorf("failed to compress JA3JA4 data: %v", err)
	}

	// Compress JA4S data
	ja4sCompressed, err := u.compressFunc(ja4sData)
	if err != nil {
		return nil, fmt.Errorf("failed to compress JA4S data: %v", err)
	}

	// Compress DHCP data
	dhcpCompressed, err := u.compressFunc(dhcpData)
	if err != nil {
		return nil, fmt.Errorf("failed to compress DHCP data: %v", err)
	}

	// Combine into JSON structure
	combined := CombinedLogs{
		DNS:    base64.StdEncoding.EncodeToString(dnsCompressed),
		Conn:   base64.StdEncoding.EncodeToString(connCompressed),
		JA3JA4: base64.StdEncoding.EncodeToString(ja3ja4Compressed),
		JA4S:   base64.StdEncoding.EncodeToString(ja4sCompressed),
		DHCP:   base64.StdEncoding.EncodeToString(dhcpCompressed),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(combined)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal combined data: %v", err)
	}

	// Compress the combined JSON
	return u.compressFunc(jsonData)
}

// upload sends the compressed data to the server
func (u *LogUploader) upload(ctx context.Context, data []byte) error {
	// Generate metadata for the payload
	metadataMap := metadata.GenerateMetadata(u.sensorID)
	log.Printf("[upload] Sending metadata to API: %+v", metadataMap)

	_, statusCode, message, err := u.client.uploadExcelMethod(ctx, data, u.apiKey, metadataMap)
	if err != nil {
		return fmt.Errorf("gRPC call failed: %v", err)
	}

	if statusCode == 410 {
		return fmt.Errorf("API returned 410 Gone: sensor should stop sending data and terminate: %w", ErrAPIGone)
	}

	if statusCode != 200 {
		return fmt.Errorf("upload failed: %s (code: %d)", message, statusCode)
	}

	return nil
}

// bufferSave writes a compressed payload to disk for later retry
func (u *LogUploader) bufferSave(data []byte) error {
	if u.bufferDir == "" {
		return nil
	}
	if err := os.MkdirAll(u.bufferDir, 0o755); err != nil {
		return fmt.Errorf("failed to create buffer dir: %w", err)
	}
	// Name encoded with timestamp for ordering
	ts := time.Now().UTC().Format("20060102T150405Z")
	// Include monotonic nsec to avoid collisions
	fname := fmt.Sprintf("buf_%s_%d.bin", ts, time.Now().UTC().UnixNano())
	path := filepath.Join(u.bufferDir, fname)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write buffer file: %w", err)
	}
	return nil
}

// flushBuffer attempts to send buffered payloads oldest-first and purges old entries
func (u *LogUploader) flushBuffer(ctx context.Context) error {
	if u.bufferDir == "" {
		return nil
	}
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
		// Purge old files beyond retention
		if u.bufferMaxAge > 0 && info.ModTime().Add(u.bufferMaxAge).Before(now) {
			_ = os.Remove(full)
			continue
		}
		// Try upload
		data, readErr := os.ReadFile(full)
		if readErr != nil {
			// If unreadable, remove to avoid blocking
			_ = os.Remove(full)
			continue
		}
		if err := u.upload(ctx, data); err != nil {
			// Stop on first failure (likely still down); keep file
			return err
		}
		// Success: remove file
		_ = os.Remove(full)
	}
	return nil
}

// compressData compresses byte data using zlib
func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %v", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close compressor: %v", err)
	}

	return buf.Bytes(), nil
}

// calculateTotalFileSize calculates the total size of log files in MB
func (u *LogUploader) calculateTotalFileSize(files LogFiles) (int64, error) {
	var totalSize int64

	// Check DNS file size (optional)
	if files.DNSPath != "" {
		if stat, err := os.Stat(files.DNSPath); err == nil {
			totalSize += stat.Size()
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("failed to stat DNS file: %v", err)
		}
	}

	// Check conn file size (required)
	if stat, err := os.Stat(files.ConnPath); err != nil {
		return 0, fmt.Errorf("failed to stat connection file: %v", err)
	} else {
		totalSize += stat.Size()
	}

	// Check JA3JA4 file size (optional)
	if files.JA3JA4Path != "" {
		if stat, err := os.Stat(files.JA3JA4Path); err == nil {
			totalSize += stat.Size()
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("failed to stat JA3JA4 file: %v", err)
		}
	}

	// Check JA4S file size (optional)
	if files.JA4SPath != "" {
		if stat, err := os.Stat(files.JA4SPath); err == nil {
			totalSize += stat.Size()
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("failed to stat JA4S file: %v", err)
		}
	}

	// Check DHCP file size (optional)
	if files.DHCPPath != "" {
		if stat, err := os.Stat(files.DHCPPath); err == nil {
			totalSize += stat.Size()
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("failed to stat DHCP file: %v", err)
		}
	}

	// Convert to MB
	return totalSize / (1024 * 1024), nil
}

// splitCSVFile splits a CSV file into chunks of specified size
func splitCSVFile(filePath string, maxSizeBytes int64) ([]string, error) {
	if filePath == "" {
		return nil, nil // Skip empty files
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Skip missing files
		}
		return nil, fmt.Errorf("failed to open file %s: %v", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Read header
	if !scanner.Scan() {
		return []string{filePath}, nil // Return original file if empty
	}
	header := scanner.Text()

	var chunks []string
	var currentChunk []string
	var currentSize int64
	chunkNum := 1

	for scanner.Scan() {
		line := scanner.Text()
		lineSize := int64(len(line) + 1) // +1 for newline

		// Start new chunk if size exceeded
		if currentSize > 0 && currentSize+lineSize > maxSizeBytes {
			chunkPath, err := writeChunk(filePath, chunkNum, header, currentChunk)
			if err != nil {
				return nil, err
			}
			chunks = append(chunks, chunkPath)

			currentChunk = currentChunk[:0] // Reset slice
			currentSize = int64(len(header) + 1)
			chunkNum++
		}

		currentChunk = append(currentChunk, line)
		currentSize += lineSize
	}

	// Write final chunk if we have data
	if len(currentChunk) > 0 {
		chunkPath, err := writeChunk(filePath, chunkNum, header, currentChunk)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, chunkPath)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filePath, err)
	}

	// If no chunks were created, return original file
	if len(chunks) == 0 {
		return []string{filePath}, nil
	}

	return chunks, nil
}

// writeChunk writes a chunk of CSV data to a temporary file
func writeChunk(originalPath string, chunkNum int, header string, lines []string) (string, error) {
	dir := filepath.Dir(originalPath)
	base := filepath.Base(originalPath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	chunkPath := filepath.Join(dir, fmt.Sprintf("%s_chunk_%d%s", name, chunkNum, ext))

	file, err := os.OpenFile(chunkPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create chunk file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Write header
	if _, err := writer.WriteString(header + "\n"); err != nil {
		return "", fmt.Errorf("failed to write header: %v", err)
	}

	// Write lines
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return "", fmt.Errorf("failed to write line: %v", err)
		}
	}

	return chunkPath, writer.Flush()
}
