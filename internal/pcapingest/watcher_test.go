package pcapingest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
)

type mockProcessor struct {
	calls  int
	fail   bool
	result types.ProcessedData
}

func (m *mockProcessor) ProcessPCAP(pcapPath string, samplingPercentage float64) (types.ProcessedData, error) {
	m.calls++
	if m.fail {
		return types.ProcessedData{}, errors.New("process failed")
	}
	return m.result, nil
}

type mockUploader struct {
	calls   int
	fail    bool
	goneErr bool
}

func (m *mockUploader) UploadLogs(ctx context.Context, files api.LogFiles) error {
	m.calls++
	if m.goneErr {
		return api.ErrAPIGone
	}
	if m.fail {
		return errors.New("upload failed")
	}
	return nil
}

func newTestWatcher(t *testing.T, proc Processor, up Uploader) (*Watcher, string) {
	t.Helper()
	dir := t.TempDir()
	w := NewWatcher(WatcherConfig{
		WatchDir:          dir,
		PollInterval:      50 * time.Millisecond,
		FileStableSeconds: 0, // no wait in tests
		SamplingPct:       100,
	}, proc, up)
	return w, dir
}

func createTestPCAP(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("fake pcap data"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	return path
}

// createValidPCAP creates a minimal but valid PCAP file for testing
func createValidPCAP(t *testing.T, path string) {
	t.Helper()

	// PCAP global header (24 bytes)
	// magic_number: 0xa1b2c3d4 (microsecond resolution)
	// version_major: 2
	// version_minor: 4
	// thiszone: 0
	// sigfigs: 0
	// snaplen: 65535
	// network: 1 (Ethernet)
	header := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, // magic number (little-endian)
		0x02, 0x00, // version major
		0x04, 0x00, // version minor
		0x00, 0x00, 0x00, 0x00, // thiszone
		0x00, 0x00, 0x00, 0x00, // sigfigs
		0xff, 0xff, 0x00, 0x00, // snaplen
		0x01, 0x00, 0x00, 0x00, // network (Ethernet)
	}

	// Minimal Ethernet frame (14 bytes)
	// Destination MAC: 00:00:00:00:00:01
	// Source MAC: 00:00:00:00:00:02
	// EtherType: 0x0800 (IPv4)
	ethernetFrame := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst MAC
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // src MAC
		0x08, 0x00, // EtherType (IPv4)
	}

	// Packet record header (16 bytes)
	// ts_sec: 1234567890
	// ts_usec: 0
	// incl_len: 14 (size of ethernet frame)
	// orig_len: 14
	now := uint32(1234567890)
	packetHeader := []byte{
		byte(now), byte(now >> 8), byte(now >> 16), byte(now >> 24), // ts_sec
		0x00, 0x00, 0x00, 0x00, // ts_usec
		0x0e, 0x00, 0x00, 0x00, // incl_len (14)
		0x0e, 0x00, 0x00, 0x00, // orig_len (14)
	}

	// Combine all parts
	pcapData := append(header, packetHeader...)
	pcapData = append(pcapData, ethernetFrame...)

	if err := os.WriteFile(path, pcapData, 0644); err != nil {
		t.Fatalf("Failed to create valid PCAP file: %v", err)
	}
}

func TestWatcher_CreatesSubdirectories(t *testing.T) {
	proc := &mockProcessor{}
	up := &mockUploader{}
	w, dir := newTestWatcher(t, proc, up)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so Run exits after creating dirs

	_ = w.Run(ctx)

	for _, sub := range []string{"incoming", "processing", "processed", "failed"} {
		path := filepath.Join(dir, sub)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("Expected directory %s to exist: %v", sub, err)
		} else if !info.IsDir() {
			t.Errorf("Expected %s to be a directory", sub)
		}
	}
}

func TestWatcher_DetectsNewPCAP(t *testing.T) {
	proc := &mockProcessor{
		result: types.ProcessedData{
			ConnPath: "/tmp/conn.xlsx",
			DNSPath:  "/tmp/dns.xlsx",
		},
	}
	up := &mockUploader{}
	w, dir := newTestWatcher(t, proc, up)

	// Create subdirectories and place a file
	incomingDir := filepath.Join(dir, "incoming")
	os.MkdirAll(incomingDir, 0755)
	createTestPCAP(t, incomingDir, "test.pcap")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	// Wait for the file to be processed
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if proc.calls != 1 {
		t.Errorf("Expected 1 processor call, got %d", proc.calls)
	}
	if up.calls != 1 {
		t.Errorf("Expected 1 uploader call, got %d", up.calls)
	}
}

func TestWatcher_MoveToProcessed(t *testing.T) {
	proc := &mockProcessor{
		result: types.ProcessedData{
			ConnPath: "/tmp/conn.xlsx",
		},
	}
	up := &mockUploader{}
	w, dir := newTestWatcher(t, proc, up)

	incomingDir := filepath.Join(dir, "incoming")
	processedDir := filepath.Join(dir, "processed")
	os.MkdirAll(incomingDir, 0755)
	createTestPCAP(t, incomingDir, "test.pcap")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	// File should be in processed
	if _, err := os.Stat(filepath.Join(processedDir, "test.pcap")); err != nil {
		t.Errorf("Expected file in processed dir: %v", err)
	}
	// File should not be in incoming
	if _, err := os.Stat(filepath.Join(incomingDir, "test.pcap")); !os.IsNotExist(err) {
		t.Error("Expected file to be removed from incoming dir")
	}
}

func TestWatcher_MoveToFailed(t *testing.T) {
	proc := &mockProcessor{fail: true}
	up := &mockUploader{}
	w, dir := newTestWatcher(t, proc, up)

	incomingDir := filepath.Join(dir, "incoming")
	failedDir := filepath.Join(dir, "failed")
	os.MkdirAll(incomingDir, 0755)
	createTestPCAP(t, incomingDir, "bad.pcap")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	// File should be in failed
	if _, err := os.Stat(filepath.Join(failedDir, "bad.pcap")); err != nil {
		t.Errorf("Expected file in failed dir: %v", err)
	}
	if up.calls != 0 {
		t.Errorf("Expected 0 uploader calls on processing failure, got %d", up.calls)
	}
}

func TestWatcher_IgnoresNonPCAP(t *testing.T) {
	proc := &mockProcessor{}
	up := &mockUploader{}
	w, dir := newTestWatcher(t, proc, up)

	incomingDir := filepath.Join(dir, "incoming")
	os.MkdirAll(incomingDir, 0755)
	createTestPCAP(t, incomingDir, "readme.txt")
	createTestPCAP(t, incomingDir, "data.csv")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if proc.calls != 0 {
		t.Errorf("Expected 0 processor calls for non-PCAP files, got %d", proc.calls)
	}
}

func TestWatcher_ContextCancellation(t *testing.T) {
	proc := &mockProcessor{}
	up := &mockUploader{}
	w, _ := newTestWatcher(t, proc, up)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	// Cancel quickly
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Expected nil error on context cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watcher did not stop after context cancellation")
	}
}

func TestWatcher_EmptyDirectory(t *testing.T) {
	proc := &mockProcessor{}
	up := &mockUploader{}
	w, _ := newTestWatcher(t, proc, up)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	if proc.calls != 0 {
		t.Errorf("Expected 0 processor calls for empty dir, got %d", proc.calls)
	}
}

func TestWatcher_PcapngExtension(t *testing.T) {
	proc := &mockProcessor{
		result: types.ProcessedData{
			ConnPath: "/tmp/conn.xlsx",
		},
	}
	up := &mockUploader{}
	w, dir := newTestWatcher(t, proc, up)

	incomingDir := filepath.Join(dir, "incoming")
	os.MkdirAll(incomingDir, 0755)
	createTestPCAP(t, incomingDir, "capture.pcapng")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if proc.calls != 1 {
		t.Errorf("Expected 1 processor call for .pcapng file, got %d", proc.calls)
	}
}

func TestWatcher_APIGone(t *testing.T) {
	proc := &mockProcessor{
		result: types.ProcessedData{
			ConnPath: "/tmp/conn.xlsx",
			DNSPath:  "/tmp/dns.xlsx",
		},
	}
	up := &mockUploader{goneErr: true}
	w, dir := newTestWatcher(t, proc, up)

	incomingDir := filepath.Join(dir, "incoming")
	os.MkdirAll(incomingDir, 0755)
	createTestPCAP(t, incomingDir, "test.pcap")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, api.ErrAPIGone) {
			t.Errorf("Expected api.ErrAPIGone, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watcher did not return after API Gone error")
	}

	if proc.calls != 1 {
		t.Errorf("Expected 1 processor call, got %d", proc.calls)
	}
	if up.calls != 1 {
		t.Errorf("Expected 1 uploader call, got %d", up.calls)
	}
}

func TestIsPCAPFile(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"pcap lowercase", "test.pcap", true},
		{"pcap uppercase", "TEST.PCAP", true},
		{"pcapng lowercase", "test.pcapng", true},
		{"pcapng uppercase", "TEST.PCAPNG", true},
		{"txt file", "test.txt", false},
		{"csv file", "data.csv", false},
		{"no extension", "pcap", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPCAPFile(tt.input)
			if got != tt.expect {
				t.Errorf("isPCAPFile(%q) = %v, expected %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestWatcher_EndToEnd(t *testing.T) {
	// Create processor that returns valid ProcessedData
	proc := &mockProcessor{
		result: types.ProcessedData{
			ConnPath: "/tmp/conn.xlsx",
			DNSPath:  "/tmp/dns.xlsx",
		},
	}
	up := &mockUploader{}
	w, dir := newTestWatcher(t, proc, up)

	// Create subdirectories
	incomingDir := filepath.Join(dir, "incoming")
	processingDir := filepath.Join(dir, "processing")
	processedDir := filepath.Join(dir, "processed")
	failedDir := filepath.Join(dir, "failed")
	os.MkdirAll(incomingDir, 0755)
	os.MkdirAll(processingDir, 0755)
	os.MkdirAll(processedDir, 0755)
	os.MkdirAll(failedDir, 0755)

	// Create a real valid PCAP file in incoming directory
	pcapPath := filepath.Join(incomingDir, "test.pcap")
	createValidPCAP(t, pcapPath)

	// Verify the file exists in incoming
	if _, err := os.Stat(pcapPath); err != nil {
		t.Fatalf("PCAP file not created in incoming dir: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- w.Run(ctx)
	}()

	// Wait for processing to complete with timeout
	timeout := time.After(2 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	processed := false
	for !processed {
		select {
		case <-timeout:
			cancel()
			t.Fatal("Test timed out waiting for file to be processed")
		case <-ticker.C:
			// Check if file has moved to processed directory
			if _, err := os.Stat(filepath.Join(processedDir, "test.pcap")); err == nil {
				processed = true
			}
		}
	}

	// Cancel context and wait for clean shutdown
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Expected nil error on context cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watcher did not stop after context cancellation")
	}

	// Verify file was moved from incoming to processed
	if _, err := os.Stat(filepath.Join(processedDir, "test.pcap")); err != nil {
		t.Errorf("Expected file in processed dir: %v", err)
	}

	// Verify file is no longer in incoming
	if _, err := os.Stat(filepath.Join(incomingDir, "test.pcap")); !os.IsNotExist(err) {
		t.Error("Expected file to be removed from incoming dir")
	}

	// Verify processor was called exactly once
	if proc.calls != 1 {
		t.Errorf("Expected 1 processor call, got %d", proc.calls)
	}

	// Verify uploader was called exactly once
	if up.calls != 1 {
		t.Errorf("Expected 1 uploader call, got %d", up.calls)
	}

	// Verify incoming directory is empty
	entries, err := os.ReadDir(incomingDir)
	if err != nil {
		t.Fatalf("Failed to read incoming dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Expected incoming dir to be empty, found %d files", len(entries))
	}

	// Verify failed directory is empty (no processing failures)
	entries, err = os.ReadDir(failedDir)
	if err != nil {
		t.Fatalf("Failed to read failed dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Expected failed dir to be empty, found %d files", len(entries))
	}
}
