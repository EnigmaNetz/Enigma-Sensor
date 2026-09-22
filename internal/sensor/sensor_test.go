package sensor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/config"
	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
)

func intPtr(v int) *int { return &v }

type mockCapturer struct {
	calls *int32
	fail  bool
}

func (m *mockCapturer) Capture(ctx context.Context, cfg common.CaptureConfig) (string, error) {
	n := atomic.AddInt32(m.calls, 1)
	if m.fail {
		return "", errors.New("capture failed")
	}
	// Create the fake file so the worker can stat it
	pcapPath := fmt.Sprintf("/tmp/fake_%d.pcap", n)
	f, _ := os.Create(pcapPath)
	f.Close()
	// Also create a fake .etl file to test deletion
	etlPath := fmt.Sprintf("/tmp/fake_%d.etl", n)
	etl, _ := os.Create(etlPath)
	etl.Close()
	return pcapPath, nil
}

type mockProcessor struct {
	calls *int32
	fail  bool
}

func (m *mockProcessor) ProcessPCAP(pcapPath string, opts types.ProcessOptions) (types.ProcessedData, error) {
	atomic.AddInt32(m.calls, 1)
	if m.fail {
		return types.ProcessedData{}, errors.New("process failed")
	}
	return types.ProcessedData{
		ConnPath: "/tmp/conn.xlsx",
		DNSPath:  "/tmp/dns.xlsx",
		Metadata: map[string]interface{}{"test": true},
	}, nil
}

type mockUploader struct {
	calls *int32
	fail  bool
}

func (m *mockUploader) UploadLogs(ctx context.Context, files api.LogFiles) error {
	atomic.AddInt32(m.calls, 1)
	if m.fail {
		return errors.New("upload failed")
	}
	return nil
}

type slowProcessor struct {
	calls *int32
	delay time.Duration
}

func (m *slowProcessor) ProcessPCAP(pcapPath string, opts types.ProcessOptions) (types.ProcessedData, error) {
	atomic.AddInt32(m.calls, 1)
	time.Sleep(m.delay)
	return types.ProcessedData{
		ConnPath: "/tmp/conn.xlsx",
		DNSPath:  "/tmp/dns.xlsx",
		Metadata: map[string]interface{}{"test": true},
	}, nil
}

type goneUploader struct {
	calls *int32
}

func (m *goneUploader) UploadLogs(ctx context.Context, files api.LogFiles) error {
	atomic.AddInt32(m.calls, 1)
	// Wrapped the way the real uploader wraps it (chunk wrap around the client wrap)
	return fmt.Errorf("failed to upload chunk 1: %w", fmt.Errorf("API returned 410 Gone: %w", api.ErrAPIGone))
}

func minimalConfig(loop bool) *config.Config {
	return &config.Config{
		Capture: struct {
			OutputDir            string `json:"output_dir"`
			WindowSeconds        int    `json:"window_seconds"`
			Loop                 bool   `json:"loop"`
			Interface            string `json:"interface"`
			MaxProcessingWorkers int    `json:"max_processing_workers"`
			RetentionHours       *int   `json:"retention_hours,omitempty"`
		}{
			OutputDir:            "/tmp",
			WindowSeconds:        0,
			Loop:                 loop,
			Interface:            "any",
			MaxProcessingWorkers: 10,
			RetentionHours:       intPtr(24),
		},
		Logging: struct {
			File             string `json:"file"`
			MaxSizeMB        int64  `json:"max_size_mb"`
			LogRetentionDays int    `json:"log_retention_days"`
			MaxBackups       int    `json:"max_backups"`
		}{
			File:             "",
			MaxSizeMB:        100,
			LogRetentionDays: 1,
			MaxBackups:       5,
		},
		EnigmaAPI: struct {
			Server           string `json:"server"`
			APIKey           string `json:"api_key"`
			CACertFile       string `json:"ca_cert_file"`
			Upload           bool   `json:"upload"`
			MaxPayloadSizeMB int64  `json:"max_payload_size_mb"`
		}{},
		PcapIngest: struct {
			Enabled             bool   `json:"enabled"`
			WatchDir            string `json:"watch_dir"`
			PollIntervalSeconds int    `json:"poll_interval_seconds"`
			FileStableSeconds   int    `json:"file_stable_seconds"`
		}{},
	}
}

func TestRunSensor_SingleIteration_Success(t *testing.T) {
	defer t.Log("TestRunSensor_SingleIteration_Success completed")
	var capCalls, procCalls, upCalls int32
	cfg := minimalConfig(false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&mockUploader{calls: &upCalls},
		true, true,
	)
	if err != nil {
		t.Fatalf("RunSensor failed: %v", err)
	}
	if capCalls != 1 || procCalls != 1 || upCalls != 1 {
		t.Errorf("Expected 1 call each, got: cap=%d proc=%d up=%d", capCalls, procCalls, upCalls)
	}
	// Check that the capture file was deleted
	if _, err := os.Stat("/tmp/fake_1.pcap"); !os.IsNotExist(err) {
		t.Errorf("Expected capture file to be deleted, but it still exists or another error occurred: %v", err)
	}
	// Check that the corresponding .etl file was deleted
	if _, err := os.Stat("/tmp/fake_1.etl"); !os.IsNotExist(err) {
		t.Errorf("Expected ETL file to be deleted, but it still exists or another error occurred: %v", err)
	}
	t.Log("TestRunSensor_SingleIteration_Success end reached")
}

func TestRunSensor_CaptureError(t *testing.T) {
	defer t.Log("TestRunSensor_CaptureError completed")
	var capCalls int32
	cfg := minimalConfig(false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls, fail: true},
		&mockProcessor{calls: new(int32)},
		&mockUploader{calls: new(int32)},
		true, true,
	)
	if err == nil {
		t.Error("Expected error from failed capture, got nil")
	}
	t.Log("TestRunSensor_CaptureError end reached")
}

func TestRunSensor_ProcessorError(t *testing.T) {
	defer t.Log("TestRunSensor_ProcessorError completed")
	var capCalls, procCalls int32
	cfg := minimalConfig(false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls, fail: true},
		&mockUploader{calls: new(int32)},
		true, true,
	)
	if err != nil {
		t.Fatalf("RunSensor should not fail on processor error, got: %v", err)
	}
	if capCalls != 1 || procCalls != 1 {
		t.Errorf("Expected 1 call each, got: cap=%d proc=%d", capCalls, procCalls)
	}
	t.Log("TestRunSensor_ProcessorError end reached")
}

func TestRunSensor_QueueFull(t *testing.T) {
	defer t.Log("TestRunSensor_QueueFull completed")
	var capCalls, procCalls int32
	cfg := minimalConfig(true)
	cfg.Capture.Loop = true
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// Use a capturer that returns quickly to fill the queue
	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&mockUploader{calls: new(int32)},
		true, true,
	)
	if err != nil {
		t.Fatalf("RunSensor failed: %v", err)
	}
	if capCalls < 2 {
		t.Errorf("Expected at least 2 capture calls due to loop, got: %d", capCalls)
	}
	t.Log("TestRunSensor_QueueFull end reached")
}

func TestRunSensor_StopsOnAPIGone(t *testing.T) {
	defer t.Log("TestRunSensor_StopsOnAPIGone completed")
	var capCalls, procCalls, upCalls int32
	cfg := minimalConfig(false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&goneUploader{calls: &upCalls},
		true, true,
	)
	if !errors.Is(err, ErrAPIGone) {
		t.Fatalf("Expected ErrAPIGone, got: %v", err)
	}
	if capCalls != 1 || procCalls != 1 || upCalls != 1 {
		t.Errorf("Expected 1 call each, got: cap=%d proc=%d up=%d", capCalls, procCalls, upCalls)
	}
	t.Log("TestRunSensor_StopsOnAPIGone end reached")
}

// With loop on, only the 410 can end the run before the context deadline, so an
// early return proves the capture loop saw the shutdown.
func TestRunSensor_LoopStopsOnAPIGone(t *testing.T) {
	var capCalls, procCalls, upCalls int32
	cfg := minimalConfig(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&goneUploader{calls: &upCalls},
		true, true,
	)
	if !errors.Is(err, ErrAPIGone) {
		t.Fatalf("Expected ErrAPIGone, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("RunSensor kept looping after a 410 (returned after %v)", elapsed)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunSensor returned only because the context expired")
	}

	// Every capture must be cleaned up, including the ones that got a 410
	for n := int32(1); n <= atomic.LoadInt32(&capCalls); n++ {
		path := fmt.Sprintf("/tmp/fake_%d.pcap", n)
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%s was left on disk after a 410", path)
		}
	}
}

// waitingGoneUploader returns a 410 only once the capturer has made a few more
// captures, so at least one is still queued when the only worker returns.
type waitingGoneUploader struct {
	capCalls *int32
}

func (m *waitingGoneUploader) UploadLogs(ctx context.Context, files api.LogFiles) error {
	for atomic.LoadInt32(m.capCalls) < 3 {
		time.Sleep(time.Millisecond)
	}
	return fmt.Errorf("API returned 410 Gone: %w", api.ErrAPIGone)
}

func TestRunSensor_APIGoneDeletesQueuedCaptures(t *testing.T) {
	var capCalls, procCalls int32
	cfg := minimalConfig(true)
	cfg.Capture.MaxProcessingWorkers = 1
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&waitingGoneUploader{capCalls: &capCalls},
		true, true,
	)
	if !errors.Is(err, ErrAPIGone) {
		t.Fatalf("Expected ErrAPIGone, got: %v", err)
	}
	if atomic.LoadInt32(&procCalls) != 1 {
		t.Fatalf("expected the single worker to process 1 capture, got %d", procCalls)
	}
	for n := int32(1); n <= atomic.LoadInt32(&capCalls); n++ {
		path := fmt.Sprintf("/tmp/fake_%d.pcap", n)
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%s was left on disk after a 410", path)
		}
	}
}

// The ingest watcher only returns when its context ends, so a 410 from a
// capture worker must still stop it rather than hang in wg.Wait.
func TestRunSensor_APIGoneStopsIngestWatcher(t *testing.T) {
	var capCalls, procCalls, upCalls int32
	cfg := minimalConfig(false)
	cfg.PcapIngest.Enabled = true
	cfg.PcapIngest.WatchDir = t.TempDir() // stays empty, so the watcher never sees a 410 itself
	cfg.PcapIngest.PollIntervalSeconds = 1
	cfg.PcapIngest.FileStableSeconds = 1
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&goneUploader{calls: &upCalls},
		true, true,
	)
	if !errors.Is(err, ErrAPIGone) {
		t.Fatalf("Expected ErrAPIGone, got: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("RunSensor returned only because the context expired: the ingest watcher kept it waiting")
	}
}

func TestRunSensor_ConcurrentWorkers(t *testing.T) {
	defer t.Log("TestRunSensor_ConcurrentWorkers completed")
	var capCalls, procCalls int32
	cfg := minimalConfig(true)

	// Use a slow processor to verify concurrency
	slowProc := &slowProcessor{calls: &procCalls, delay: 20 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := RunSensor(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		slowProc,
		&mockUploader{calls: new(int32)},
		true, true,
	)
	if err != nil {
		t.Fatalf("RunSensor failed: %v", err)
	}
	finalProcCalls := atomic.LoadInt32(&procCalls)
	if finalProcCalls < 2 {
		t.Errorf("Expected at least 2 processed PCAPs with concurrent workers, got: %d", finalProcCalls)
	}
	t.Logf("Concurrent workers processed %d PCAPs", finalProcCalls)
	t.Log("TestRunSensor_ConcurrentWorkers end reached")
}

func TestAddFingerprintScriptToMainZeek_AddsDirective(t *testing.T) {
	f, err := os.CreateTemp("", "main-*.zeek")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("@load base/protocols/dhcp\n")
	f.Close()

	if err := addFingerprintScriptToMainZeek(f.Name()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(f.Name())
	if !strings.Contains(string(content), "@load ./dhcp-fingerprint.zeek") {
		t.Errorf("expected directive in main.zeek, got:\n%s", content)
	}
}

func TestAddFingerprintScriptToMainZeek_Idempotent(t *testing.T) {
	f, err := os.CreateTemp("", "main-*.zeek")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("@load base/protocols/dhcp\n@load ./dhcp-fingerprint.zeek\n")
	f.Close()

	if err := addFingerprintScriptToMainZeek(f.Name()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(f.Name())
	count := strings.Count(string(content), "@load ./dhcp-fingerprint.zeek")
	if count != 1 {
		t.Errorf("expected directive exactly once, found %d times", count)
	}
}

func TestAddFingerprintScriptToMainZeek_MissingFile(t *testing.T) {
	err := addFingerprintScriptToMainZeek("/nonexistent/path/main.zeek")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestValidateZipPath_RejectsPathTraversal(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"safe relative path", "file.txt", false},
		{"safe nested path", "dir/file.txt", false},
		{"safe deep path", "dir1/dir2/dir3/file.txt", false},
		{"dot dot in path", "../file.txt", true},
		{"dot dot in middle", "dir/../file.txt", true},
		{"dot dot at end", "dir/..", true},
		{"double dot dot", "../../file.txt", true},
		{"absolute path unix", "/etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateZipPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateZipPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestPruneRotatedServiceLogs(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-8 * 24 * time.Hour)
	files := map[string]bool{ // name -> should survive
		"enigma-sensor.log":                     true,  // live log, never pruned
		"enigma-sensor-20260901T120000.000.log": false, // old rotated log
		"enigma-sensor-20260920T120000.000.log": true,  // recent rotated log
		"other-20260901T120000.000.log":         true,  // not ours
	}
	for name := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if name != "enigma-sensor-20260920T120000.000.log" {
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}

	pruneRotatedServiceLogs(dir, 7*24*time.Hour)

	for name, survive := range files {
		_, err := os.Stat(filepath.Join(dir, name))
		if survive && err != nil {
			t.Errorf("%s should have been kept: %v", name, err)
		}
		if !survive && !os.IsNotExist(err) {
			t.Errorf("%s should have been deleted", name)
		}
	}
}

func TestPruneRotatedServiceLogs_MissingDir(t *testing.T) {
	// Must not panic or create anything when the directory does not exist
	pruneRotatedServiceLogs(filepath.Join(t.TempDir(), "absent"), time.Hour)
}
