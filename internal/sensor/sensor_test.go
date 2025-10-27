package sensor

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/config"
	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
)

type mockCapturer struct {
	calls *int32
	fail  bool
}

func (m *mockCapturer) Capture(ctx context.Context, cfg common.CaptureConfig) (string, error) {
	atomic.AddInt32(m.calls, 1)
	if m.fail {
		return "", errors.New("capture failed")
	}
	// Create the fake file so the worker can stat it
	f, _ := os.Create("/tmp/fake.pcap")
	f.Close()
	// Also create a fake .etl file to test deletion
	etl, _ := os.Create("/tmp/fake.etl")
	etl.Close()
	return "/tmp/fake.pcap", nil
}

type mockProcessor struct {
	calls *int32
	fail  bool
}

func (m *mockProcessor) ProcessPCAP(pcapPath string, samplingPercentage float64) (types.ProcessedData, error) {
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

type goneUploader struct {
	calls *int32
}

func (m *goneUploader) UploadLogs(ctx context.Context, files api.LogFiles) error {
	atomic.AddInt32(m.calls, 1)
	return api.ErrAPIGone
}

func minimalConfig(loop bool) *config.Config {
	return &config.Config{
		Capture: struct {
			OutputDir     string `json:"output_dir"`
			WindowSeconds int    `json:"window_seconds"`
			Loop          bool   `json:"loop"`
			Interface     string `json:"interface"`
		}{
			OutputDir:     "/tmp",
			WindowSeconds: 0,
			Loop:          loop,
			Interface:     "any",
		},
		Logging: struct {
			Level            string `json:"level"`
			File             string `json:"file"`
			MaxSizeMB        int64  `json:"max_size_mb"`
			LogRetentionDays int    `json:"log_retention_days"`
		}{
			Level:            "info",
			File:             "",
			MaxSizeMB:        100,
			LogRetentionDays: 1,
		},
		EnigmaAPI: struct {
			Server           string `json:"server"`
			APIKey           string `json:"api_key"`
			Upload           bool   `json:"upload"`
			MaxPayloadSizeMB int64  `json:"max_payload_size_mb"`
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
	if _, err := os.Stat("/tmp/fake.pcap"); !os.IsNotExist(err) {
		t.Errorf("Expected capture file to be deleted, but it still exists or another error occurred: %v", err)
	}
	// Check that the corresponding .etl file was deleted
	if _, err := os.Stat("/tmp/fake.etl"); !os.IsNotExist(err) {
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
	if err != nil {
		t.Fatalf("RunSensor should not return error on 410 Gone, got: %v", err)
	}
	if capCalls != 1 || procCalls != 1 || upCalls != 1 {
		t.Errorf("Expected 1 call each, got: cap=%d proc=%d up=%d", capCalls, procCalls, upCalls)
	}
	t.Log("TestRunSensor_StopsOnAPIGone end reached")
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
