package agent

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/config"
	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
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
	return "/tmp/fake.pcap", nil
}

type mockProcessor struct {
	calls *int32
	fail  bool
}

func (m *mockProcessor) ProcessPCAP(pcapPath string) (types.ProcessedData, error) {
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

func minimalConfig(loop bool) *config.Config {
	return &config.Config{
		Capture: struct {
			OutputDir     string `json:"output_dir"`
			WindowSeconds int    `json:"window_seconds"`
			Loop          bool   `json:"loop"`
		}{
			OutputDir:     "/tmp",
			WindowSeconds: 0,
			Loop:          loop,
		},
		Logging: struct {
			Level     string `json:"level"`
			File      string `json:"file"`
			MaxSizeMB int64  `json:"max_size_mb"`
		}{},
		EnigmaAPI: struct {
			Server string `json:"server"`
			APIKey string `json:"api_key"`
			Upload bool   `json:"upload"`
		}{},
	}
}

func TestRunAgent_SingleIteration_Success(t *testing.T) {
	defer t.Log("TestRunAgent_SingleIteration_Success completed")
	var capCalls, procCalls, upCalls int32
	cfg := minimalConfig(false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := RunAgent(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&mockUploader{calls: &upCalls},
		true,
	)
	if err != nil {
		t.Fatalf("RunAgent failed: %v", err)
	}
	if capCalls != 1 || procCalls != 1 || upCalls != 1 {
		t.Errorf("Expected 1 call each, got: cap=%d proc=%d up=%d", capCalls, procCalls, upCalls)
	}
	t.Log("TestRunAgent_SingleIteration_Success end reached")
}

func TestRunAgent_CaptureError(t *testing.T) {
	defer t.Log("TestRunAgent_CaptureError completed")
	var capCalls int32
	cfg := minimalConfig(false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := RunAgent(ctx, cfg,
		&mockCapturer{calls: &capCalls, fail: true},
		&mockProcessor{calls: new(int32)},
		&mockUploader{calls: new(int32)},
		true,
	)
	if err == nil {
		t.Error("Expected error from failed capture, got nil")
	}
	t.Log("TestRunAgent_CaptureError end reached")
}

func TestRunAgent_ProcessorError(t *testing.T) {
	defer t.Log("TestRunAgent_ProcessorError completed")
	var capCalls, procCalls int32
	cfg := minimalConfig(false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := RunAgent(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls, fail: true},
		&mockUploader{calls: new(int32)},
		true,
	)
	if err != nil {
		t.Fatalf("RunAgent should not fail on processor error, got: %v", err)
	}
	if capCalls != 1 || procCalls != 1 {
		t.Errorf("Expected 1 call each, got: cap=%d proc=%d", capCalls, procCalls)
	}
	t.Log("TestRunAgent_ProcessorError end reached")
}

func TestRunAgent_QueueFull(t *testing.T) {
	defer t.Log("TestRunAgent_QueueFull completed")
	var capCalls, procCalls int32
	cfg := minimalConfig(true)
	cfg.Capture.Loop = true
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// Use a capturer that returns quickly to fill the queue
	err := RunAgent(ctx, cfg,
		&mockCapturer{calls: &capCalls},
		&mockProcessor{calls: &procCalls},
		&mockUploader{calls: new(int32)},
		true,
	)
	if err != nil {
		t.Fatalf("RunAgent failed: %v", err)
	}
	if capCalls < 2 {
		t.Errorf("Expected at least 2 capture calls due to loop, got: %d", capCalls)
	}
	t.Log("TestRunAgent_QueueFull end reached")
}
