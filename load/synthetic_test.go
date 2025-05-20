package load

import (
	"context"
	"errors"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
)

type mockCapturer struct {
	called bool
	cfg    common.CaptureConfig
	err    error
}

func (m *mockCapturer) Capture(ctx context.Context, cfg common.CaptureConfig) (string, error) {
	m.called = true
	m.cfg = cfg
	return "capture.pcap", m.err
}

type mockProcessor struct {
	called bool
	err    error
}

func (m *mockProcessor) ProcessPCAP(p string) (types.ProcessedData, error) {
	m.called = true
	return types.ProcessedData{ConnPath: "conn.xlsx", DNSPath: "dns.xlsx"}, m.err
}

type mockUploader struct {
	called bool
	err    error
}

func (m *mockUploader) UploadLogs(ctx context.Context, files api.LogFiles) error {
	m.called = true
	return m.err
}

func TestRunSyntheticCaptureLoadSuccess(t *testing.T) {
	cap := &mockCapturer{}
	proc := &mockProcessor{}
	up := &mockUploader{}
	cfg := Config{Duration: 50 * time.Millisecond}
	if err := RunSyntheticCaptureLoad(context.Background(), cap, proc, up, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cap.called || !proc.called || !up.called {
		t.Fatalf("expected capturer, processor, and uploader to be called")
	}
}

func TestRunSyntheticCaptureLoadCaptureError(t *testing.T) {
	cap := &mockCapturer{err: errors.New("capture failed")}
	proc := &mockProcessor{}
	up := &mockUploader{}
	cfg := Config{Duration: 10 * time.Millisecond}
	if err := RunSyntheticCaptureLoad(context.Background(), cap, proc, up, cfg); err == nil {
		t.Fatal("expected error but got nil")
	}
	if !cap.called {
		t.Fatal("capturer not called")
	}
	if proc.called || up.called {
		t.Fatal("processor or uploader should not be called on capture error")
	}
}
