//go:build linux || darwin

package linux

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestProcessPCAP verifies that ProcessPCAP processes a valid PCAP file and produces non-empty XLSX log paths. Skips if the test PCAP file is not found.
func TestProcessPCAP(t *testing.T) {
	p := NewProcessor()

	// This test assumes Zeek is installed and a valid PCAP is available.
	// For CI, mock exec.Command or use a test fixture.
	pcapPath := "/tmp/test.pcap" // TODO: Provide a real or mock PCAP file
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("Test PCAP file not found; skipping integration test.")
	}

	result, err := p.ProcessPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ProcessPCAP failed: %v", err)
	}
	if result.ConnPath == "" || result.DNSPath == "" {
		t.Errorf("Expected non-empty XLSX paths, got: %+v", result)
	}
}

// TestZeekNotInstalled is a placeholder for testing behavior when Zeek is not installed. Requires refactor for true unit test.
func TestZeekNotInstalled(t *testing.T) {
	_ = NewProcessor()
	// Temporarily set zeekBinary to a non-existent path (requires refactor to allow injection for true unit test)
	// This is a placeholder for how you'd test Zeek not being present.
	// t.Skip("TODO: Refactor to allow zeekBinary injection for unit test.")
}

// TestMissingLogFiles is a placeholder for testing behavior when Zeek runs but does not produce expected log files. Requires mocking for full coverage.
func TestMissingLogFiles(t *testing.T) {
	_ = NewProcessor()
	// Simulate Zeek running but not producing conn.log/dns.log (requires mocking exec.Command and file system)
	// t.Skip("TODO: Mock exec.Command and file system for missing log files.")
}

// TestMetadataContent verifies that ProcessPCAP output includes expected metadata fields such as 'zeek_out_dir' and a valid 'timestamp'. Skips if the test PCAP file is not found.
func TestMetadataContent(t *testing.T) {
	p := NewProcessor()
	pcapPath := "/tmp/test.pcap"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("Test PCAP file not found; skipping integration test.")
	}
	result, err := p.ProcessPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ProcessPCAP failed: %v", err)
	}
	if _, ok := result.Metadata["zeek_out_dir"]; !ok {
		t.Error("Expected metadata to contain 'zeek_out_dir'")
	}
	if ts, ok := result.Metadata["timestamp"]; !ok || !strings.Contains(ts.(string), "T") {
		t.Error("Expected metadata to contain valid 'timestamp'")
	}
}

// --- Real unit tests with mocks ---

type fakeFS struct {
	failMkdirAll bool
	failOpen     bool
	failCreate   bool
	failRename   bool
	files        map[string][]byte
}

func (f *fakeFS) MkdirAll(path string, perm os.FileMode) error {
	if f.failMkdirAll {
		return errors.New("mkdir failed")
	}
	return nil
}
func (f *fakeFS) Stat(name string) (os.FileInfo, error) {
	if _, ok := f.files[name]; ok {
		return &fakeFileInfo{name}, nil
	}
	return nil, os.ErrNotExist
}
func (f *fakeFS) Open(name string) (*os.File, error) {
	if f.failOpen {
		return nil, errors.New("open failed")
	}
	// Use a temp file to avoid using os.Stdin
	tmp, err := os.CreateTemp("", "fake-open")
	if err != nil {
		return nil, err
	}
	return tmp, nil
}
func (f *fakeFS) Create(name string) (*os.File, error) {
	if f.failCreate {
		return nil, errors.New("create failed")
	}
	// Use a temp file to avoid using os.Stdout
	tmp, err := os.CreateTemp("", "fake-create")
	if err != nil {
		return nil, err
	}
	return tmp, nil
}
func (f *fakeFS) Rename(oldpath, newpath string) error {
	if f.failRename {
		return errors.New("rename failed")
	}
	f.files[newpath] = f.files[oldpath]
	delete(f.files, oldpath)
	return nil
}

type fakeFileInfo struct{ name string }

func (f *fakeFileInfo) Name() string           { return f.name }
func (f *fakeFileInfo) Size() int64            { return 0 }
func (f *fakeFileInfo) Mode() os.FileMode      { return 0644 }
func (f *fakeFileInfo) ModTime() (t time.Time) { return }
func (f *fakeFileInfo) IsDir() bool            { return false }
func (f *fakeFileInfo) Sys() interface{}       { return nil }

type fakeCmd struct{ fail bool }

func (f *fakeCmd) Run() error {
	if f.fail {
		return errors.New("zeek not installed")
	}
	return nil
}

type fakeCmdRunner struct{ fail bool }

func (f *fakeCmdRunner) Command(name string, arg ...string) Cmd {
	return &fakeCmd{fail: f.fail}
}

func TestProcessPCAP_Unit(t *testing.T) {
	tests := []struct {
		name      string
		fs        *fakeFS
		cmdRunner *fakeCmdRunner
		wantErr   string
		files     map[string][]byte
	}{
		{
			name:      "Zeek not installed",
			fs:        &fakeFS{files: map[string][]byte{"/tmp/test.pcap": {}}},
			cmdRunner: &fakeCmdRunner{fail: true},
			wantErr:   "zeek failed",
		},
		{
			name:      "Directory creation fails",
			fs:        &fakeFS{failMkdirAll: true, files: map[string][]byte{"/tmp/test.pcap": {}}},
			cmdRunner: &fakeCmdRunner{},
			wantErr:   "failed to create output dir",
		},
		{
			name:      "Missing log files",
			fs:        &fakeFS{files: map[string][]byte{"/tmp/test.pcap": {}}},
			cmdRunner: &fakeCmdRunner{},
			wantErr:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProcessorWithDeps(tt.fs, tt.cmdRunner, "/bin/zeek")
			// Use a fake PCAP path
			os.Setenv("CAPTURE_OUTPUT_DIR", "/tmp")
			_, err := p.ProcessPCAP("/tmp/test.pcap")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TODO: Add more granular unit tests with mocks for Zeek and file conversion.
