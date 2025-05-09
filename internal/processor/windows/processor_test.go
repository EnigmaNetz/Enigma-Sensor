//go:build windows

package windows

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// mockCmd simulates exec.Cmd behavior for testing.
type mockCmd struct{}

func (m *mockCmd) Run() error                      { return nil }
func (m *mockCmd) Start() error                    { return nil }
func (m *mockCmd) Wait() error                     { return nil }
func (m *mockCmd) Output() ([]byte, error)         { return nil, nil }
func (m *mockCmd) CombinedOutput() ([]byte, error) { return nil, nil }

// mockExecCmd returns a mockCmd for any input.
func mockExecCmd(name string, arg ...string) *exec.Cmd {
	// Use a cross-platform no-op command
	return exec.Command("cmd", "/C", "echo")
}

// mockFS implements common.FS for testing.
type mockFS struct {
	existing  map[string]bool
	renameErr map[string]error
}

func (m *mockFS) Stat(name string) (os.FileInfo, error) {
	name = filepath.Clean(name)
	if m.existing[name] {
		return &mockFileInfo{name: name}, nil
	}
	return nil, errors.New("not found")
}

// mockFileInfo implements os.FileInfo for testing
// Only Name() is used in this context
// Add more methods if needed for future tests
type mockFileInfo struct {
	name string
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() interface{}   { return nil }

func (m *mockFS) Rename(oldpath, newpath string) error {
	oldpath = filepath.Clean(oldpath)
	newpath = filepath.Clean(newpath)
	if err, ok := m.renameErr[oldpath]; ok {
		return err
	}
	// Simulate rename: mark new path as existing, remove old
	m.existing[newpath] = true
	delete(m.existing, oldpath)
	return nil
}

// TestProcessPCAP verifies that ProcessPCAP processes a valid PCAP file and produces non-empty XLSX log paths. Skips if the test PCAP file is not found.
func TestProcessPCAP(t *testing.T) {
	runDir := "/tmp"
	pcapPath := runDir + "/test.pcap"
	zeekBaseDir := filepath.Join("zeek-windows", "zeek-runtime-win64")
	zeekPath := filepath.Join(zeekBaseDir, "bin", "zeek.exe")
	// Ensure zeekBaseDir exists for the test
	if err := os.MkdirAll(zeekBaseDir, 0755); err != nil {
		t.Fatalf("Failed to create zeekBaseDir: %v", err)
	}
	defer os.RemoveAll("zeek-windows")
	fs := &mockFS{
		existing: map[string]bool{
			filepath.Clean(runDir + "/conn.log"): true,
			filepath.Clean(runDir + "/dns.log"):  true,
			filepath.Clean(zeekPath):             true,
		},
		renameErr: map[string]error{},
	}
	p := NewTestProcessor(mockExecCmd, fs)

	result, err := p.ProcessPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ProcessPCAP failed: %v", err)
	}
	if result.ConnPath == "" || result.DNSPath == "" {
		t.Errorf("Expected non-empty XLSX paths, got: %+v", result)
	}
}
