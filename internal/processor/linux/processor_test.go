//go:build linux || darwin

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
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

	result, err := p.ProcessPCAP(pcapPath, types.ProcessOptions{SamplingPercentage: 100})
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
	result, err := p.ProcessPCAP(pcapPath, types.ProcessOptions{SamplingPercentage: 100})
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

// --- Unit test for embedded JA3/JA4 script materialization ---------------------
// Uses the injected FS + CmdRunner seams (no real Zeek) to assert that the
// embedded JA3/JA4 fingerprint script is written into the run directory and passed
// to the Zeek invocation — guarding the materialization path in ProcessPCAP.

// fakeFS is a no-op filesystem; ProcessPCAP short-circuits (via the stubbed Run
// error) before any of its methods are exercised. Scripts are materialized with
// os.WriteFile directly, not through this FS.
type fakeFS struct{}

func (fakeFS) MkdirAll(string, os.FileMode) error { return nil }
func (fakeFS) Stat(string) (os.FileInfo, error)   { return nil, os.ErrNotExist }
func (fakeFS) Open(string) (*os.File, error)      { return nil, os.ErrNotExist }
func (fakeFS) Create(string) (*os.File, error)    { return nil, os.ErrNotExist }
func (fakeFS) Rename(string, string) error        { return nil }

// capturingCmdRunner records the args handed to Command. The fingerprint scripts
// are appended before Command is called, so Run can abort immediately (returning
// an error) without affecting what was captured.
type capturingCmdRunner struct{ args []string }

func (r *capturingCmdRunner) Command(name string, arg ...string) Cmd {
	r.args = arg
	return stubCmd{}
}

type stubCmd struct{}

func (stubCmd) Run() error { return fmt.Errorf("stub: skipping real zeek execution") }

func argsContain(args []string, substr string) bool {
	for _, a := range args {
		if strings.Contains(a, substr) {
			return true
		}
	}
	return false
}

func TestProcessPCAP_JA3JA4ScriptMaterialized(t *testing.T) {
	const script = "ja3-ja4-fingerprinting.zeek"
	runDir := t.TempDir()
	pcapPath := filepath.Join(runDir, "test.pcap")

	runner := &capturingCmdRunner{}
	p := NewProcessorWithDeps(fakeFS{}, runner, zeekBinary)

	// Run() errors to skip real Zeek; args were already captured at Command().
	_, _ = p.ProcessPCAP(pcapPath, types.ProcessOptions{SamplingPercentage: 100})

	// The embedded script must be passed to Zeek...
	if !argsContain(runner.args, script) {
		t.Fatalf("expected zeek args to include %q, got: %v", script, runner.args)
	}
	// ...and written to the run directory as a real file (embed → disk).
	if _, err := os.Stat(filepath.Join(runDir, script)); err != nil {
		t.Fatalf("expected %q to be materialized into runDir: %v", script, err)
	}
}

// TODO: Add more granular unit tests with mocks for Zeek and file conversion.
