//go:build linux || darwin

package linux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
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

// stubCmd aborts immediately. It satisfies the full Cmd interface (including the
// stdout/stderr seams used for Zeek failure capture) but discards both streams:
// this test only cares about the args handed to Command.
type stubCmd struct{}

func (stubCmd) Run() error            { return fmt.Errorf("stub: skipping real zeek execution") }
func (stubCmd) SetStdout(w io.Writer) {}
func (stubCmd) SetStderr(w io.Writer) {}

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

// fakeCmd is a test double for Cmd that records the writers it was handed,
// emits a canned stderr payload when Run is called, and returns a canned error.
type fakeCmd struct {
	stderrOut string // written to the stderr writer during Run
	runErr    error

	stdout io.Writer
	stderr io.Writer

	runCalled          bool
	setStdoutCalled    bool
	setStderrCalled    bool
	stdoutSetBeforeRun bool
	stderrSetBeforeRun bool
}

func (f *fakeCmd) SetStdout(w io.Writer) {
	f.setStdoutCalled = true
	f.stdoutSetBeforeRun = !f.runCalled
	f.stdout = w
}

func (f *fakeCmd) SetStderr(w io.Writer) {
	f.setStderrCalled = true
	f.stderrSetBeforeRun = !f.runCalled
	f.stderr = w
}

func (f *fakeCmd) Run() error {
	f.runCalled = true
	if f.stderrOut != "" && f.stderr != nil {
		if _, err := io.WriteString(f.stderr, f.stderrOut); err != nil {
			return err
		}
	}
	return f.runErr
}

// fakeCmdRunner hands out a single pre-configured fakeCmd.
type fakeCmdRunner struct {
	cmd *fakeCmd
}

func (r *fakeCmdRunner) Command(name string, arg ...string) Cmd { return r.cmd }

// captureLogs redirects the standard logger into a buffer for the duration of
// the test and restores it afterwards.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// runProcessPCAPWithFake wires the processor to the given fake command and runs
// ProcessPCAP against a throwaway run directory. It returns the error from
// ProcessPCAP and the captured log output.
func runProcessPCAPWithFake(t *testing.T, fc *fakeCmd) (string, error) {
	t.Helper()
	buf := captureLogs(t)
	pcapPath := filepath.Join(t.TempDir(), "capture.pcap")
	p := NewProcessorWithDeps(realFS{}, &fakeCmdRunner{cmd: fc}, "/opt/zeek/bin/zeek")
	_, err := p.ProcessPCAP(pcapPath, types.ProcessOptions{SamplingPercentage: 100})
	return buf.String(), err
}

// TestProcessPCAP_ZeekNonZeroExitSurfacesStderr verifies that when Zeek exits
// non-zero, the stderr it produced (the only place the real reason appears) is
// surfaced in the sensor log rather than silently discarded.
func TestProcessPCAP_ZeekNonZeroExitSurfacesStderr(t *testing.T) {
	const zeekStderr = "fatal error: problem with trace file /tmp/capture.pcap (No such file or directory)\n"
	fc := &fakeCmd{stderrOut: zeekStderr, runErr: errors.New("exit status 1")}

	logs, err := runProcessPCAPWithFake(t, fc)
	if err == nil {
		t.Fatal("ProcessPCAP returned nil error, want a zeek failure error")
	}
	if !strings.Contains(err.Error(), "zeek failed") {
		t.Errorf("error = %q, want it to wrap %q", err.Error(), "zeek failed")
	}
	if !strings.Contains(logs, "[processor] Zeek execution failed:") {
		t.Errorf("log output missing the failure line, got:\n%s", logs)
	}
	if !strings.Contains(logs, "problem with trace file") {
		t.Errorf("log output does not contain the captured Zeek stderr, got:\n%s", logs)
	}
	if !strings.Contains(logs, "No such file or directory") {
		t.Errorf("log output does not contain the Zeek stderr detail, got:\n%s", logs)
	}
}

// TestProcessPCAP_ZeekAbortSurfacesStderr covers the signal/abort shape, where
// Zeek dies on an uncaught exception and the exit error alone says nothing
// useful.
func TestProcessPCAP_ZeekAbortSurfacesStderr(t *testing.T) {
	const zeekStderr = "terminating with uncaught exception of type std::bad_alloc: std::bad_alloc\n"
	fc := &fakeCmd{stderrOut: zeekStderr, runErr: errors.New("signal: aborted")}

	logs, err := runProcessPCAPWithFake(t, fc)
	if err == nil {
		t.Fatal("ProcessPCAP returned nil error, want a zeek failure error")
	}
	if !strings.Contains(logs, "[processor] Zeek execution failed:") {
		t.Errorf("log output missing the failure line, got:\n%s", logs)
	}
	if !strings.Contains(logs, "std::bad_alloc") {
		t.Errorf("log output does not contain the bad_alloc stderr, got:\n%s", logs)
	}
}

// TestProcessPCAP_ZeekFailsWithNoStderr verifies the empty-stderr path still
// reports the failure and does not panic on an empty tail buffer.
func TestProcessPCAP_ZeekFailsWithNoStderr(t *testing.T) {
	fc := &fakeCmd{stderrOut: "", runErr: errors.New("exit status 2")}

	logs, err := runProcessPCAPWithFake(t, fc)
	if err == nil {
		t.Fatal("ProcessPCAP returned nil error, want a zeek failure error")
	}
	if !strings.Contains(err.Error(), "zeek failed") {
		t.Errorf("error = %q, want it to wrap %q", err.Error(), "zeek failed")
	}
	if !strings.Contains(logs, "[processor] Zeek execution failed:") {
		t.Errorf("log output missing the failure line, got:\n%s", logs)
	}
	if !strings.Contains(logs, "exit status 2") {
		t.Errorf("log output missing the underlying error, got:\n%s", logs)
	}
}

// TestProcessPCAP_ZeekSuccessDoesNotLogFailure verifies that stderr noise from a
// successful Zeek run is not reported as a failure. ProcessPCAP still returns an
// error from later stages against a throwaway run dir, so this asserts only on
// the absence of the failure line.
func TestProcessPCAP_ZeekSuccessDoesNotLogFailure(t *testing.T) {
	fc := &fakeCmd{stderrOut: "warning: no packet filter, listening on all traffic\n", runErr: nil}

	logs, _ := runProcessPCAPWithFake(t, fc)
	if strings.Contains(logs, "Zeek execution failed") {
		t.Errorf("failure line logged for a successful Zeek run, got:\n%s", logs)
	}
}

// TestProcessPCAP_SetsStdoutAndStderrBeforeRun verifies the processor attaches
// non-nil output writers to the command before starting it, which is what makes
// the stderr capture possible at all.
func TestProcessPCAP_SetsStdoutAndStderrBeforeRun(t *testing.T) {
	fc := &fakeCmd{stderrOut: "some output\n", runErr: errors.New("exit status 1")}

	if _, _ = runProcessPCAPWithFake(t, fc); !fc.runCalled {
		t.Fatal("Run was never called on the fake command")
	}
	if !fc.setStdoutCalled {
		t.Error("SetStdout was never called")
	}
	if !fc.setStderrCalled {
		t.Error("SetStderr was never called")
	}
	if !fc.stdoutSetBeforeRun {
		t.Error("SetStdout was called after Run, want before")
	}
	if !fc.stderrSetBeforeRun {
		t.Error("SetStderr was called after Run, want before")
	}
	if fc.stdout == nil {
		t.Error("SetStdout was handed a nil writer")
	}
	if fc.stderr == nil {
		t.Error("SetStderr was handed a nil writer")
	}
}
