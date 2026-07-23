//go:build linux || darwin

package types

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// runForExitError runs a shell command that is expected to fail and returns the
// resulting error. Using a real process guarantees a real *exec.ExitError with a
// populated ProcessState, which is the only way to exercise the exit-status
// decode branch in FormatZeekFailure.
func runForExitError(t *testing.T, script string) error {
	t.Helper()
	err := exec.Command("sh", "-c", script).Run()
	if err == nil {
		t.Fatalf("expected %q to fail, got nil error", script)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError from %q, got %T: %v", script, err, err)
	}
	return err
}

// signalOf pulls the terminating signal out of an error produced by a process
// that died by signal. The signal's rendered name is platform dependent (Go
// spells SIGABRT "aborted" on Linux and "abort trap" on Darwin), so tests must
// derive the expected text from the same source the production formatter uses
// rather than hardcoding either spelling.
func signalOf(t *testing.T, err error) syscall.Signal {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("expected syscall.WaitStatus, got %T", exitErr.Sys())
	}
	if !status.Signaled() {
		t.Fatalf("expected the process to have died by signal, got %v", exitErr.ProcessState)
	}
	return status.Signal()
}

// TestFormatZeekFailure_ExitStatusDecode covers the exit-status decode branch
// with errors produced by real process exits: a non-zero exit code and a death
// by signal. Without a real *exec.ExitError, errors.As never matches and the
// entire decode branch could be deleted with the suite still green.
func TestFormatZeekFailure_ExitStatusDecode(t *testing.T) {
	exitErr := runForExitError(t, "exit 3")
	signalErr := runForExitError(t, "kill -ABRT $$")

	sig := signalOf(t, signalErr)
	if sig != syscall.SIGABRT {
		t.Fatalf("expected the child to die of SIGABRT, got %v", sig)
	}
	// The full phrase the formatter must emit, signal name included, derived
	// from the OS rather than hardcoded so it holds on Linux and Darwin alike.
	wantSignalPhrase := "terminated by signal: " + sig.String()

	tests := []struct {
		name         string
		err          error
		tailContents string
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:         "non-zero exit code is decoded",
			err:          exitErr,
			tailContents: "fatal error in scripts/base/init.zeek",
			wantContains: []string{
				"exit code 3",
				"zeek stderr:",
				"fatal error in scripts/base/init.zeek",
			},
			wantAbsent: []string{"terminated by"},
		},
		{
			name:         "death by signal is decoded",
			err:          signalErr,
			tailContents: "zeek crashed hard",
			wantContains: []string{
				wantSignalPhrase,
				"zeek stderr:",
				"zeek crashed hard",
			},
			wantAbsent: []string{"exit code"},
		},
		{
			name:         "plain error formats without an exit status",
			err:          errors.New("context deadline exceeded"),
			tailContents: "partial output",
			wantContains: []string{
				"context deadline exceeded",
				"zeek stderr:",
				"partial output",
			},
			wantAbsent: []string{"exit code", "terminated by"},
		},
		{
			name:         "empty tail renders the explicit empty marker",
			err:          exitErr,
			tailContents: "",
			wantContains: []string{"exit code 3", "zeek stderr: <empty>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tail := NewTailBuffer(4096)
			if tt.tailContents != "" {
				if _, err := tail.Write([]byte(tt.tailContents)); err != nil {
					t.Fatalf("tail.Write: %v", err)
				}
			}

			got := FormatZeekFailure(tt.err, tail)

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("FormatZeekFailure() = %q, want it to contain %q", got, want)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("FormatZeekFailure() = %q, want it NOT to contain %q", got, absent)
				}
			}
		})
	}
}

// TestFormatZeekFailure_SignalIsNotReportedAsExitCode pins the distinction the
// acceptance criteria call out: a signalled process must not be described with
// an exit code, and a clean non-zero exit must not be described as signalled.
func TestFormatZeekFailure_SignalIsNotReportedAsExitCode(t *testing.T) {
	signalErr := runForExitError(t, "kill -ABRT $$")

	var exitErr *exec.ExitError
	if !errors.As(signalErr, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T", signalErr)
	}
	if code := exitErr.ExitCode(); code >= 0 {
		t.Fatalf("expected ExitCode() < 0 for a signalled process, got %d", code)
	}

	got := FormatZeekFailure(signalErr, nil)
	wantSignalPhrase := "terminated by signal: " + signalOf(t, signalErr).String()
	if !strings.Contains(got, wantSignalPhrase) {
		t.Errorf("FormatZeekFailure() = %q, want it to contain %q", got, wantSignalPhrase)
	}
	if strings.Contains(got, "exit code") {
		t.Errorf("FormatZeekFailure() = %q, want a signalled process NOT described with an exit code", got)
	}
	if !strings.Contains(got, "zeek stderr: <empty>") {
		t.Errorf("FormatZeekFailure() with a nil tail = %q, want the empty-stderr marker", got)
	}
}

// TestFormatZeekFailure_TruncatedTail verifies that a tail which dropped bytes
// is labelled as truncated so a field engineer does not read a partial stderr
// as the whole story.
func TestFormatZeekFailure_TruncatedTail(t *testing.T) {
	tail := NewTailBuffer(8)
	if _, err := tail.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatalf("tail.Write: %v", err)
	}
	if !tail.Truncated() {
		t.Fatal("expected the tail buffer to report truncation")
	}

	got := FormatZeekFailure(runForExitError(t, "exit 3"), tail)
	if !strings.Contains(got, "truncated") {
		t.Errorf("FormatZeekFailure() = %q, want it to flag the truncated stderr", got)
	}
	if !strings.Contains(got, "89abcdef") {
		t.Errorf("FormatZeekFailure() = %q, want it to contain the retained tail bytes", got)
	}
}
