//go:build linux || darwin

package linux

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
)

// mockCmd is a mock for exec.Cmd
var mockRunError error
var gotArgs []string

// TestLinuxCapturer_Capture_Success verifies that the LinuxCapturer successfully captures data when the command executes without error.
func TestLinuxCapturer_Capture_Success(t *testing.T) {
	c := NewLinuxCapturer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := common.CaptureConfig{
		CaptureWindow:   1 * time.Second,
		CaptureInterval: 1 * time.Second,
		OutputDir:       "/tmp",
		Interface:       "eth0",
	}

	// Patch commandContext to return a dummy Cmd
	origCommandContext := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		gotArgs = arg
		return exec.Command("echo")
	}
	defer func() { commandContext = origCommandContext }()

	_, err := c.Capture(ctx, config)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	found := false
	for i := range gotArgs {
		if gotArgs[i] == "eth0" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected interface arg 'eth0', got %v", gotArgs)
	}
}

// TestLinuxCapturer_Capture_Error verifies that the LinuxCapturer returns an error when the capture command fails to execute.
func TestLinuxCapturer_Capture_Error(t *testing.T) {
	c := NewLinuxCapturer()
	mockRunError = errors.New("mock error")
	origCommandContext := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		cmd := exec.Command("false")
		return cmd
	}
	defer func() { commandContext = origCommandContext }()
	config := common.CaptureConfig{
		CaptureWindow:   1 * time.Second,
		CaptureInterval: 1 * time.Second,
		OutputDir:       "/tmp",
	}
	_, err := c.Capture(context.Background(), config)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}
