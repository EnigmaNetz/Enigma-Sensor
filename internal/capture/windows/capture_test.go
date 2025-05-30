//go:build windows

package windows

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
)

// TestWindowsCapturer_Capture_Success verifies that the WindowsCapturer successfully captures data when the command executes without error.
var winArgs []string

func TestWindowsCapturer_Capture_Success(t *testing.T) {
	c := NewWindowsCapturer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := common.CaptureConfig{
		CaptureWindow:   1 * time.Second,
		CaptureInterval: 1 * time.Second,
		OutputDir:       "C:/tmp",
		Interface:       "1",
	}

	// Patch commandContext to return a dummy Cmd
	origCommandContext := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		winArgs = arg
		return exec.Command("cmd", "/C", "echo")
	}
	defer func() { commandContext = origCommandContext }()

	_, err := c.Capture(ctx, config)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	found := false
	for i := range winArgs {
		if winArgs[i] == "-i" && i+1 < len(winArgs) && winArgs[i+1] == "1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected interface filter args, got %v", winArgs)
	}
}

// TestWindowsCapturer_Capture_Error verifies that the WindowsCapturer returns an error when the capture command fails to execute.
func TestWindowsCapturer_Capture_Error(t *testing.T) {
	c := NewWindowsCapturer()
	origCommandContext := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("cmd", "/C", "exit", "1")
	}
	defer func() { commandContext = origCommandContext }()
	config := common.CaptureConfig{
		CaptureWindow:   1 * time.Second,
		CaptureInterval: 1 * time.Second,
		OutputDir:       "C:/tmp",
	}
	_, err := c.Capture(context.Background(), config)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}
