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
var winArgsList [][]string

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

	// Patch commandContext to record all command invocations
	origCommandContext := commandContext
	winArgsList = nil
	commandContext = func(name string, arg ...string) *exec.Cmd {
		winArgsList = append(winArgsList, append([]string{name}, arg...))
		return exec.Command("cmd", "/C", "echo")
	}
	defer func() { commandContext = origCommandContext }()

	_, err := c.Capture(ctx, config)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	found := false
	for _, args := range winArgsList {
		if len(args) >= 4 && args[0] == "pktmon" && args[1] == "filter" && args[2] == "add" && args[3] == "-i" && len(args) >= 5 && args[4] == "1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected pktmon filter add command with interface, got %v", winArgsList)
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
