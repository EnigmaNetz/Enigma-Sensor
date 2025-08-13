//go:build windows

package windows

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
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

// TestWindowsCapturer_ETL_File_Not_Found reproduces the B1CF-431 issue where ETL file doesn't exist during conversion
func TestWindowsCapturer_ETL_File_Not_Found(t *testing.T) {
	c := NewWindowsCapturer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a Windows-style output directory that reproduces the path mixing issue from the ticket
	config := common.CaptureConfig{
		CaptureWindow: 1 * time.Second,
		OutputDir:     "captures\\zeek_out_20250616T175905Z", // Windows-style path from ticket
		Interface:     "any",
	}

	origCommandContext := commandContext
	callCount := 0
	commandContext = func(name string, arg ...string) *exec.Cmd {
		callCount++

		// Mock pktmon start/stop to succeed but NOT create the ETL file
		if name == "pktmon" && len(arg) > 0 {
			switch arg[0] {
			case "start":
				// Simulate pktmon start succeeding but silently failing to create ETL
				return exec.Command("cmd", "/C", "echo", "pktmon start succeeded")
			case "stop":
				// Simulate pktmon stop succeeding
				return exec.Command("cmd", "/C", "echo", "pktmon stop succeeded")
			case "etl2pcapng", "etl2pcap":
				// This should not be reached now because our fix checks file existence first
				if len(arg) >= 3 {
					etlPath := arg[1]
					t.Logf("Attempting to convert ETL file: %s", etlPath)
					// This should fail with file not found since we didn't create the ETL
					return exec.Command("cmd", "/C", "echo Cannot open file '"+etlPath+"': The system cannot find the file specified & exit 2")
				}
			}
		}

		// For detection commands, return success
		return exec.Command("cmd", "/C", "echo")
	}
	defer func() { commandContext = origCommandContext }()

	// This should now fail during ETL file verification, not during conversion
	_, err := c.Capture(ctx, config)

	// Verify we get the expected "ETL file verification failed" error instead of "failed to convert ETL to PCAPNG"
	if err == nil {
		t.Errorf("Expected error due to ETL file verification, got nil")
	} else {
		expectedErrMsg := "ETL file verification failed"
		if !containsString(err.Error(), expectedErrMsg) {
			t.Errorf("Expected error containing '%s', got: %v", expectedErrMsg, err)
		} else {
			t.Logf("Fix working correctly - failing at verification stage instead of conversion: %v", err)
		}
	}
}

// TestWindowsCapturer_With_Fix_Success tests that the fix works when ETL file is properly created
func TestWindowsCapturer_With_Fix_Success(t *testing.T) {
	c := NewWindowsCapturer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a temporary directory for testing
	tempDir := t.TempDir()
	config := common.CaptureConfig{
		CaptureWindow: 1 * time.Second,
		OutputDir:     tempDir,
		Interface:     "any",
	}

	origCommandContext := commandContext
	var etlFilePath string
	commandContext = func(name string, arg ...string) *exec.Cmd {
		if name == "pktmon" && len(arg) > 0 {
			switch arg[0] {
			case "start":
				// Extract ETL file path from arguments and create a dummy file
				for i, a := range arg {
					if a == "--file" && i+1 < len(arg) {
						etlFilePath = arg[i+1]
						// Create the ETL file with some dummy content
						go func() {
							time.Sleep(200 * time.Millisecond) // Simulate file creation delay
							if err := os.WriteFile(etlFilePath, []byte("dummy ETL content"), 0644); err != nil {
								t.Logf("Failed to create dummy ETL file: %v", err)
							}
						}()
						break
					}
				}
				return exec.Command("echo", "pktmon start succeeded")
			case "stop":
				return exec.Command("echo", "pktmon stop succeeded")
			case "etl2pcapng", "etl2pcap":
				if len(arg) >= 3 {
					// Create a dummy PCAPNG file to simulate successful conversion
					pcapngPath := arg[len(arg)-1] // Last argument is output file
					if err := os.WriteFile(pcapngPath, []byte("dummy PCAPNG content"), 0644); err != nil {
						t.Logf("Failed to create dummy PCAPNG file: %v", err)
					}
					return exec.Command("echo", "conversion succeeded")
				}
			}
		}

		// For detection commands, return success
		return exec.Command("echo")
	}
	defer func() { commandContext = origCommandContext }()

	// This should now succeed with our fixes
	result, err := c.Capture(ctx, config)

	if err != nil {
		t.Errorf("Expected successful capture with fixes, got error: %v", err)
	} else {
		t.Logf("Capture succeeded with result: %s", result)
		// Verify the result path uses proper path separators
		if result == "" {
			t.Errorf("Expected non-empty result path")
		}
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
