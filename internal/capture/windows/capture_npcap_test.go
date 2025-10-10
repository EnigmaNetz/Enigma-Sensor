//go:build windows

package windows

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
)

func TestIsNpcapAvailable(t *testing.T) {
	// This test will pass or fail based on actual Npcap installation
	// Just verify the function doesn't panic
	available := IsNpcapAvailable()
	t.Logf("Npcap available: %v", available)

	// Function should return a boolean without error
	assert.IsType(t, true, available)
}

func TestNpcapCapturer_Creation(t *testing.T) {
	capturer := NewNpcapCapturer()
	assert.NotNil(t, capturer)
	assert.IsType(t, &NpcapCapturer{}, capturer)
}

func TestNpcapCapturer_Capture_NpcapNotInstalled(t *testing.T) {
	// Skip this test if Npcap is actually installed
	if IsNpcapAvailable() {
		t.Skip("Npcap is installed, skipping not-installed test")
	}

	capturer := NewNpcapCapturer()
	tempDir := t.TempDir()

	config := common.CaptureConfig{
		CaptureWindow: 1 * time.Second,
		OutputDir:     tempDir,
		Interface:     "any",
	}

	ctx := context.Background()
	_, err := capturer.Capture(ctx, config)

	// Should fail gracefully if Npcap is not installed
	assert.Error(t, err)
}

func TestNpcapCapturer_Capture_Success(t *testing.T) {
	// Skip if Npcap is not installed
	if !IsNpcapAvailable() {
		t.Skip("Npcap not installed, skipping capture test")
	}

	capturer := NewNpcapCapturer()
	tempDir := t.TempDir()

	config := common.CaptureConfig{
		CaptureWindow: 2 * time.Second, // Short capture for testing
		OutputDir:     tempDir,
		Interface:     "any", // Use first available interface
	}

	ctx := context.Background()
	pcapFile, err := capturer.Capture(ctx, config)

	assert.NoError(t, err)
	assert.NotEmpty(t, pcapFile)
	assert.FileExists(t, pcapFile)

	// Verify PCAP file has content
	info, err := os.Stat(pcapFile)
	assert.NoError(t, err)
	assert.Greater(t, info.Size(), int64(24)) // At least PCAP header size

	// Verify file is in correct directory
	assert.Equal(t, tempDir, filepath.Dir(pcapFile))
	assert.Equal(t, ".pcap", filepath.Ext(pcapFile))
}

func TestNpcapCapturer_Capture_ContextCancellation(t *testing.T) {
	// Skip if Npcap is not installed
	if !IsNpcapAvailable() {
		t.Skip("Npcap not installed, skipping capture test")
	}

	capturer := NewNpcapCapturer()
	tempDir := t.TempDir()

	config := common.CaptureConfig{
		CaptureWindow: 30 * time.Second, // Long capture
		OutputDir:     tempDir,
		Interface:     "any",
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after 1 second
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()

	pcapFile, err := capturer.Capture(ctx, config)

	// Should return context cancellation error
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	// File should still exist (partial capture)
	assert.NotEmpty(t, pcapFile)
	assert.FileExists(t, pcapFile)
}

func TestGetDeviceNamesForInterfaces(t *testing.T) {
	// Skip if Npcap is not installed
	if !IsNpcapAvailable() {
		t.Skip("Npcap not installed, skipping device enumeration test")
	}

	tests := []struct {
		name          string
		interfaces    []string
		shouldSucceed bool
		expectMin     int // Minimum expected devices
	}{
		{
			name:          "Single any interface",
			interfaces:    []string{"any"},
			shouldSucceed: true,
			expectMin:     1, // Should have at least one active interface
		},
		{
			name:          "Multiple specific interfaces",
			interfaces:    []string{"15", "16"},
			shouldSucceed: true,
			expectMin:     1, // At least one should resolve
		},
		{
			name:          "Mixed any and specific",
			interfaces:    []string{"any", "12"},
			shouldSucceed: true,
			expectMin:     1,
		},
		{
			name:          "Duplicate interfaces",
			interfaces:    []string{"any", "any"},
			shouldSucceed: true,
			expectMin:     1, // Should deduplicate
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devices, err := getDeviceNamesForInterfaces(tt.interfaces)

			if tt.shouldSucceed {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, len(devices), tt.expectMin)
				t.Logf("Interfaces %v mapped to %d devices", tt.interfaces, len(devices))
				for _, dev := range devices {
					t.Logf("  - %s (%s)", dev.Name, dev.Description)
				}
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestGetDeviceNameForInterface(t *testing.T) {
	// Skip if Npcap is not installed
	if !IsNpcapAvailable() {
		t.Skip("Npcap not installed, skipping device enumeration test")
	}

	tests := []struct {
		name          string
		interfaceID   string
		shouldSucceed bool
		expectMulti   bool // Expect multiple devices
	}{
		{
			name:          "any interface",
			interfaceID:   "any",
			shouldSucceed: true,
			expectMulti:   true, // Should return all active interfaces
		},
		{
			name:          "all interfaces",
			interfaceID:   "all",
			shouldSucceed: true,
			expectMulti:   true, // Should return all active interfaces
		},
		{
			name:          "numeric interface",
			interfaceID:   "12",
			shouldSucceed: true, // Should fall back to first device
			expectMulti:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devices, err := getDeviceNamesForInterface(tt.interfaceID)

			if tt.shouldSucceed {
				assert.NoError(t, err)
				assert.NotEmpty(t, devices)

				if tt.expectMulti {
					t.Logf("Interface %s mapped to %d devices", tt.interfaceID, len(devices))
					for _, dev := range devices {
						t.Logf("  - %s (%s)", dev.Name, dev.Description)
					}
				} else {
					t.Logf("Interface %s mapped to device: %s (%s)", tt.interfaceID, devices[0].Name, devices[0].Description)
				}
			} else {
				assert.Error(t, err)
			}
		})
	}
}
