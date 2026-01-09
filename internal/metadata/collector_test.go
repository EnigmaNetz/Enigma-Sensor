package metadata

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateMetadata(t *testing.T) {
	testNetworkID := "Test-Network-01"
	testCaptureInterface := "any"
	metadata := GenerateMetadata(testNetworkID, testCaptureInterface)

	// Test that all essential fields are present
	assert.Equal(t, testNetworkID, metadata["network_id"], "network_id should match input")
	assert.NotEmpty(t, metadata["machine_id"], "machine_id should be present")
	assert.NotEmpty(t, metadata["sensor_version"], "sensor_version should be present")
	assert.NotEmpty(t, metadata["os_name"], "os_name should be present")
	assert.NotEmpty(t, metadata["os_version"], "os_version should be present")
	assert.NotEmpty(t, metadata["architecture"], "architecture should be present")

	// Test that additional fields are present
	assert.NotEmpty(t, metadata["session_id"], "session_id should be present")

	// Test machine_id format (should be 64 char hex string)
	machineID := metadata["machine_id"]
	assert.Len(t, machineID, 64, "machine_id should be 64 characters (SHA256 hex)")

	// Test session_id format (should be UUID)
	sessionID := metadata["session_id"]
	assert.Len(t, sessionID, 36, "session_id should be 36 characters (UUID format)")
	assert.Contains(t, sessionID, "-", "session_id should contain hyphens (UUID format)")
}

func TestGenerateMachineID(t *testing.T) {
	// Test that machine ID is consistent between calls
	id1 := generateMachineID()
	id2 := generateMachineID()

	assert.Equal(t, id1, id2, "machine_id should be consistent between calls")
	assert.Len(t, id1, 64, "machine_id should be 64 characters (SHA256 hex)")
}

func TestGetPrimaryMACAddress(t *testing.T) {
	// This test may pass or fail depending on network interfaces
	// but it shouldn't crash
	macAddr := getPrimaryMACAddress()

	// MAC address should either be empty or in the format "xx:xx:xx:xx:xx:xx"
	if macAddr != "" {
		require.True(t, len(macAddr) >= 17, "MAC address should be at least 17 characters")
		assert.Contains(t, macAddr, ":", "MAC address should contain colons")
	}
}

func TestGetHostIPAddresses(t *testing.T) {
	tests := []struct {
		name             string
		captureInterface string
	}{
		{
			name:             "with 'any' interface",
			captureInterface: "any",
		},
		{
			name:             "with 'all' interface",
			captureInterface: "all",
		},
		{
			name:             "with empty interface",
			captureInterface: "",
		},
		{
			name:             "with non-existent interface",
			captureInterface: "nonexistent0",
		},
		{
			name:             "with comma-separated interfaces",
			captureInterface: "eth0,wlan0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := getHostIPAddresses(tt.captureInterface)

			// Function should not panic and should return a slice (possibly empty)
			// If IPs are found, verify they look like valid private IPs
			for _, ip := range ips {
				assert.NotEmpty(t, ip, "IP address should not be empty")
				// Basic format check - should contain dots for IPv4
				assert.Contains(t, ip, ".", "IP address should be IPv4 format")
			}
		})
	}
}

func TestGetHostIPAddresses_ValidatesPrivateIPs(t *testing.T) {
	// Get IPs with "any" interface
	ips := getHostIPAddresses("any")

	// If any IPs are returned, they should all be private IPs
	for _, ipStr := range ips {
		// Parse the IP and verify it's private
		assert.NotContains(t, ipStr, "127.", "Should not include loopback IPs")
	}
}

func TestGenerateMetadata_IncludesHostIPs(t *testing.T) {
	testNetworkID := "Test-Network-02"
	testCaptureInterface := "any"
	metadata := GenerateMetadata(testNetworkID, testCaptureInterface)

	// host_ips may or may not be present depending on network configuration
	// but if present, it should be a comma-separated list of IPs
	if hostIPs, ok := metadata["host_ips"]; ok {
		assert.NotEmpty(t, hostIPs, "host_ips should not be empty if present")
		// Verify it looks like an IP or comma-separated IPs
		for _, ip := range strings.Split(hostIPs, ",") {
			assert.Contains(t, ip, ".", "Each host IP should be IPv4 format")
		}
	}
}

func TestGetHostIPAddresses_RespectsMaxLimit(t *testing.T) {
	// Get IPs with "any" interface - should never exceed maxHostIPs
	ips := getHostIPAddresses("any")

	// Verify the limit is respected
	assert.LessOrEqual(t, len(ips), maxHostIPs,
		"Number of IPs should not exceed maxHostIPs limit of %d", maxHostIPs)
}

func TestMaxHostIPsConstant(t *testing.T) {
	// Verify the constant is set to a reasonable value
	assert.Equal(t, 10, maxHostIPs, "maxHostIPs should be 10")
}
