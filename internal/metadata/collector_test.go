package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateMetadata(t *testing.T) {
	testNetworkID := "Test-Network-01"
	metadata := GenerateMetadata(testNetworkID)

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
