//go:build windows

package windows

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripMACAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "MAC address prefix",
			input:    "2C-98-11-A1-70-7B Realtek 8851BE Wireless LAN WiFi 6 PCI-E NIC",
			expected: "Realtek 8851BE Wireless LAN WiFi 6 PCI-E NIC",
		},
		{
			name:     "No MAC address",
			input:    "Hyper-V Virtual Ethernet Adapter",
			expected: "Hyper-V Virtual Ethernet Adapter",
		},
		{
			name:     "MAC address with lowercase",
			input:    "aa-bb-cc-dd-ee-ff Some Network Adapter",
			expected: "Some Network Adapter",
		},
		{
			name:     "MAC address with mixed case",
			input:    "Aa-Bb-Cc-Dd-Ee-Ff Another Adapter",
			expected: "Another Adapter",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "MAC-like but invalid",
			input:    "ZZ-ZZ-ZZ-ZZ-ZZ-ZZ Invalid MAC",
			expected: "ZZ-ZZ-ZZ-ZZ-ZZ-ZZ Invalid MAC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripMACAddress(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Remove Microsoft prefix",
			input:    "Microsoft Wi-Fi Direct Virtual Adapter",
			expected: "wi-fi direct virtual",
		},
		{
			name:     "Remove Adapter suffix",
			input:    "Realtek PCIe GbE Family Controller",
			expected: "realtek pcie gbe family",
		},
		{
			name:     "Normalize spaces",
			input:    "Intel(R)   Ethernet    Connection",
			expected: "intel(r) ethernet connection",
		},
		{
			name:     "Lowercase conversion",
			input:    "Hyper-V Virtual Ethernet ADAPTER",
			expected: "hyper-v virtual ethernet",
		},
		{
			name:     "Combined normalization",
			input:    "Microsoft Bluetooth Device (Personal Area Network) Adapter",
			expected: "bluetooth device (personal area network)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeDescription(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePktmonCompList(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected map[string]string
	}{
		{
			name: "Standard output with MAC addresses",
			output: `Id  Component
--  ---------
15  2C-98-11-A1-70-7C Bluetooth Device (Personal Area Network)
16  2C-98-11-A1-70-7B Realtek 8851BE Wireless LAN WiFi 6 PCI-E NIC
142 CC-28-AA-44-09-28 Realtek PCIe GbE Family Controller`,
			expected: map[string]string{
				"15":  "Bluetooth Device (Personal Area Network)",
				"16":  "Realtek 8851BE Wireless LAN WiFi 6 PCI-E NIC",
				"142": "Realtek PCIe GbE Family Controller",
			},
		},
		{
			name: "Mixed MAC and no MAC",
			output: `Id  Component
--  ---------
138 00-15-5D-B7-BF-72 vEthernet (Default Switch)
140 vEthernet (WSL (Hyper-V firewall))`,
			expected: map[string]string{
				"138": "vEthernet (Default Switch)",
				"140": "vEthernet (WSL (Hyper-V firewall))",
			},
		},
		{
			name:     "Empty output",
			output:   "",
			expected: map[string]string{},
		},
		{
			name: "Header only",
			output: `Id  Component
--  ---------`,
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePktmonCompList(tt.output)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Single digit",
			input:    "5",
			expected: true,
		},
		{
			name:     "Multiple digits",
			input:    "142",
			expected: true,
		},
		{
			name:     "Zero",
			input:    "0",
			expected: true,
		},
		{
			name:     "Alphanumeric",
			input:    "12abc",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Device name",
			input:    "\\Device\\NPF_{GUID}",
			expected: false,
		},
		{
			name:     "Word",
			input:    "any",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNumeric(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterfaceMapper_TranslateToNpcapDevice(t *testing.T) {
	// Create a mock mapper with pre-populated mappings
	mapper := &InterfaceMapper{
		idToDevice: map[string]string{
			"15":  "\\Device\\NPF_{8B0D986B-6AB4-4644-AFC6-045BE9CCAB0A}",
			"16":  "\\Device\\NPF_{EFA35337-2FFF-4EE1-8B33-79FEA518CDED}",
			"142": "\\Device\\NPF_{E5D7914D-E3DC-441A-9601-33C75AE61DFA}",
		},
		idToDesc: map[string]string{
			"15":  "Bluetooth Device",
			"16":  "Realtek WiFi",
			"142": "Realtek Ethernet",
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Translate pktmon ID 15",
			input:    "15",
			expected: "\\Device\\NPF_{8B0D986B-6AB4-4644-AFC6-045BE9CCAB0A}",
		},
		{
			name:     "Translate pktmon ID 16",
			input:    "16",
			expected: "\\Device\\NPF_{EFA35337-2FFF-4EE1-8B33-79FEA518CDED}",
		},
		{
			name:     "Already Npcap device name",
			input:    "\\Device\\NPF_{SOME-GUID}",
			expected: "\\Device\\NPF_{SOME-GUID}",
		},
		{
			name:     "Unmapped ID",
			input:    "999",
			expected: "999", // Returns as-is
		},
		{
			name:     "any keyword",
			input:    "any",
			expected: "any", // Returns as-is
		},
		{
			name:     "all keyword",
			input:    "all",
			expected: "all", // Returns as-is
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.TranslateToNpcapDevice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewInterfaceMapper_Integration(t *testing.T) {
	// Skip if pktmon is not available
	mapper, err := NewInterfaceMapper()

	if err != nil {
		t.Skipf("Could not create interface mapper (pktmon or Npcap may not be available): %v", err)
	}

	assert.NotNil(t, mapper)
	assert.NotNil(t, mapper.idToDevice)
	assert.NotNil(t, mapper.idToDesc)

	t.Logf("Mapper created with %d ID mappings", len(mapper.idToDevice))

	// Log all mappings for debugging
	for id, dev := range mapper.idToDevice {
		t.Logf("  ID %s -> %s (%s)", id, dev, mapper.idToDesc[id])
	}
}
