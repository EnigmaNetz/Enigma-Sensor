//go:build linux || darwin

package linux

import (
	"os"
	"strings"
	"testing"
)

func TestProcessPCAP(t *testing.T) {
	p := NewProcessor()

	// This test assumes Zeek is installed and a valid PCAP is available.
	// For CI, mock exec.Command or use a test fixture.
	pcapPath := "/tmp/test.pcap" // TODO: Provide a real or mock PCAP file
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("Test PCAP file not found; skipping integration test.")
	}

	result, err := p.ProcessPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ProcessPCAP failed: %v", err)
	}
	if result.ConnPath == "" || result.DNSPath == "" {
		t.Errorf("Expected non-empty XLSX paths, got: %+v", result)
	}
}

func TestZeekNotInstalled(t *testing.T) {
	_ = NewProcessor()
	// Temporarily set zeekBinary to a non-existent path (requires refactor to allow injection for true unit test)
	// This is a placeholder for how you'd test Zeek not being present.
	// t.Skip("TODO: Refactor to allow zeekBinary injection for unit test.")
}

func TestMissingLogFiles(t *testing.T) {
	_ = NewProcessor()
	// Simulate Zeek running but not producing conn.log/dns.log (requires mocking exec.Command and file system)
	// t.Skip("TODO: Mock exec.Command and file system for missing log files.")
}

func TestMetadataContent(t *testing.T) {
	p := NewProcessor()
	pcapPath := "/tmp/test.pcap"
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("Test PCAP file not found; skipping integration test.")
	}
	result, err := p.ProcessPCAP(pcapPath)
	if err != nil {
		t.Fatalf("ProcessPCAP failed: %v", err)
	}
	if _, ok := result.Metadata["zeek_out_dir"]; !ok {
		t.Error("Expected metadata to contain 'zeek_out_dir'")
	}
	if ts, ok := result.Metadata["timestamp"]; !ok || !strings.Contains(ts.(string), "T") {
		t.Error("Expected metadata to contain valid 'timestamp'")
	}
}

// TODO: Add more granular unit tests with mocks for Zeek and file conversion.
