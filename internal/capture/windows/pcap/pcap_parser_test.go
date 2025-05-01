package pcap

import (
	"path/filepath"
	"testing"
)

func TestPcapParser_ProcessFile(t *testing.T) {
	// Create temp output directory for Zeek logs
	tempDir := t.TempDir()

	// Test file path - adjust relative path to test data
	testFile := filepath.Join("test", "data", "package-capture.pcapng")

	parser := NewPcapParser(testFile, tempDir)
	stats, err := parser.ProcessFile()
	if err != nil {
		t.Fatalf("Failed to process pcap file: %v", err)
	}

	// Basic validation
	if stats.TotalPackets == 0 {
		t.Error("Expected non-zero packet count")
	}
	if stats.TotalBytes == 0 {
		t.Error("Expected non-zero byte count")
	}
	if len(stats.ProtocolCounts) == 0 {
		t.Error("Expected at least one protocol")
	}

	// Log stats for manual verification
	t.Logf("Packet Statistics:\n%s", stats)
}
