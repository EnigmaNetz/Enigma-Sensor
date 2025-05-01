package capture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPcapParser_ProcessFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		wantErr  bool
	}{
		{
			name:     "Valid pcap file",
			filePath: filepath.Join("..", "..", "test", "package-capture.pcapng"),
			wantErr:  false,
		},
		{
			name:     "Non-existent file",
			filePath: "nonexistent.pcap",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create output directory
			outputDir := filepath.Join(t.TempDir(), "zeek_logs")
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				t.Fatalf("Failed to create output directory: %v", err)
			}

			// Create parser with output directory
			parser := NewPcapParser(tt.filePath, outputDir)
			stats, err := parser.ProcessFile()

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Skip validation for error cases
			if tt.wantErr {
				if stats != nil {
					t.Error("Expected nil stats for error case")
				}
				return
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

			// Check for common protocols
			commonProtocols := []string{"IPv4", "TCP", "UDP", "Ethernet"}
			for _, proto := range commonProtocols {
				if count := stats.ProtocolCounts[proto]; count == 0 {
					t.Errorf("Expected to find protocol %s but found none", proto)
				}
			}

			// Check if Zeek log files were created
			logFiles := []string{"conn.log", "dns.log"}
			for _, logFile := range logFiles {
				logPath := filepath.Join(outputDir, logFile)
				if _, err := os.Stat(logPath); os.IsNotExist(err) {
					t.Errorf("Expected log file %s was not created", logFile)
					continue
				}

				// Check if files have content
				info, err := os.Stat(logPath)
				if err != nil {
					t.Errorf("Failed to stat log file %s: %v", logFile, err)
					continue
				}
				if info.Size() == 0 {
					t.Errorf("Log file %s is empty", logFile)
					continue
				}

				// Read and log first few lines of each file
				content, err := os.ReadFile(logPath)
				if err != nil {
					t.Errorf("Failed to read log file %s: %v", logFile, err)
					continue
				}
				t.Logf("%s content (first 500 bytes): %s", logFile, string(content[:min(500, len(content))]))
			}

			// Log stats for manual verification
			t.Logf("Packet Statistics:\n%s", stats)
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestPacketStats_String(t *testing.T) {
	stats := &PacketStats{
		TotalPackets: 100,
		TotalBytes:   1500,
		ProtocolCounts: map[string]uint64{
			"TCP": 60,
			"UDP": 40,
		},
	}

	output := stats.String()
	if output == "" {
		t.Error("Expected non-empty string representation")
	}
	t.Logf("String representation:\n%s", output)
}
