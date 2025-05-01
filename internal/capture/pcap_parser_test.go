package capture

import (
	"path/filepath"
	"testing"
)

func TestPcapParser_ProcessFile(t *testing.T) {
	tests := []struct {
		name          string
		filePath      string
		wantErr       bool
		validateStats func(*testing.T, *PacketStats)
	}{
		{
			name:     "Valid pcap file",
			filePath: filepath.Join("..", "..", "test", "package-capture.pcapng"),
			wantErr:  false,
			validateStats: func(t *testing.T, stats *PacketStats) {
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

				// Log stats for manual verification
				t.Logf("Packet Statistics:\n%s", stats)
			},
		},
		{
			name:     "Non-existent file",
			filePath: "nonexistent.pcap",
			wantErr:  true,
			validateStats: func(t *testing.T, stats *PacketStats) {
				if stats != nil {
					t.Error("Expected nil stats for non-existent file")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewPcapParser(tt.filePath)
			stats, err := parser.ProcessFile()

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Validate stats if provided
			if tt.validateStats != nil {
				tt.validateStats(t, stats)
			}
		})
	}
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
