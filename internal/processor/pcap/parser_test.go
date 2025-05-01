package pcap

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPcapParser(t *testing.T) {
	parser := NewPcapParser("test.pcap", "output")
	assert.NotNil(t, parser)
	assert.Equal(t, "test.pcap", parser.filePath)
	assert.Equal(t, "output", parser.outDir)
	assert.Empty(t, parser.connLogs)
	assert.Empty(t, parser.dnsLogs)
}

func TestProcessFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "pcap_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("NonExistentFile", func(t *testing.T) {
		parser := NewPcapParser("nonexistent.pcap", tempDir)
		stats, err := parser.ProcessFile()
		assert.Error(t, err)
		assert.Nil(t, stats)
	})

	// Note: Add more test cases with actual PCAP data when test data is available
}

func TestProcessTCPPacket(t *testing.T) {
	parser := NewPcapParser("", "")

	// Create a mock packet with TCP layer
	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 1},
		DstIP: []byte{192, 168, 1, 2},
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		SYN:     true,
	}

	// Mock the necessary layers
	mockPacket := &mockPacket{
		layers: []gopacket.Layer{ip, tcp},
		metadata: &gopacket.PacketMetadata{
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp: time.Now(),
			},
		},
	}

	parser.processTCPPacket(mockPacket, tcp)

	assert.Len(t, parser.connLogs, 1)
	log := parser.connLogs[0]
	assert.Equal(t, "192.168.1.1", log.SrcIP)
	assert.Equal(t, uint16(12345), log.SrcPort)
	assert.Equal(t, "192.168.1.2", log.DstIP)
	assert.Equal(t, uint16(80), log.DstPort)
	assert.Equal(t, "tcp", log.Proto)
}

func TestProcessUDPPacket(t *testing.T) {
	parser := NewPcapParser("", "")

	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 1},
		DstIP: []byte{192, 168, 1, 2},
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(53),
		DstPort: layers.UDPPort(12345),
	}

	mockPacket := &mockPacket{
		layers: []gopacket.Layer{ip, udp},
		metadata: &gopacket.PacketMetadata{
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp: time.Now(),
			},
		},
	}

	parser.processUDPPacket(mockPacket, udp)

	assert.Len(t, parser.connLogs, 1)
	log := parser.connLogs[0]
	assert.Equal(t, "192.168.1.1", log.SrcIP)
	assert.Equal(t, uint16(53), log.SrcPort)
	assert.Equal(t, "192.168.1.2", log.DstIP)
	assert.Equal(t, uint16(12345), log.DstPort)
	assert.Equal(t, "udp", log.Proto)
}

func TestProcessDNSPacket(t *testing.T) {
	parser := NewPcapParser("", "")

	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 1},
		DstIP: []byte{8, 8, 8, 8},
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(53),
	}
	dns := &layers.DNS{
		ID:           1234,
		QR:           true,
		OpCode:       0,
		AA:           true,
		TC:           false,
		RD:           true,
		RA:           true,
		ResponseCode: 0,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300,
				IP:    []byte{93, 184, 216, 34},
			},
		},
	}

	mockPacket := &mockPacket{
		layers: []gopacket.Layer{ip, udp, dns},
		metadata: &gopacket.PacketMetadata{
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp: time.Now(),
			},
		},
	}

	parser.processDNSPacket(mockPacket, dns)

	assert.Len(t, parser.dnsLogs, 1)
	log := parser.dnsLogs[0]
	assert.Equal(t, "192.168.1.1", log.SrcIP)
	assert.Equal(t, uint16(12345), log.SrcPort)
	assert.Equal(t, "8.8.8.8", log.DstIP)
	assert.Equal(t, uint16(53), log.DstPort)
	assert.Equal(t, "udp", log.Proto)
	assert.Equal(t, uint16(1234), log.TransID)
	assert.Equal(t, "example.com", log.Query)
	assert.Equal(t, uint16(layers.DNSClassIN), log.QClass)
	assert.Equal(t, "A", log.QType)
	assert.Equal(t, []string{"93.184.216.34"}, log.Answers)
	assert.Equal(t, []float64{300}, log.TTLs)
	assert.True(t, log.AA)
	assert.False(t, log.TC)
	assert.True(t, log.RD)
	assert.True(t, log.RA)
}

func TestWriteLogs(t *testing.T) {
	// Create a temporary directory for test output with Windows-compatible path
	tempDir := filepath.Join(".", fmt.Sprintf("pcap_logs_test_%d", time.Now().UnixNano()))
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	parser := NewPcapParser("", tempDir)

	// Add some test logs
	parser.connLogs = []ConnLog{{
		TS:        time.Now(),
		UID:       "test-uid",
		SrcIP:     "192.168.1.1",
		SrcPort:   12345,
		DstIP:     "192.168.1.2",
		DstPort:   80,
		Proto:     "tcp",
		Duration:  1.5,
		OrigBytes: 100,
		ConnState: "S0",
	}}

	parser.dnsLogs = []DNSLog{{
		TS:      time.Now(),
		UID:     "test-uid",
		SrcIP:   "192.168.1.1",
		SrcPort: 12345,
		DstIP:   "8.8.8.8",
		DstPort: 53,
		Proto:   "udp",
		Query:   "example.com",
	}}

	err = parser.writeLogs()
	require.NoError(t, err)

	// Verify conn.xlsx exists and has content
	connLogPath := filepath.Join(tempDir, "conn.xlsx")
	assert.FileExists(t, connLogPath)
	connLogData, err := os.ReadFile(connLogPath)
	require.NoError(t, err)
	assert.NotEmpty(t, connLogData)

	// Verify dns.xlsx exists and has content
	dnsLogPath := filepath.Join(tempDir, "dns.xlsx")
	assert.FileExists(t, dnsLogPath)
	dnsLogData, err := os.ReadFile(dnsLogPath)
	require.NoError(t, err)
	assert.NotEmpty(t, dnsLogData)

	// Verify the files contain the expected headers and data format
	connLines := strings.Split(string(connLogData), "\n")
	hasFields := false
	for _, line := range connLines {
		if strings.HasPrefix(line, "#fields") {
			hasFields = true
			break
		}
	}
	assert.True(t, hasFields, "conn.xlsx should have a #fields line")
	assert.True(t, len(connLines) > 7, "Should have headers and at least one data line")

	dnsLines := strings.Split(string(dnsLogData), "\n")
	hasFields = false
	for _, line := range dnsLines {
		if strings.HasPrefix(line, "#fields") {
			hasFields = true
			break
		}
	}
	assert.True(t, hasFields, "dns.xlsx should have a #fields line")
	assert.True(t, len(dnsLines) > 7, "Should have headers and at least one data line")
}

// Mock packet for testing
type mockPacket struct {
	layers   []gopacket.Layer
	metadata *gopacket.PacketMetadata
}

func (m *mockPacket) String() string           { return "" }
func (m *mockPacket) Dump() string             { return "" }
func (m *mockPacket) Layers() []gopacket.Layer { return m.layers }
func (m *mockPacket) Layer(t gopacket.LayerType) gopacket.Layer {
	for _, l := range m.layers {
		if l.LayerType() == t {
			return l
		}
	}
	return nil
}
func (m *mockPacket) LayerClass(c gopacket.LayerClass) gopacket.Layer { return nil }
func (m *mockPacket) Metadata() *gopacket.PacketMetadata              { return m.metadata }
func (m *mockPacket) Data() []byte                                    { return nil }
func (m *mockPacket) ApplicationLayer() gopacket.ApplicationLayer     { return nil }
func (m *mockPacket) ErrorLayer() gopacket.ErrorLayer                 { return nil }
func (m *mockPacket) LinkLayer() gopacket.LinkLayer                   { return nil }
func (m *mockPacket) NetworkLayer() gopacket.NetworkLayer             { return nil }
func (m *mockPacket) TransportLayer() gopacket.TransportLayer         { return nil }

func TestProcessTCPPacketIPv6(t *testing.T) {
	parser := NewPcapParser("", "")

	// Create a mock packet with TCP layer and IPv6
	ipv6 := &layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       20,
		NextHeader:   layers.IPProtocolTCP,
		HopLimit:     64,
		SrcIP:        net.ParseIP("2001:db8::1"),
		DstIP:        net.ParseIP("2001:db8::2"),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		SYN:     true,
	}

	mockPacket := &mockPacket{
		layers: []gopacket.Layer{ipv6, tcp},
		metadata: &gopacket.PacketMetadata{
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp: time.Now(),
			},
		},
	}

	parser.processTCPPacket(mockPacket, tcp)

	require.Len(t, parser.connLogs, 1)
	log := parser.connLogs[0]
	assert.Equal(t, "2001:db8::1", log.SrcIP)
	assert.Equal(t, uint16(12345), log.SrcPort)
	assert.Equal(t, "2001:db8::2", log.DstIP)
	assert.Equal(t, uint16(80), log.DstPort)
	assert.Equal(t, "tcp", log.Proto)
}

func TestProcessDNSPacketErrors(t *testing.T) {
	parser := NewPcapParser("", "")

	t.Run("Missing IP Layer", func(t *testing.T) {
		dns := &layers.DNS{
			Questions: []layers.DNSQuestion{{
				Name: []byte("example.com"),
			}},
		}
		mockPacket := &mockPacket{
			layers: []gopacket.Layer{dns},
			metadata: &gopacket.PacketMetadata{
				CaptureInfo: gopacket.CaptureInfo{
					Timestamp: time.Now(),
				},
			},
		}
		parser.processDNSPacket(mockPacket, dns)
		assert.Empty(t, parser.dnsLogs)
	})

	t.Run("Malformed DNS Answer", func(t *testing.T) {
		ip := &layers.IPv4{
			SrcIP: []byte{192, 168, 1, 1},
			DstIP: []byte{8, 8, 8, 8},
		}
		dns := &layers.DNS{
			Questions: []layers.DNSQuestion{{
				Name: []byte("example.com"),
				Type: layers.DNSTypeA,
			}},
			Answers: []layers.DNSResourceRecord{{
				Type: layers.DNSTypeA,
				IP:   nil, // Invalid IP
			}},
		}
		mockPacket := &mockPacket{
			layers: []gopacket.Layer{ip, dns},
			metadata: &gopacket.PacketMetadata{
				CaptureInfo: gopacket.CaptureInfo{
					Timestamp: time.Now(),
				},
			},
		}
		parser.processDNSPacket(mockPacket, dns)
		assert.Len(t, parser.dnsLogs, 1)
		assert.Empty(t, parser.dnsLogs[0].Answers)
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("Empty_PCAP_File", func(t *testing.T) {
		tempDir := filepath.Join(".", fmt.Sprintf("pcap_test_%d", time.Now().UnixNano()))
		err := os.MkdirAll(tempDir, 0755)
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		emptyFile := filepath.Join(tempDir, "empty.pcap")
		err = os.WriteFile(emptyFile, []byte{}, 0644)
		require.NoError(t, err)

		parser := NewPcapParser(emptyFile, tempDir)
		stats, err := parser.ProcessFile()
		assert.Error(t, err) // Should error on invalid PCAP file
		assert.Nil(t, stats) // Stats should be nil when there's an error
	})

	t.Run("Invalid_Output_Directory", func(t *testing.T) {
		parser := NewPcapParser("test.pcap", "/nonexistent/directory")
		err := parser.writeLogs()
		assert.Error(t, err)
	})

	t.Run("Large_Number_of_Logs", func(t *testing.T) {
		tempDir := filepath.Join(".", fmt.Sprintf("pcap_test_%d", time.Now().UnixNano()))
		err := os.MkdirAll(tempDir, 0755)
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		parser := NewPcapParser("", tempDir)

		// Add a large number of test logs
		for i := 0; i < 1000; i++ {
			parser.connLogs = append(parser.connLogs, ConnLog{
				TS:    time.Now(),
				UID:   fmt.Sprintf("test-uid-%d", i),
				SrcIP: "192.168.1.1",
				DstIP: "192.168.1.2",
				Proto: "tcp",
			})
		}

		err = parser.writeLogs()
		require.NoError(t, err)

		// Verify conn.xlsx exists and has content
		connLogPath := filepath.Join(tempDir, "conn.xlsx")
		assert.FileExists(t, connLogPath)
		connLogData, err := os.ReadFile(connLogPath)
		require.NoError(t, err)
		assert.NotEmpty(t, connLogData)

		// Verify the file contains the expected headers and data format
		connLines := strings.Split(string(connLogData), "\n")
		hasFields := false
		for _, line := range connLines {
			if strings.HasPrefix(line, "#fields") {
				hasFields = true
				break
			}
		}
		assert.True(t, hasFields, "conn.xlsx should have a #fields line")
		assert.True(t, len(connLines) > 1007, "Should have headers and 1000 data lines")
	})
}

func BenchmarkProcessDNSPacket(b *testing.B) {
	parser := NewPcapParser("", "")
	ip := &layers.IPv4{
		SrcIP: []byte{192, 168, 1, 1},
		DstIP: []byte{8, 8, 8, 8},
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(53),
	}
	dns := &layers.DNS{
		Questions: []layers.DNSQuestion{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
		Answers: []layers.DNSResourceRecord{{
			Type: layers.DNSTypeA,
			IP:   []byte{93, 184, 216, 34},
		}},
	}
	mockPacket := &mockPacket{
		layers: []gopacket.Layer{ip, udp, dns},
		metadata: &gopacket.PacketMetadata{
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp: time.Now(),
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.processDNSPacket(mockPacket, dns)
	}
}

func BenchmarkWriteLogs(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "pcap_bench")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	parser := NewPcapParser("", tempDir)

	// Add some test logs
	for i := 0; i < 1000; i++ {
		parser.connLogs = append(parser.connLogs, ConnLog{
			TS:    time.Now(),
			UID:   fmt.Sprintf("C%d", i),
			SrcIP: "192.168.1.1",
			DstIP: "192.168.1.2",
			Proto: "tcp",
		})
		parser.dnsLogs = append(parser.dnsLogs, DNSLog{
			TS:    time.Now(),
			UID:   fmt.Sprintf("D%d", i),
			Query: "example.com",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testDir := filepath.Join(tempDir, fmt.Sprintf("test%d", i))
		err := os.MkdirAll(testDir, 0755)
		if err != nil {
			b.Fatal(err)
		}
		parser.outDir = testDir
		if err := parser.writeLogs(); err != nil {
			b.Fatal(err)
		}
	}
}
