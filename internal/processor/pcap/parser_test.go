package pcap

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	// Create a temporary directory for test output
	tempDir, err := os.MkdirTemp("", "pcap_logs_test")
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

	// Verify conn.log
	connLogPath := filepath.Join(tempDir, "conn.log")
	assert.FileExists(t, connLogPath)
	connLogData, err := os.ReadFile(connLogPath)
	require.NoError(t, err)
	var connLogs []ConnLog
	err = json.Unmarshal(connLogData, &connLogs)
	require.NoError(t, err)
	assert.Len(t, connLogs, 1)

	// Verify dns.log
	dnsLogPath := filepath.Join(tempDir, "dns.log")
	assert.FileExists(t, dnsLogPath)
	dnsLogData, err := os.ReadFile(dnsLogPath)
	require.NoError(t, err)
	var dnsLogs []DNSLog
	err = json.Unmarshal(dnsLogData, &dnsLogs)
	require.NoError(t, err)
	assert.Len(t, dnsLogs, 1)
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
