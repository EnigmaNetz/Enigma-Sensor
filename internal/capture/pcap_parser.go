package capture

import (
	"fmt"
	"os"

	"EnigmaNetz/Enigma-Go-Agent/internal/zeekconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// PacketStats holds statistics about processed packets
type PacketStats struct {
	TotalPackets   uint64
	TotalBytes     uint64
	ProtocolCounts map[string]uint64
}

func (s PacketStats) String() string {
	return fmt.Sprintf("Total Packets: %d\nTotal Bytes: %d\nProtocol Distribution: %v",
		s.TotalPackets, s.TotalBytes, s.ProtocolCounts)
}

// PcapParser handles pcap file processing
type PcapParser struct {
	filePath string
	outDir   string
}

// NewPcapParser creates a new PcapParser instance
func NewPcapParser(filePath string, outputDir string) *PcapParser {
	return &PcapParser{
		filePath: filePath,
		outDir:   outputDir,
	}
}

// ProcessFile reads and processes a pcap file, returning packet statistics and generating Zeek logs
func (p *PcapParser) ProcessFile() (*PacketStats, error) {
	// Open the pcap file
	handle, err := os.Open(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Try pcapng format first
	var packetSource *gopacket.PacketSource
	ngReader, err := pcapgo.NewNgReader(handle, pcapgo.DefaultNgReaderOptions)
	if err == nil {
		packetSource = gopacket.NewPacketSource(ngReader, ngReader.LinkType())
	} else {
		// If not pcapng, try regular pcap
		if _, err := handle.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("error resetting file position: %v", err)
		}
		reader, err := pcapgo.NewReader(handle)
		if err != nil {
			return nil, fmt.Errorf("error creating pcap reader: %v", err)
		}
		packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	}

	stats := &PacketStats{
		ProtocolCounts: make(map[string]uint64),
	}

	// Create Zeek converter
	converter := zeekconv.NewZeekConverter(p.outDir)

	// Process packets
	for packet := range packetSource.Packets() {
		stats.TotalPackets++
		stats.TotalBytes += uint64(len(packet.Data()))

		// Count protocols at different layers
		for _, layer := range packet.Layers() {
			stats.ProtocolCounts[layer.LayerType().String()]++
		}

		// Process packet for Zeek logs
		converter.ProcessPacket(packet)
	}

	// Write Zeek logs
	if err := converter.WriteLogs(); err != nil {
		return nil, fmt.Errorf("error writing Zeek logs: %v", err)
	}

	return stats, nil
}
