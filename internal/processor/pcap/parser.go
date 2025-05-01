// Package pcap provides platform-agnostic PCAP processing functionality
package pcap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// ConnLog represents a connection log entry
type ConnLog struct {
	TS        time.Time `json:"ts"`
	UID       string    `json:"uid"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
	Proto     string    `json:"proto"`
	Duration  float64   `json:"duration"`
	OrigBytes int64     `json:"orig_bytes"`
	ConnState string    `json:"conn_state"`
}

// DNSLog represents a DNS log entry
type DNSLog struct {
	TS      time.Time `json:"ts"`
	UID     string    `json:"uid"`
	SrcIP   string    `json:"src_ip"`
	SrcPort uint16    `json:"src_port"`
	DstIP   string    `json:"dst_ip"`
	DstPort uint16    `json:"dst_port"`
	Proto   string    `json:"proto"`
	TransID uint16    `json:"trans_id"`
	Query   string    `json:"query"`
	QClass  uint16    `json:"qclass"`
	QType   string    `json:"qtype"`
	Answers []string  `json:"answers"`
	TTLs    []float64 `json:"ttls"`
	Rcode   uint16    `json:"rcode"`
	AA      bool      `json:"aa"`
	TC      bool      `json:"tc"`
	RD      bool      `json:"rd"`
	RA      bool      `json:"ra"`
}

// PcapParser handles reading and processing pcap/pcapng files
type PcapParser struct {
	filePath string
	outDir   string
	connLogs []ConnLog
	dnsLogs  []DNSLog
}

// NewPcapParser creates a new pcap parser instance
func NewPcapParser(filePath string, outputDir string) *PcapParser {
	return &PcapParser{
		filePath: filePath,
		outDir:   outputDir,
		connLogs: make([]ConnLog, 0),
		dnsLogs:  make([]DNSLog, 0),
	}
}

// ProcessFile reads and processes a pcap file, returning packet statistics
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

	// Process packets
	for packet := range packetSource.Packets() {
		stats.TotalPackets++
		stats.TotalBytes += uint64(len(packet.Data()))

		// Count protocols at different layers
		for _, layer := range packet.Layers() {
			stats.ProtocolCounts[layer.LayerType().String()]++
		}

		// Process connection logs
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			p.processTCPPacket(packet, tcpLayer.(*layers.TCP))
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			p.processUDPPacket(packet, udpLayer.(*layers.UDP))
		}

		// Process DNS logs
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			p.processDNSPacket(packet, dnsLayer.(*layers.DNS))
		}
	}

	// Write logs
	if err := p.writeLogs(); err != nil {
		return nil, fmt.Errorf("error writing logs: %v", err)
	}

	return stats, nil
}

func (p *PcapParser) processTCPPacket(packet gopacket.Packet, tcp *layers.TCP) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	connLog := ConnLog{
		TS:        packet.Metadata().Timestamp,
		UID:       generateUID(ip, tcp),
		SrcIP:     ip.SrcIP.String(),
		SrcPort:   uint16(tcp.SrcPort),
		DstIP:     ip.DstIP.String(),
		DstPort:   uint16(tcp.DstPort),
		Proto:     "tcp",
		Duration:  0, // Will be calculated when connection ends
		OrigBytes: int64(len(tcp.Payload)),
		ConnState: getConnState(tcp),
	}
	p.connLogs = append(p.connLogs, connLog)
}

func (p *PcapParser) processUDPPacket(packet gopacket.Packet, udp *layers.UDP) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	connLog := ConnLog{
		TS:        packet.Metadata().Timestamp,
		UID:       generateUID(ip, udp),
		SrcIP:     ip.SrcIP.String(),
		SrcPort:   uint16(udp.SrcPort),
		DstIP:     ip.DstIP.String(),
		DstPort:   uint16(udp.DstPort),
		Proto:     "udp",
		Duration:  0,
		OrigBytes: int64(len(udp.Payload)),
	}
	p.connLogs = append(p.connLogs, connLog)
}

func (p *PcapParser) processDNSPacket(packet gopacket.Packet, dns *layers.DNS) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	var srcPort, dstPort uint16
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}

	for _, q := range dns.Questions {
		dnsLog := DNSLog{
			TS:      packet.Metadata().Timestamp,
			UID:     generateUID(ip, nil),
			SrcIP:   ip.SrcIP.String(),
			SrcPort: srcPort,
			DstIP:   ip.DstIP.String(),
			DstPort: dstPort,
			Proto:   "udp",
			TransID: uint16(dns.ID),
			Query:   string(q.Name),
			QClass:  uint16(q.Class),
			QType:   q.Type.String(),
			Answers: extractAnswers(dns),
			TTLs:    extractTTLs(dns),
			Rcode:   uint16(dns.ResponseCode),
			AA:      dns.AA,
			TC:      dns.TC,
			RD:      dns.RD,
			RA:      dns.RA,
		}
		p.dnsLogs = append(p.dnsLogs, dnsLog)
	}
}

func (p *PcapParser) writeLogs() error {
	// Write conn.log
	connPath := filepath.Join(p.outDir, "conn.log")
	if err := p.writeLogFile(connPath, p.connLogs); err != nil {
		return fmt.Errorf("failed to write conn.log: %v", err)
	}

	// Write dns.log
	dnsPath := filepath.Join(p.outDir, "dns.log")
	if err := p.writeLogFile(dnsPath, p.dnsLogs); err != nil {
		return fmt.Errorf("failed to write dns.log: %v", err)
	}

	return nil
}

func (p *PcapParser) writeLogFile(path string, logs interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(logs)
}

// Helper functions
func generateUID(ip *layers.IPv4, l gopacket.Layer) string {
	// Simple UID generation - in practice you might want something more sophisticated
	return fmt.Sprintf("C%d", time.Now().UnixNano())
}

func getConnState(tcp *layers.TCP) string {
	if tcp.SYN {
		return "S0"
	} else if tcp.FIN {
		return "SF"
	} else if tcp.RST {
		return "REJ"
	}
	return "OTH"
}

func extractAnswers(dns *layers.DNS) []string {
	var answers []string
	for _, answer := range dns.Answers {
		switch answer.Type {
		case layers.DNSTypeA:
			if answer.IP != nil {
				answers = append(answers, answer.IP.String())
			}
		case layers.DNSTypeAAAA:
			if answer.IP != nil {
				answers = append(answers, answer.IP.String())
			}
		case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
			if answer.CNAME != nil {
				answers = append(answers, string(answer.CNAME))
			}
		case layers.DNSTypeMX:
			if len(answer.MX.Name) > 0 {
				answers = append(answers, string(answer.MX.Name))
			}
		case layers.DNSTypeTXT:
			if answer.TXT != nil {
				answers = append(answers, string(answer.TXT[0]))
			}
		}
	}
	return answers
}

func extractTTLs(dns *layers.DNS) []float64 {
	var ttls []float64
	for _, answer := range dns.Answers {
		ttls = append(ttls, float64(answer.TTL))
	}
	return ttls
}
