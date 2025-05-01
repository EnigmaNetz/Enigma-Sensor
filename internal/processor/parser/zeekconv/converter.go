package zeekconv

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ZeekConverter handles conversion of packet data to Zeek log format
type ZeekConverter struct {
	connLogs []ConnLog
	dnsLogs  []DNSLog
	outDir   string
}

// NewZeekConverter creates a new ZeekConverter instance
func NewZeekConverter(outputDir string) *ZeekConverter {
	return &ZeekConverter{
		outDir:   outputDir,
		connLogs: make([]ConnLog, 0),
		dnsLogs:  make([]DNSLog, 0),
	}
}

// ProcessPacket processes a single packet and updates internal log state
func (z *ZeekConverter) ProcessPacket(packet gopacket.Packet) {
	// Process connection logs
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		z.processTCPPacket(packet, tcpLayer.(*layers.TCP))
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		z.processUDPPacket(packet, udpLayer.(*layers.UDP))
	}

	// Process DNS logs
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		z.processDNSPacket(packet, dnsLayer.(*layers.DNS))
	}
}

func (z *ZeekConverter) processTCPPacket(packet gopacket.Packet, tcp *layers.TCP) {
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
	z.connLogs = append(z.connLogs, connLog)
}

func (z *ZeekConverter) processUDPPacket(packet gopacket.Packet, udp *layers.UDP) {
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
	z.connLogs = append(z.connLogs, connLog)
}

func (z *ZeekConverter) processDNSPacket(packet gopacket.Packet, dns *layers.DNS) {
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
		z.dnsLogs = append(z.dnsLogs, dnsLog)
	}
}

// WriteLogs writes the collected logs to files in Zeek format
func (z *ZeekConverter) WriteLogs() error {
	if err := os.MkdirAll(z.outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Write conn.log
	connPath := filepath.Join(z.outDir, "conn.log")
	if err := z.writeLogFile(connPath, z.connLogs); err != nil {
		return fmt.Errorf("failed to write conn.log: %v", err)
	}

	// Write dns.log
	dnsPath := filepath.Join(z.outDir, "dns.log")
	if err := z.writeLogFile(dnsPath, z.dnsLogs); err != nil {
		return fmt.Errorf("failed to write dns.log: %v", err)
	}

	return nil
}

func (z *ZeekConverter) writeLogFile(path string, logs interface{}) error {
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
		if answer.Name != nil {
			answers = append(answers, string(answer.Name))
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
