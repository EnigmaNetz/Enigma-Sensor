// Package pcap provides platform-agnostic PCAP processing functionality
package pcap

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	TS            time.Time `json:"ts"`
	UID           string    `json:"uid"`
	SrcIP         string    `json:"id.orig_h"`
	SrcPort       uint16    `json:"id.orig_p"`
	DstIP         string    `json:"id.resp_h"`
	DstPort       uint16    `json:"id.resp_p"`
	Proto         string    `json:"proto"`
	Service       string    `json:"service"`
	Duration      float64   `json:"duration"`
	OrigBytes     int64     `json:"orig_bytes"`
	RespBytes     int64     `json:"resp_bytes"`
	ConnState     string    `json:"conn_state"`
	LocalOrig     bool      `json:"local_orig"`
	LocalResp     bool      `json:"local_resp"`
	MissedBytes   int64     `json:"missed_bytes"`
	History       string    `json:"history"`
	OrigPkts      int64     `json:"orig_pkts"`
	OrigIPBytes   int64     `json:"orig_ip_bytes"`
	RespPkts      int64     `json:"resp_pkts"`
	RespIPBytes   int64     `json:"resp_ip_bytes"`
	TunnelParents []string  `json:"tunnel_parents"`
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
	var srcIP, dstIP string
	var ipBytes int64

	// Try IPv4 first
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ip := ipv4Layer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ipBytes = int64(len(ip.Contents) + len(ip.Payload))
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		// Try IPv6
		ip := ipv6Layer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ipBytes = int64(len(ip.Contents) + len(ip.Payload))
	} else {
		// No IP layer found
		return
	}

	// Determine if IPs are local (private) addresses
	localOrig := isLocalIP(srcIP)
	localResp := isLocalIP(dstIP)

	// Build connection history string
	history := buildTCPHistory(tcp)

	connLog := ConnLog{
		TS:            packet.Metadata().Timestamp,
		UID:           generateUID(srcIP, uint16(tcp.SrcPort), dstIP, uint16(tcp.DstPort), "tcp", packet.Metadata().Timestamp),
		SrcIP:         srcIP,
		SrcPort:       uint16(tcp.SrcPort),
		DstIP:         dstIP,
		DstPort:       uint16(tcp.DstPort),
		Proto:         "tcp",
		Service:       determineService(uint16(tcp.DstPort)),
		Duration:      0, // Will be calculated when connection ends
		OrigBytes:     int64(len(tcp.Payload)),
		RespBytes:     0, // Will be updated when response is received
		ConnState:     getConnState(tcp),
		LocalOrig:     localOrig,
		LocalResp:     localResp,
		MissedBytes:   0,
		History:       history,
		OrigPkts:      1,
		OrigIPBytes:   ipBytes,
		RespPkts:      0,
		RespIPBytes:   0,
		TunnelParents: []string{},
	}
	p.connLogs = append(p.connLogs, connLog)
}

func (p *PcapParser) processUDPPacket(packet gopacket.Packet, udp *layers.UDP) {
	var srcIP, dstIP string
	var ipBytes int64

	// Try IPv4 first
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ip := ipv4Layer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ipBytes = int64(len(ip.Contents) + len(ip.Payload))
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		// Try IPv6
		ip := ipv6Layer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ipBytes = int64(len(ip.Contents) + len(ip.Payload))
	} else {
		// No IP layer found
		return
	}

	// Determine if IPs are local (private) addresses
	localOrig := isLocalIP(srcIP)
	localResp := isLocalIP(dstIP)

	connLog := ConnLog{
		TS:            packet.Metadata().Timestamp,
		UID:           generateUID(srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort), "udp", packet.Metadata().Timestamp),
		SrcIP:         srcIP,
		SrcPort:       uint16(udp.SrcPort),
		DstIP:         dstIP,
		DstPort:       uint16(udp.DstPort),
		Proto:         "udp",
		Service:       determineService(uint16(udp.DstPort)),
		Duration:      0,
		OrigBytes:     int64(len(udp.Payload)),
		RespBytes:     0,
		ConnState:     "SF", // UDP is stateless
		LocalOrig:     localOrig,
		LocalResp:     localResp,
		MissedBytes:   0,
		History:       "Dd", // Default UDP history
		OrigPkts:      1,
		OrigIPBytes:   ipBytes,
		RespPkts:      0,
		RespIPBytes:   0,
		TunnelParents: []string{},
	}
	p.connLogs = append(p.connLogs, connLog)
}

func (p *PcapParser) processDNSPacket(packet gopacket.Packet, dns *layers.DNS) {
	var srcIP, dstIP string

	// Try IPv4 first
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ip := ipv4Layer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		// Try IPv6
		ip := ipv6Layer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		// No IP layer found
		return
	}

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
			UID:     generateUID(srcIP, srcPort, dstIP, dstPort, "udp", packet.Metadata().Timestamp),
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
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
	// Write conn.xlsx
	connPath := filepath.Join(p.outDir, "conn.xlsx")
	if err := p.writeLogFile(connPath, p.connLogs); err != nil {
		return fmt.Errorf("failed to write conn.xlsx: %v", err)
	}

	// Write dns.xlsx
	dnsPath := filepath.Join(p.outDir, "dns.xlsx")
	if err := p.writeLogFile(dnsPath, p.dnsLogs); err != nil {
		return fmt.Errorf("failed to write dns.xlsx: %v", err)
	}

	return nil
}

func (p *PcapParser) writeLogFile(path string, logs interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)

	// Write headers
	writer.WriteString("#separator \\x09\n")
	writer.WriteString("#set_separator\t,\n")
	writer.WriteString("#empty_field\t(empty)\n")
	writer.WriteString("#unset_field\t-\n")

	switch v := logs.(type) {
	case []ConnLog:
		writer.WriteString("#path\tconn\n")
		writer.WriteString("#open\t" + time.Now().Format("2006-01-02-15-04-05") + "\n")
		writer.WriteString("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n")
		writer.WriteString("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n")

		for _, log := range v {
			tunnelParents := "-"
			if len(log.TunnelParents) > 0 {
				tunnelParents = strings.Join(log.TunnelParents, ",")
			}

			service := "-"
			if log.Service != "" {
				service = log.Service
			}

			// Convert boolean values to T/F
			localOrig := "F"
			if log.LocalOrig {
				localOrig = "T"
			}
			localResp := "F"
			if log.LocalResp {
				localResp = "T"
			}

			// Format timestamp to match example (unix timestamp with microsecond precision)
			ts := float64(log.TS.UnixNano()) / 1e9

			line := fmt.Sprintf("%.6f\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%.6f\t%d\t%d\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\n",
				ts,
				log.UID,
				log.SrcIP,
				log.SrcPort,
				log.DstIP,
				log.DstPort,
				log.Proto,
				service,
				log.Duration,
				log.OrigBytes,
				log.RespBytes,
				log.ConnState,
				localOrig,
				localResp,
				log.MissedBytes,
				log.History,
				log.OrigPkts,
				log.OrigIPBytes,
				log.RespPkts,
				log.RespIPBytes,
				tunnelParents)
			writer.WriteString(line)
		}

	case []DNSLog:
		writer.WriteString("#path\tdns\n")
		writer.WriteString("#open\t" + time.Now().Format("2006-01-02-15-04-05") + "\n")
		writer.WriteString("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqclass\tqtype\tanswers\tttls\trcode\taa\ttc\trd\tra\n")
		writer.WriteString("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tcount\tstring\tvector[string]\tvector[interval]\tcount\tbool\tbool\tbool\tbool\n")

		for _, log := range v {
			answers := "-"
			if len(log.Answers) > 0 {
				answers = strings.Join(log.Answers, ",")
			}

			ttls := "-"
			if len(log.TTLs) > 0 {
				ttlStrs := make([]string, len(log.TTLs))
				for i, ttl := range log.TTLs {
					ttlStrs[i] = fmt.Sprintf("%.6f", ttl)
				}
				ttls = strings.Join(ttlStrs, ",")
			}

			// Convert boolean values to T/F
			aa := "F"
			if log.AA {
				aa = "T"
			}
			tc := "F"
			if log.TC {
				tc = "T"
			}
			rd := "F"
			if log.RD {
				rd = "T"
			}
			ra := "F"
			if log.RA {
				ra = "T"
			}

			// Format timestamp to match example
			ts := float64(log.TS.UnixNano()) / 1e9

			line := fmt.Sprintf("%.6f\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				ts,
				log.UID,
				log.SrcIP,
				log.SrcPort,
				log.DstIP,
				log.DstPort,
				log.Proto,
				log.TransID,
				log.Query,
				log.QClass,
				log.QType,
				answers,
				ttls,
				log.Rcode,
				aa,
				tc,
				rd,
				ra)
			writer.WriteString(line)
		}
	}

	return writer.Flush()
}

// Helper functions
func generateUID(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string, ts time.Time) string {
	// Create a unique string from the connection tuple
	connTuple := fmt.Sprintf("%s-%d-%s-%d-%s-%d",
		srcIP, srcPort,
		dstIP, dstPort,
		proto, ts.UnixNano())

	// Generate SHA-1 hash of the connection tuple
	h := sha1.New()
	h.Write([]byte(connTuple))
	hash := h.Sum(nil)

	// Format as C[hex] to match Zeek format
	return fmt.Sprintf("C%x", hash)[:17] // Keep consistent 17-char length
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

func isLocalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is private
	if parsedIP.IsPrivate() || parsedIP.IsLoopback() {
		return true
	}

	// Check common private CIDR ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func buildTCPHistory(tcp *layers.TCP) string {
	var history strings.Builder

	if tcp.SYN {
		history.WriteString("S")
	}
	if tcp.ACK {
		history.WriteString("A")
	}
	if len(tcp.Payload) > 0 {
		history.WriteString("D")
	}
	if tcp.FIN {
		history.WriteString("F")
	}
	if tcp.RST {
		history.WriteString("R")
	}

	return history.String()
}

func determineService(port uint16) string {
	// Common port to service mappings
	switch port {
	case 80:
		return "http"
	case 443:
		return "https"
	case 53:
		return "dns"
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 25:
		return "smtp"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	default:
		return "-"
	}
}
