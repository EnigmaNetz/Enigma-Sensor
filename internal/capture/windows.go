//go:build windows

package capture

import (
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/windows/pcap"
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// WindowsCapturer implements PacketCapturer for Windows
type WindowsCapturer struct {
	config      Config
	etlFile     string // ETL trace file
	dnsLogPath  string
	connLogPath string
	isCapturing bool
}

// NewWindowsCapturer creates a new WindowsCapturer
func NewWindowsCapturer(cfg Config) PacketCapturer {
	return &WindowsCapturer{
		config:      cfg,
		etlFile:     filepath.Join(cfg.OutputDir, "capture.etl"),
		dnsLogPath:  filepath.Join(cfg.OutputDir, "dns.log"),
		connLogPath: filepath.Join(cfg.OutputDir, "conn.log"),
	}
}

// StartCapture begins packet capture using pktmon
func (w *WindowsCapturer) StartCapture() error {
	if w.isCapturing {
		return fmt.Errorf("capture already in progress")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(w.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Start pktmon capture with filters for DNS and connection tracking
	cmd := exec.Command("pktmon", "start", "--capture",
		"-f", w.etlFile,
		"--flags", "Ethernet+IP+TCP+UDP+DNS",
		"--file-size", "100MB")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start pktmon: %v", err)
	}

	w.isCapturing = true

	// Wait for configured duration
	time.Sleep(time.Duration(w.config.CaptureWindow) * time.Second)

	// Stop capture
	return w.StopCapture()
}

// StopCapture ends the current capture session and processes logs
func (w *WindowsCapturer) StopCapture() error {
	if !w.isCapturing {
		return nil
	}

	// Stop pktmon
	cmd := exec.Command("pktmon", "stop")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop pktmon: %v", err)
	}

	w.isCapturing = false

	// Format the ETL file into text
	formatCmd := exec.Command("pktmon", "format", w.etlFile, "-o", w.etlFile+".txt")
	if err := formatCmd.Run(); err != nil {
		return fmt.Errorf("failed to format ETL: %v", err)
	}

	// Process the formatted output into our required log files
	return w.processLogs(w.etlFile + ".txt")
}

// OutputFiles returns paths to the log files
func (w *WindowsCapturer) OutputFiles() (string, string, error) {
	// Check if files exist
	if _, err := os.Stat(w.dnsLogPath); err != nil {
		return "", "", fmt.Errorf("dns.log not found: %v", err)
	}
	if _, err := os.Stat(w.connLogPath); err != nil {
		return "", "", fmt.Errorf("conn.log not found: %v", err)
	}
	return w.dnsLogPath, w.connLogPath, nil
}

// processLogs converts pktmon output to dns.log and conn.log format
func (w *WindowsCapturer) processLogs(inputFile string) error {
	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer input.Close()

	dnsFile, err := os.Create(w.dnsLogPath)
	if err != nil {
		return fmt.Errorf("failed to create dns log: %v", err)
	}
	defer dnsFile.Close()

	connFile, err := os.Create(w.connLogPath)
	if err != nil {
		return fmt.Errorf("failed to create conn log: %v", err)
	}
	defer connFile.Close()

	// Write headers
	fmt.Fprintln(dnsFile, "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqclass\tqtype\trcode\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected")
	fmt.Fprintln(connFile, "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents")

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()

		// Process DNS packets
		if strings.Contains(line, "DNS") {
			processDNSLine(line, dnsFile)
		}

		// Process TCP/UDP connections
		if strings.Contains(line, "TCP") || strings.Contains(line, "UDP") {
			processConnLine(line, connFile)
		}
	}

	return scanner.Err()
}

func processDNSLine(line string, output *os.File) {
	// Example pktmon DNS line:
	// [timestamp] DNS Request from 192.168.1.100:12345 to 8.8.8.8:53 Query: example.com Type: A

	fields := strings.Fields(line)
	if len(fields) < 10 {
		return // Skip malformed lines
	}

	var entry struct {
		Timestamp string
		SrcIP     string
		SrcPort   string
		DstIP     string
		DstPort   string
		Query     string
		Type      string
	}

	// Parse timestamp (in brackets)
	entry.Timestamp = strings.Trim(fields[0], "[]")

	// Parse source and destination
	for i, field := range fields {
		if field == "from" && i+1 < len(fields) {
			parts := strings.Split(fields[i+1], ":")
			if len(parts) == 2 {
				entry.SrcIP = parts[0]
				entry.SrcPort = parts[1]
			}
		}
		if field == "to" && i+1 < len(fields) {
			parts := strings.Split(fields[i+1], ":")
			if len(parts) == 2 {
				entry.DstIP = parts[0]
				entry.DstPort = parts[1]
			}
		}
		if field == "Query:" && i+1 < len(fields) {
			entry.Query = strings.TrimRight(fields[i+1], ".")
		}
		if field == "Type:" && i+1 < len(fields) {
			entry.Type = fields[i+1]
		}
	}

	// Write in Zeek dns.log format
	fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%s\tUDP\t-\t%s\t-\t%s\t-\tF\tF\tT\tF\t0\t-\t-\tF\n",
		entry.Timestamp,
		entry.SrcIP,
		entry.SrcPort,
		entry.DstIP,
		entry.DstPort,
		entry.Query,
		entry.Type)
}

func processConnLine(line string, output *os.File) {
	// Example pktmon connection line:
	// [timestamp] TCP Connection from 192.168.1.100:12345 to 10.0.0.1:443 Bytes: 1234/5678

	fields := strings.Fields(line)
	if len(fields) < 10 {
		return // Skip malformed lines
	}

	var entry struct {
		Timestamp string
		Proto     string
		SrcIP     string
		SrcPort   string
		DstIP     string
		DstPort   string
		OrigBytes string
		RespBytes string
		Duration  string
	}

	// Parse timestamp (in brackets)
	entry.Timestamp = strings.Trim(fields[0], "[]")
	entry.Proto = fields[1]

	// Parse source and destination
	for i, field := range fields {
		if field == "from" && i+1 < len(fields) {
			parts := strings.Split(fields[i+1], ":")
			if len(parts) == 2 {
				entry.SrcIP = parts[0]
				entry.SrcPort = parts[1]
			}
		}
		if field == "to" && i+1 < len(fields) {
			parts := strings.Split(fields[i+1], ":")
			if len(parts) == 2 {
				entry.DstIP = parts[0]
				entry.DstPort = parts[1]
			}
		}
		if field == "Bytes:" && i+1 < len(fields) {
			parts := strings.Split(fields[i+1], "/")
			if len(parts) == 2 {
				entry.OrigBytes = parts[0]
				entry.RespBytes = parts[1]
			}
		}
		if field == "Duration:" && i+1 < len(fields) {
			entry.Duration = strings.TrimRight(fields[i+1], "s")
		}
	}

	// Write in Zeek conn.log format
	fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%s\t%s\t-\t%s\t%s\t%s\tS0\tF\tF\t0\t-\t-\t-\t-\t-\t-\n",
		entry.Timestamp,
		entry.SrcIP,
		entry.SrcPort,
		entry.DstIP,
		entry.DstPort,
		entry.Proto,
		entry.Duration,
		entry.OrigBytes,
		entry.RespBytes)
}

// NewPcapParser creates a new pcap parser instance
func NewPcapParser(filePath string, outputDir string) *pcap.PcapParser {
	return pcap.NewPcapParser(filePath, outputDir)
}
