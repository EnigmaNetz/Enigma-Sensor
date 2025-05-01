//go:build windows
// +build windows

package capture

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/processor/pcap"
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
		dnsLogPath:  filepath.Join(cfg.OutputDir, "dns.xlsx"),
		connLogPath: filepath.Join(cfg.OutputDir, "conn.xlsx"),
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

	log.Printf("Stopping any existing pktmon capture...")
	stopCmd := exec.Command("cmd.exe", "/c", "pktmon", "stop")
	if out, err := stopCmd.CombinedOutput(); err != nil {
		log.Printf("Warning: Failed to stop existing capture: %v\nOutput: %s", err, out)
	}

	log.Printf("Starting new pktmon capture...")
	startCmd := exec.Command("cmd.exe", "/c", "pktmon", "start", "-c", "-f", w.etlFile)
	if out, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start pktmon: %v\nOutput: %s", err, out)
	}

	w.isCapturing = true
	log.Printf("Capture started successfully. Running for %d seconds...", w.config.CaptureWindow)

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

	log.Printf("Stopping pktmon capture...")
	stopCmd := exec.Command("cmd.exe", "/c", "pktmon", "stop")
	if out, err := stopCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop pktmon: %v\nOutput: %s", err, out)
	}

	w.isCapturing = false

	log.Printf("Converting ETL to PCAPNG format...")
	pcapngFile := w.etlFile + ".pcapng"
	formatCmd := exec.Command("cmd.exe", "/c", "pktmon", "pcapng", w.etlFile, "-o", pcapngFile)
	if out, err := formatCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to convert to PCAPNG: %v\nOutput: %s", err, out)
	}

	log.Printf("Processing logs into Zeek format...")
	return w.processLogs(pcapngFile)
}

// OutputFiles returns paths to the log files
func (w *WindowsCapturer) OutputFiles() (string, string, error) {
	// Check if files exist
	if _, err := os.Stat(w.dnsLogPath); err != nil {
		return "", "", fmt.Errorf("dns.xlsx not found: %v", err)
	}
	if _, err := os.Stat(w.connLogPath); err != nil {
		return "", "", fmt.Errorf("conn.xlsx not found: %v", err)
	}
	return w.dnsLogPath, w.connLogPath, nil
}

// processLogs converts pktmon output to dns.xlsx and conn.xlsx format
func (w *WindowsCapturer) processLogs(inputFile string) error {
	log.Printf("Opening input file: %s", inputFile)

	// Create a new pcap parser
	parser := pcap.NewPcapParser(inputFile, w.config.OutputDir)
	stats, err := parser.ProcessFile()
	if err != nil {
		return fmt.Errorf("failed to parse pcap: %v", err)
	}
	log.Printf("Packet processing stats: %v", stats)

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// NewPcapParser creates a new pcap parser instance
func NewPcapParser(filePath string, outputDir string) *pcap.PcapParser {
	return pcap.NewPcapParser(filePath, outputDir)
}
