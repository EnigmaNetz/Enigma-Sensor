//go:build windows
// +build windows

package capture

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/processor/pcap"
)

// WindowsCapturer implements PacketCapturer for Windows using pktmon
type WindowsCapturer struct {
	opts        CaptureOptions
	etlFile     string
	pcapngFile  string
	cmd         *exec.Cmd
	isCapturing bool
	startTime   time.Time
	result      CaptureResult
	resultChan  chan CaptureResult
	mu          sync.Mutex
}

// NewWindowsCapturer creates a new WindowsCapturer
func NewWindowsCapturer() *WindowsCapturer {
	return &WindowsCapturer{}
}

// Initialize prepares the capturer with the given options
func (w *WindowsCapturer) Initialize(opts CaptureOptions) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isCapturing {
		return fmt.Errorf("cannot initialize while capture is in progress")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	w.opts = opts
	w.etlFile = filepath.Join(opts.OutputDir, "capture.etl")
	w.pcapngFile = w.etlFile + ".pcapng"

	// Stop any existing pktmon capture
	stopCmd := exec.Command("cmd.exe", "/c", "pktmon", "stop")
	if out, err := stopCmd.CombinedOutput(); err != nil {
		log.Printf("Warning: Failed to stop existing capture: %v\nOutput: %s", err, out)
	}

	return nil
}

// StartCapture begins a packet capture session
func (w *WindowsCapturer) StartCapture() (<-chan CaptureResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isCapturing {
		return nil, fmt.Errorf("capture already in progress")
	}

	w.resultChan = make(chan CaptureResult, 1)
	w.startTime = time.Now()
	w.result = CaptureResult{
		StartTime: w.startTime,
		PCAPFile:  w.pcapngFile,
	}

	// Build pktmon command with options
	args := []string{"/c", "pktmon", "start", "-c"}
	if w.opts.Interface != "" {
		args = append(args, "--adapter", w.opts.Interface)
	}
	if w.opts.Filter != "" {
		args = append(args, "--filter", w.opts.Filter)
	}
	args = append(args, "-f", w.etlFile)

	w.cmd = exec.Command("cmd.exe", args...)
	if out, err := w.cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to start pktmon: %v\nOutput: %s", err, out)
	}

	w.isCapturing = true

	// Start monitoring goroutine
	go w.monitor()

	return w.resultChan, nil
}

// monitor handles the capture duration and automatic stopping
func (w *WindowsCapturer) monitor() {
	if w.opts.Duration > 0 {
		time.Sleep(w.opts.Duration)
		w.StopCapture()
	}
}

// StopCapture ends the current capture session
func (w *WindowsCapturer) StopCapture() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.isCapturing {
		return nil
	}

	// Stop pktmon
	stopCmd := exec.Command("cmd.exe", "/c", "pktmon", "stop")
	if out, err := stopCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop pktmon: %v\nOutput: %s", err, out)
	}

	w.isCapturing = false
	w.result.EndTime = time.Now()

	// Convert ETL to PCAPNG
	formatCmd := exec.Command("cmd.exe", "/c", "pktmon", "pcapng", w.etlFile, "-o", w.pcapngFile)
	if out, err := formatCmd.CombinedOutput(); err != nil {
		w.result.Error = fmt.Errorf("failed to convert to PCAPNG: %v\nOutput: %s", err, out)
		w.resultChan <- w.result
		return w.result.Error
	}

	// Get file stats
	if info, err := os.Stat(w.pcapngFile); err == nil {
		w.result.ByteCount = info.Size()
	}

	// Process with pcap parser to get packet count
	parser := pcap.NewPcapParser(w.pcapngFile, w.opts.OutputDir)
	if stats, err := parser.ProcessFile(); err == nil {
		w.result.PacketCount = int64(stats.TotalPackets)
	}

	w.resultChan <- w.result
	return nil
}

// Status returns the current status of the capture
func (w *WindowsCapturer) Status() (CaptureResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.isCapturing {
		return w.result, nil
	}

	current := w.result
	current.EndTime = time.Now()
	return current, nil
}

// Cleanup releases any resources
func (w *WindowsCapturer) Cleanup() error {
	w.StopCapture()
	close(w.resultChan)
	return nil
}

// OutputFiles returns paths to the log files
func (w *WindowsCapturer) OutputFiles() (string, string, error) {
	// Check if files exist
	if _, err := os.Stat(w.etlFile); err != nil {
		return "", "", fmt.Errorf("capture.etl not found: %v", err)
	}
	if _, err := os.Stat(w.pcapngFile); err != nil {
		return "", "", fmt.Errorf("capture.pcapng not found: %v", err)
	}
	return w.etlFile, w.pcapngFile, nil
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
