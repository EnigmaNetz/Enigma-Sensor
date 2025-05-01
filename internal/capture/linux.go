//go:build linux
// +build linux

package capture

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/processor/pcap"
)

// LinuxCapturer implements PacketCapturer for Linux using tcpdump
type LinuxCapturer struct {
	opts        CaptureOptions
	pcapPath    string
	cmd         *exec.Cmd
	isCapturing bool
	startTime   time.Time
	result      CaptureResult
	resultChan  chan CaptureResult
	mu          sync.Mutex
}

// NewLinuxCapturer creates a new LinuxCapturer
func NewLinuxCapturer() *LinuxCapturer {
	return &LinuxCapturer{}
}

// Initialize prepares the capturer with the given options
func (l *LinuxCapturer) Initialize(opts CaptureOptions) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isCapturing {
		return fmt.Errorf("cannot initialize while capture is in progress")
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (sudo) to capture packets")
	}

	// Check if tcpdump is available
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return fmt.Errorf("tcpdump not found in PATH: %v", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	l.opts = opts
	l.pcapPath = filepath.Join(opts.OutputDir, "capture.pcap")

	return nil
}

// StartCapture begins a packet capture session
func (l *LinuxCapturer) StartCapture() (<-chan CaptureResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isCapturing {
		return nil, fmt.Errorf("capture already in progress")
	}

	l.resultChan = make(chan CaptureResult, 1)
	l.startTime = time.Now()
	l.result = CaptureResult{
		StartTime: l.startTime,
		PCAPFile:  l.pcapPath,
	}

	// Build tcpdump arguments
	args := []string{
		"-w", l.pcapPath, // Write to pcap file
		"-K",      // Don't verify checksums
		"-n",      // Don't resolve addresses
		"-s", "0", // Capture full packets
		"-Z", "root", // Drop privileges after starting
	}

	// Add interface if specified
	if l.opts.Interface != "" {
		args = append(args, "-i", l.opts.Interface)
	} else {
		// Find first non-loopback interface that's up
		if iface, err := l.findDefaultInterface(); err == nil {
			args = append(args, "-i", iface)
		}
	}

	// Add BPF filter if specified
	if l.opts.Filter != "" {
		args = append(args, l.opts.Filter)
	}

	// Add snap length if specified
	if l.opts.SnapLen > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", l.opts.SnapLen))
	}

	// Add buffer size if specified
	if l.opts.BufferSize > 0 {
		args = append(args, "-B", fmt.Sprintf("%d", l.opts.BufferSize))
	}

	// Start tcpdump
	tcpdumpPath, _ := exec.LookPath("tcpdump")
	l.cmd = exec.Command(tcpdumpPath, args...)

	// Capture stderr for logging
	stderr, err := l.cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	go l.monitorStderr(stderr)

	if err := l.cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tcpdump: %v", err)
	}

	l.isCapturing = true

	// Start monitoring goroutine
	go l.monitor()

	return l.resultChan, nil
}

// monitor handles the capture duration and automatic stopping
func (l *LinuxCapturer) monitor() {
	if l.opts.Duration > 0 {
		time.Sleep(l.opts.Duration)
		l.StopCapture()
	}
}

// monitorStderr captures and logs tcpdump stderr output
func (l *LinuxCapturer) monitorStderr(stderr io.ReadCloser) {
	buf := make([]byte, 1024)
	for {
		n, err := stderr.Read(buf)
		if n > 0 {
			log.Printf("[TCPDUMP] %s", string(buf[:n]))
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[ERROR] tcpdump stderr read error: %v", err)
			}
			break
		}
	}
}

// findDefaultInterface returns the first non-loopback interface that's up
func (l *LinuxCapturer) findDefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

// StopCapture ends the current capture session
func (l *LinuxCapturer) StopCapture() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.isCapturing {
		return nil
	}

	if l.cmd != nil && l.cmd.Process != nil {
		if err := l.cmd.Process.Kill(); err != nil {
			l.result.Error = fmt.Errorf("failed to stop tcpdump: %v", err)
			l.resultChan <- l.result
			return l.result.Error
		}
		l.cmd.Wait()
	}

	l.isCapturing = false
	l.result.EndTime = time.Now()

	// Get file stats
	if info, err := os.Stat(l.pcapPath); err == nil {
		l.result.ByteCount = info.Size()
	}

	// Process with pcap parser to get packet count
	parser := pcap.NewPcapParser(l.pcapPath, l.opts.OutputDir)
	if stats, err := parser.ProcessFile(); err == nil {
		l.result.PacketCount = int64(stats.TotalPackets)
	}

	l.resultChan <- l.result
	return nil
}

// Status returns the current status of the capture
func (l *LinuxCapturer) Status() (CaptureResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.isCapturing {
		return l.result, nil
	}

	current := l.result
	current.EndTime = time.Now()
	return current, nil
}

// Cleanup releases any resources
func (l *LinuxCapturer) Cleanup() error {
	l.StopCapture()
	close(l.resultChan)
	return nil
}
