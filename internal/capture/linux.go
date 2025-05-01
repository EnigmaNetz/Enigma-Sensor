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
	"time"
)

// LinuxCapturer implements PacketCapturer for Linux
type LinuxCapturer struct {
	config      Config
	tcpdumpCmd  *exec.Cmd
	zeekCmd     *exec.Cmd
	pcapPath    string
	dnsLogPath  string
	connLogPath string
}

// NewLinuxCapturer creates a new LinuxCapturer
func NewLinuxCapturer(cfg Config) PacketCapturer {
	return &LinuxCapturer{
		config:      cfg,
		pcapPath:    filepath.Join(cfg.OutputDir, "capture.pcap"),
		dnsLogPath:  filepath.Join(cfg.OutputDir, "dns.log"),
		connLogPath: filepath.Join(cfg.OutputDir, "conn.log"),
	}
}

// StartCapture begins packet capture using tcpdump and Zeek
func (l *LinuxCapturer) StartCapture() error {
	// Ensure output directory exists
	if err := os.MkdirAll(l.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	log.Printf("[DEBUG] Created output directory: %s", l.config.OutputDir)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (sudo) to capture packets")
	}

	// Check if tcpdump is available
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		return fmt.Errorf("tcpdump not found in PATH: %v", err)
	}
	log.Printf("[DEBUG] Found tcpdump at: %s", tcpdumpPath)

	// Check if Zeek is installed and get its base path
	zeekPath := "/opt/zeek/bin/zeek"
	if _, err := os.Stat(zeekPath); err != nil {
		return fmt.Errorf("Zeek not found at %s: %v", zeekPath, err)
	}
	log.Printf("[DEBUG] Found Zeek at: %s", zeekPath)

	// Check for Zeek scripts directory
	zeekScriptsPath := "/opt/zeek/share/zeek"
	if _, err := os.Stat(zeekScriptsPath); err != nil {
		// Try alternate location
		zeekScriptsPath = "/usr/share/zeek"
		if _, err := os.Stat(zeekScriptsPath); err != nil {
			return fmt.Errorf("Zeek scripts not found in standard locations")
		}
	}
	log.Printf("[DEBUG] Found Zeek scripts at: %s", zeekScriptsPath)

	// Get available interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list network interfaces: %v", err)
	}

	// Find first non-loopback interface that's up
	var captureIface string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			captureIface = iface.Name
			break
		}
	}
	if captureIface == "" {
		return fmt.Errorf("no suitable network interface found for capture")
	}
	log.Printf("[DEBUG] Selected interface for capture: %s", captureIface)

	// Start tcpdump capture
	tcpdumpArgs := []string{
		"-w", l.pcapPath, // Write to pcap file
		"-G", fmt.Sprintf("%d", l.config.CaptureWindow), // Rotate after duration
		"-W", "1", // Only keep 1 file
		"-K",               // Don't verify checksums
		"-n",               // Don't resolve addresses
		"-i", captureIface, // Use specific interface instead of 'any'
		"-s", "0", // Capture full packets
		"-Z", "root", // Drop privileges after starting
		"not port 22", // Exclude SSH traffic
	}

	log.Printf("[DEBUG] Starting tcpdump with args: %v", tcpdumpArgs)
	l.tcpdumpCmd = exec.Command(tcpdumpPath, tcpdumpArgs...)

	// Capture tcpdump stderr for logging
	tcpdumpStderr, err := l.tcpdumpCmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe for tcpdump: %v", err)
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := tcpdumpStderr.Read(buf)
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
	}()

	if err := l.tcpdumpCmd.Start(); err != nil {
		return fmt.Errorf("failed to start tcpdump: %v", err)
	}
	log.Printf("[INFO] Started tcpdump with PID: %d", l.tcpdumpCmd.Process.Pid)

	// Wait for PCAP file to be created and have some data
	log.Printf("[DEBUG] Waiting for PCAP file to be created at: %s", l.pcapPath)
	timeout := time.After(10 * time.Second)          // Increased timeout
	ticker := time.NewTicker(500 * time.Millisecond) // Increased interval
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			l.tcpdumpCmd.Process.Kill()
			return fmt.Errorf("timeout waiting for PCAP file after 10 seconds - ensure network traffic is flowing")
		case <-ticker.C:
			if info, err := os.Stat(l.pcapPath); err == nil {
				log.Printf("[DEBUG] PCAP file found, size: %d bytes", info.Size())
				if info.Size() > 0 {
					goto pcapReady
				}
			}
		}
	}
pcapReady:

	// Start Zeek analysis
	zeekArgs := []string{
		"-r", l.pcapPath, // Read from pcap file
		"-U", "zeek_process.log", // Write process status to file
		fmt.Sprintf("Log::default_logdir=%s", l.config.OutputDir), // Set log directory
		"-C", // Ignore checksums
	}

	log.Printf("[DEBUG] Starting Zeek with args: %v", zeekArgs)
	l.zeekCmd = exec.Command(zeekPath, zeekArgs...)

	// Set working directory to output directory for log files
	l.zeekCmd.Dir = l.config.OutputDir

	// Set minimal environment
	l.zeekCmd.Env = []string{
		fmt.Sprintf("PATH=%s", os.Getenv("PATH")),
		fmt.Sprintf("ZEEKPATH=%s", zeekScriptsPath),
		"ZEEK_DISABLE_ZEEKYGEN=1",
		fmt.Sprintf("HOME=%s", os.Getenv("HOME")),
		"TZ=America/Chicago", // Match Docker timezone setting
	}

	// Create stdout pipe for Zeek
	zeekStdout, err := l.zeekCmd.StdoutPipe()
	if err != nil {
		l.tcpdumpCmd.Process.Kill()
		return fmt.Errorf("failed to create stdout pipe for Zeek: %v", err)
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := zeekStdout.Read(buf)
			if n > 0 {
				log.Printf("[ZEEK-OUT] %s", string(buf[:n]))
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[ERROR] Zeek stdout read error: %v", err)
				}
				break
			}
		}
	}()

	// Capture Zeek stderr for logging
	zeekStderr, err := l.zeekCmd.StderrPipe()
	if err != nil {
		l.tcpdumpCmd.Process.Kill()
		return fmt.Errorf("failed to create stderr pipe for Zeek: %v", err)
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := zeekStderr.Read(buf)
			if n > 0 {
				log.Printf("[ZEEK-ERR] %s", string(buf[:n]))
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[ERROR] Zeek stderr read error: %v", err)
				}
				break
			}
		}
	}()

	if err := l.zeekCmd.Start(); err != nil {
		l.tcpdumpCmd.Process.Kill()
		return fmt.Errorf("failed to start Zeek: %v", err)
	}
	log.Printf("[INFO] Started Zeek with PID: %d", l.zeekCmd.Process.Pid)

	return nil
}

// StopCapture ends the current capture session
func (l *LinuxCapturer) StopCapture() error {
	// Stop tcpdump
	if l.tcpdumpCmd != nil && l.tcpdumpCmd.Process != nil {
		if err := l.tcpdumpCmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to stop tcpdump: %v", err)
		}
	}

	// Stop Zeek
	if l.zeekCmd != nil && l.zeekCmd.Process != nil {
		if err := l.zeekCmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to stop Zeek: %v", err)
		}
	}

	return nil
}

// OutputFiles returns paths to the log files
func (l *LinuxCapturer) OutputFiles() (string, string, error) {
	log.Printf("[DEBUG] Waiting for tcpdump to finish writing...")
	// Wait for tcpdump to finish writing
	if l.tcpdumpCmd != nil && l.tcpdumpCmd.Process != nil {
		if err := l.tcpdumpCmd.Wait(); err != nil {
			log.Printf("[ERROR] tcpdump process failed: %v", err)
			return "", "", fmt.Errorf("tcpdump process failed: %v", err)
		}
		log.Printf("[DEBUG] tcpdump process completed")
	}

	// Wait for Zeek to finish processing with timeout
	if l.zeekCmd != nil {
		log.Printf("[DEBUG] Waiting for Zeek to finish processing...")
		done := make(chan error)
		go func() {
			done <- l.zeekCmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				log.Printf("[ERROR] Zeek process failed: %v", err)
				return "", "", fmt.Errorf("Zeek process failed: %v", err)
			}
			log.Printf("[DEBUG] Zeek process completed successfully")
		case <-time.After(30 * time.Second):
			log.Printf("[ERROR] Timeout waiting for Zeek after 30 seconds")
			l.zeekCmd.Process.Kill()
			return "", "", fmt.Errorf("timeout waiting for Zeek to finish processing")
		}
	}

	// Check if log files exist and get their sizes
	if info, err := os.Stat(l.dnsLogPath); err != nil {
		log.Printf("[ERROR] DNS log file not found at %s: %v", l.dnsLogPath, err)
		return "", "", fmt.Errorf("DNS log file not found: %v", err)
	} else {
		log.Printf("[DEBUG] Found DNS log file, size: %d bytes", info.Size())
	}

	if info, err := os.Stat(l.connLogPath); err != nil {
		log.Printf("[ERROR] Connection log file not found at %s: %v", l.connLogPath, err)
		return "", "", fmt.Errorf("Connection log file not found: %v", err)
	} else {
		log.Printf("[DEBUG] Found connection log file, size: %d bytes", info.Size())
	}

	return l.dnsLogPath, l.connLogPath, nil
}

// LinuxCaptureManager implements CaptureManager for Linux.
type LinuxCaptureManager struct {
	config   Config
	quitChan chan struct{}
}

// NewLinuxCaptureManager creates a new LinuxCaptureManager.
func NewLinuxCaptureManager(cfg Config) *LinuxCaptureManager {
	return &LinuxCaptureManager{config: cfg, quitChan: make(chan struct{})}
}

func (l *LinuxCaptureManager) Start() error {
	// TODO: Implement Linux Zeek capture loop
	return nil
}

func (l *LinuxCaptureManager) Stop() error {
	// TODO: Implement stop logic
	return nil
}

func (l *LinuxCaptureManager) RotateLogs() error {
	// TODO: Implement log rotation (7-day retention)
	return nil
}
