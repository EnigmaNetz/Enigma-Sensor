//go:build windows

package capture

import (
	"log"
	"os/exec"
	"time"
)

// WindowsCaptureManager implements CaptureManager for Windows.
type WindowsCaptureManager struct {
	config   Config
	quitChan chan struct{}
}

// NewWindowsCaptureManager creates a new WindowsCaptureManager.
func NewWindowsCaptureManager(cfg Config) *WindowsCaptureManager {
	log.Printf("[INFO] Creating WindowsCaptureManager with config: %+v", cfg)
	return &WindowsCaptureManager{config: cfg, quitChan: make(chan struct{})}
}

// Start begins the capture loop.
func (w *WindowsCaptureManager) Start() error {
	log.Println("[INFO] Starting Windows capture loop...")
	go w.captureLoop()
	return nil
}

// Stop halts the capture loop.
func (w *WindowsCaptureManager) Stop() error {
	log.Println("[INFO] Stopping Windows capture loop...")
	close(w.quitChan)
	return nil
}

// RotateLogs performs log rotation and cleanup.
func (w *WindowsCaptureManager) RotateLogs() error {
	log.Println("[DEBUG] Rotating logs (7-day retention)...")
	// TODO: Implement log rotation (7-day retention)
	return nil
}

// captureLoop runs the capture at the configured interval.
func (w *WindowsCaptureManager) captureLoop() {
	log.Printf("[INFO] Capture loop started. Interval: %ds, Window: %ds", w.config.CaptureInterval, w.config.CaptureWindow)
	ticker := time.NewTicker(time.Duration(w.config.CaptureInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.quitChan:
			log.Println("[INFO] Capture loop stopped.")
			return
		case <-ticker.C:
			log.Println("[DEBUG] Triggering packet capture...")
			w.runCapture()
		}
	}
}

// runCapture tries Zeek, falls back to pktmon if Zeek is unavailable.
func (w *WindowsCaptureManager) runCapture() {
	log.Println("[INFO] Attempting Zeek capture...")
	if err := w.invokeZeek(); err != nil {
		log.Printf("[WARN] Zeek not available, falling back to pktmon: %v", err)
		log.Println("[INFO] Attempting pktmon capture...")
		if err := w.invokePktmon(); err != nil {
			log.Printf("[ERROR] pktmon capture failed: %v", err)
		} else {
			log.Println("[INFO] pktmon capture succeeded.")
		}
	} else {
		log.Println("[INFO] Zeek capture succeeded.")
	}
	// TODO: Monitor output dir, parse/transform logs
}

// invokeZeek tries to run Zeek for packet capture.
func (w *WindowsCaptureManager) invokeZeek() error {
	log.Println("[DEBUG] Invoking Zeek...")
	cmd := exec.Command("zeek", "-C", "-r", "input.pcap") // Example args
	err := cmd.Run()
	if err != nil {
		log.Printf("[ERROR] Zeek invocation failed: %v", err)
	}
	return err
}

// invokePktmon runs pktmon as fallback.
func (w *WindowsCaptureManager) invokePktmon() error {
	log.Println("[DEBUG] Invoking pktmon...")
	cmd := exec.Command("pktmon", "start", "--capture") // Example args
	err := cmd.Run()
	if err != nil {
		log.Printf("[ERROR] pktmon invocation failed: %v", err)
	}
	return err
}
