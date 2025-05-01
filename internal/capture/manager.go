package capture

import (
	"log"
	"time"
)

// CaptureManager handles the shared capture loop and log management.
type CaptureManager struct {
	capturer PacketCapturer
	config   Config
	quitChan chan struct{}
}

// NewCaptureManager creates a new CaptureManager.
func NewCaptureManager(cfg Config, capturer PacketCapturer) *CaptureManager {
	return &CaptureManager{
		capturer: capturer,
		config:   cfg,
		quitChan: make(chan struct{}),
	}
}

// Start begins the shared capture loop.
func (m *CaptureManager) Start() error {
	log.Println("[INFO] Starting shared capture loop...")
	go m.captureLoop()
	return nil
}

// Stop halts the capture loop.
func (m *CaptureManager) Stop() error {
	log.Println("[INFO] Stopping shared capture loop...")
	close(m.quitChan)
	return nil
}

// RotateLogs performs log rotation and cleanup.
func (m *CaptureManager) RotateLogs() error {
	log.Println("[DEBUG] Rotating logs (7-day retention)...")
	// TODO: Implement log rotation
	return nil
}

// captureLoop runs the capture at the configured interval.
func (m *CaptureManager) captureLoop() {
	log.Printf("[INFO] Capture loop started. Interval: %ds, Window: %ds", m.config.CaptureInterval, m.config.CaptureWindow)
	ticker := time.NewTicker(time.Duration(m.config.CaptureInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.quitChan:
			log.Println("[INFO] Capture loop stopped.")
			return
		case <-ticker.C:
			log.Println("[DEBUG] Triggering packet capture...")
			if err := m.capturer.StartCapture(); err != nil {
				log.Printf("[ERROR] Packet capture failed: %v", err)
			}
			// TODO: Handle output files, parse/transform logs
		}
	}
}
