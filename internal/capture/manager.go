package capture

import (
	"log"
	"time"
)

// CaptureManager handles the shared capture loop and log management.
type CaptureManager struct {
	capturer PacketCapturer
	opts     CaptureOptions
	quitChan chan struct{}
}

// NewCaptureManager creates a new CaptureManager.
func NewCaptureManager(opts CaptureOptions, capturer PacketCapturer) *CaptureManager {
	return &CaptureManager{
		capturer: capturer,
		opts:     opts,
		quitChan: make(chan struct{}),
	}
}

// Start begins the shared capture loop.
func (m *CaptureManager) Start() error {
	log.Println("[INFO] Starting shared capture loop...")

	// Initialize the capturer with our options
	if err := m.capturer.Initialize(m.opts); err != nil {
		return err
	}

	go m.captureLoop()
	return nil
}

// Stop halts the capture loop.
func (m *CaptureManager) Stop() error {
	log.Println("[INFO] Stopping shared capture loop...")
	close(m.quitChan)
	return m.capturer.Cleanup()
}

// RotateLogs performs log rotation and cleanup.
func (m *CaptureManager) RotateLogs() error {
	if m.opts.RetentionDays <= 0 {
		return nil // No rotation needed
	}
	log.Printf("[DEBUG] Rotating logs (%d-day retention)...", m.opts.RetentionDays)
	// TODO: Implement log rotation
	return nil
}

// captureLoop runs the capture at the configured interval.
func (m *CaptureManager) captureLoop() {
	log.Printf("[INFO] Capture loop started. Interval: %ds", m.opts.CaptureInterval)
	ticker := time.NewTicker(time.Duration(m.opts.CaptureInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.quitChan:
			log.Println("[INFO] Capture loop stopped.")
			return
		case <-ticker.C:
			log.Println("[DEBUG] Triggering packet capture...")
			resultChan, err := m.capturer.StartCapture()
			if err != nil {
				log.Printf("[ERROR] Failed to start capture: %v", err)
				continue
			}

			// Wait for capture to complete
			result := <-resultChan
			if result.Error != nil {
				log.Printf("[ERROR] Capture failed: %v", result.Error)
			} else {
				log.Printf("[INFO] Capture completed: %d packets, %d bytes",
					result.PacketCount, result.ByteCount)
			}
		}
	}
}
