package common

import (
	"context"
	"time"
)

// CaptureConfig holds configuration for packet capture
type CaptureConfig struct {
	CaptureWindow   time.Duration // Duration of each capture window
	CaptureInterval time.Duration // Interval between capture starts
	OutputDir       string        // Directory to store capture output
}

// Capturer defines the interface for platform-specific packet capture
type Capturer interface {
	// Start begins the capture process with the given configuration
	Start(ctx context.Context, config CaptureConfig) error

	// Stop gracefully stops the capture process
	Stop() error

	// Status returns the current capture status
	Status() (CaptureStatus, error)
}

// CaptureStatus represents the current state of capture
type CaptureStatus struct {
	IsRunning   bool
	LastCapture time.Time
	Error       error
}
