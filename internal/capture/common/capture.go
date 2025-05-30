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
	Interface       string        // Network interface to capture from ("any" for all interfaces)
}

// CaptureResult represents the result of a single capture operation
type CaptureResult struct {
	PCAPPath string                 // Path to the captured PCAP file
	Metadata map[string]interface{} // Additional metadata about the capture
}

// Capturer defines the interface for platform-specific packet capture
// Capture runs a single capture operation and returns the output file path (or error)
type Capturer interface {
	Capture(ctx context.Context, config CaptureConfig) (string, error)
}
