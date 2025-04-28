package capture

// CaptureManager defines the interface for cross-platform packet capture.
type CaptureManager interface {
	// Start begins the capture loop (interval, window, etc.).
	Start() error
	// Stop halts the capture loop and cleans up resources.
	Stop() error
	// RotateLogs performs log rotation and cleanup (e.g., 7-day retention).
	RotateLogs() error
}

// Config holds configuration for capture (intervals, paths, etc.).
type Config struct {
	OutputDir       string // Directory for Zeek/pktmon logs
	CaptureWindow   int    // Capture window in seconds (e.g., 30)
	CaptureInterval int    // Interval between captures in seconds (e.g., 120)
	RetentionDays   int    // Log retention in days (e.g., 7)
}
