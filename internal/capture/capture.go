package capture

// Config holds configuration for capture (intervals, paths, etc.).
type Config struct {
	OutputDir       string // Directory for Zeek/pktmon logs
	CaptureWindow   int    // Capture window in seconds (e.g., 30)
	CaptureInterval int    // Interval between captures in seconds (e.g., 120)
	RetentionDays   int    // Log retention in days (e.g., 7)
}
