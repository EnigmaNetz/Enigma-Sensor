package capture

// Config holds capture configuration settings
type Config struct {
	// OutputDir is the directory where capture logs will be written
	OutputDir string
	// CaptureWindow is the duration in seconds for each capture session
	CaptureWindow int
	// CaptureInterval is the time in seconds between capture sessions
	CaptureInterval int
	// RetentionDays specifies how many days of logs to retain
	RetentionDays int
}

// PacketCapturer defines the interface for platform-specific packet capture implementations.
// Each platform (Windows/Linux) must implement this interface to provide native capture
// capabilities while maintaining consistent output format (Zeek logs).
type PacketCapturer interface {
	// StartCapture begins a packet capture session using platform-specific tools
	// (pktmon for Windows, tcpdump+Zeek for Linux). The capture runs for the
	// duration specified in Config.CaptureWindow.
	StartCapture() error

	// StopCapture ends the current capture session and ensures all data is
	// properly flushed to the output files. On Windows, this includes converting
	// the ETL to Zeek format. On Linux, this includes processing with Zeek.
	StopCapture() error

	// OutputFiles returns the paths to the generated Zeek-format log files.
	// Returns the paths to dns.log and conn.log respectively, or an error if
	// the files don't exist or are not accessible.
	OutputFiles() (dnsLogPath string, connLogPath string, err error)
}
