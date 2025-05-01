package capture

import "time"

// CaptureOptions defines configuration options for a capture session
type CaptureOptions struct {
	// Interface is the network interface to capture from (e.g. "eth0", "en0")
	// If empty, the default interface will be used
	Interface string

	// Filter is a BPF filter expression to filter captured packets
	// Example: "port 53" for DNS traffic only
	Filter string

	// OutputDir is the directory where capture files will be written
	OutputDir string

	// Duration is the length of time to capture for
	// If zero, capture runs until explicitly stopped
	Duration time.Duration

	// MaxFileSize is the maximum size in bytes for the capture file
	// If zero, no size limit is enforced
	MaxFileSize int64

	// BufferSize is the kernel buffer size in MB for packet capture
	// If zero, system default is used
	BufferSize int

	// SnapLen is the maximum number of bytes to capture per packet
	// If zero, system default is used (usually 65535)
	SnapLen int

	// CaptureInterval is the time in seconds between capture sessions
	CaptureInterval int

	// RetentionDays specifies how many days of logs to retain
	RetentionDays int
}

// CaptureResult contains information about a completed capture
type CaptureResult struct {
	// PCAPFile is the path to the generated PCAP file
	PCAPFile string

	// PacketCount is the number of packets captured
	PacketCount int64

	// ByteCount is the number of bytes captured
	ByteCount int64

	// StartTime is when the capture began
	StartTime time.Time

	// EndTime is when the capture ended
	EndTime time.Time

	// Error contains any error that occurred during capture
	Error error
}

// PacketCapturer defines the interface for platform-specific packet capture
type PacketCapturer interface {
	// Initialize prepares the capturer with the given options
	// Returns error if the options are invalid or system requirements are not met
	Initialize(opts CaptureOptions) error

	// StartCapture begins a packet capture session
	// Returns a channel that will receive the CaptureResult when complete
	StartCapture() (<-chan CaptureResult, error)

	// StopCapture ends the current capture session gracefully
	// Returns error if no capture is in progress or stop fails
	StopCapture() error

	// Status returns the current status of the capture
	// Including packets captured, duration, etc
	Status() (CaptureResult, error)

	// Cleanup releases any resources held by the capturer
	// Should be called when the capturer is no longer needed
	Cleanup() error
}
