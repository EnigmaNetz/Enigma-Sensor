//go:build linux
// +build linux

package capture

// WindowsCapturer stub for Linux builds
type WindowsCapturer struct{}

// NewWindowsCapturer creates a stub WindowsCapturer (not supported on Linux)
func NewWindowsCapturer(cfg Config) PacketCapturer {
	panic("Windows capture is not supported on Linux")
}
