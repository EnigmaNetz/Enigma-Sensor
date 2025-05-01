//go:build windows

package capture

// NewLinuxCapturer creates a new LinuxCapturer (stub for Windows builds)
func NewLinuxCapturer(cfg Config) PacketCapturer {
	panic("Linux capture is not supported on Windows")
}
