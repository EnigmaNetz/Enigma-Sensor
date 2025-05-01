package capture

import (
	"fmt"
	"runtime"
)

// NewCapturer creates a new PacketCapturer appropriate for the current platform
func NewCapturer(cfg Config) PacketCapturer {
	switch runtime.GOOS {
	case "windows":
		return NewWindowsCapturer(cfg)
	case "linux", "darwin": // Both Linux and macOS use the same implementation
		return NewLinuxCapturer(cfg)
	default:
		panic(fmt.Sprintf("unsupported platform: %s", runtime.GOOS))
	}
}
