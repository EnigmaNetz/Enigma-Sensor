package capture

import (
	"fmt"
	"runtime"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/linux"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/windows"
)

// NewCapturer creates a new Capturer appropriate for the current platform
func NewCapturer(cfg common.CaptureConfig) common.Capturer {
	switch runtime.GOOS {
	case "windows":
		return windows.NewWindowsCapturer()
	case "linux", "darwin": // Both Linux and macOS use the same implementation
		return linux.NewLinuxCapturer()
	default:
		panic(fmt.Sprintf("unsupported platform: %s", runtime.GOOS))
	}
}
