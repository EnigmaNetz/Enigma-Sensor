package capture

import (
	"fmt"
	"log"
	"runtime"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/linux"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/windows"
)

// NewCapturer creates a new Capturer appropriate for the current platform
// On Windows, automatically uses Npcap if available, otherwise falls back to pktmon
func NewCapturer(cfg common.CaptureConfig) common.Capturer {
	switch runtime.GOOS {
	case "windows":
		// Try Npcap first (supports promiscuous mode for full wire capture)
		if windows.IsNpcapAvailable() {
			log.Printf("[capture] Using Npcap capturer (promiscuous mode enabled)")
			return windows.NewNpcapCapturer()
		}
		// Fallback to pktmon (no promiscuous mode, only host-processed traffic)
		log.Printf("[capture] Npcap not available, using pktmon capturer (limited to host traffic)")
		return windows.NewWindowsCapturer()
	case "linux", "darwin": // Both Linux and macOS use the same implementation
		return linux.NewLinuxCapturer()
	default:
		panic(fmt.Sprintf("unsupported platform: %s", runtime.GOOS))
	}
}
