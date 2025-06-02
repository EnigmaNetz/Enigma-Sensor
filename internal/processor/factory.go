package processor

import (
	"fmt"
	"runtime"

	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
	"EnigmaNetz/Enigma-Go-Sensor/internal/processor/linux"
	"EnigmaNetz/Enigma-Go-Sensor/internal/processor/windows"
)

// NewProcessor returns the correct platform-specific Processor implementation.
func NewProcessor() types.Processor {
	switch runtime.GOOS {
	case "windows":
		return windows.NewProcessor()
	case "linux", "darwin":
		return linux.NewProcessor()
	default:
		panic(fmt.Sprintf("unsupported platform: %s", runtime.GOOS))
	}
}
