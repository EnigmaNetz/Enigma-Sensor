//go:build !windows

package windows

import (
	"context"
	"fmt"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
)

// NpcapCapturer stub for non-Windows platforms
type NpcapCapturer struct{}

// NewNpcapCapturer stub for non-Windows platforms
func NewNpcapCapturer() *NpcapCapturer {
	return &NpcapCapturer{}
}

// IsNpcapAvailable always returns false on non-Windows platforms
func IsNpcapAvailable() bool {
	return false
}

// Capture stub for non-Windows platforms
func (c *NpcapCapturer) Capture(ctx context.Context, config common.CaptureConfig) (string, error) {
	return "", fmt.Errorf("Npcap capture not supported on this platform")
}
