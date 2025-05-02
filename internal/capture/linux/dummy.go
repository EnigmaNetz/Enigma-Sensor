//go:build !linux && !darwin

package linux

import "EnigmaNetz/Enigma-Go-Agent/internal/capture/common"

func NewLinuxCapturer() common.Capturer {
	panic("NewLinuxCapturer called on non-Linux platform")
}
