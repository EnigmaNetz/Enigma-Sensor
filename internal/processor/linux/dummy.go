//go:build !linux && !darwin

package linux

import types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"

func NewProcessor() types.Processor {
	panic("NewProcessor called on non-Linux platform")
}
