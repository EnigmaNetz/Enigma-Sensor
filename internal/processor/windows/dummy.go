//go:build !windows

package windows

import types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"

func NewProcessor() types.Processor {
	panic("NewProcessor called on non-Windows platform")
}
