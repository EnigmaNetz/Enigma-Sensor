//go:build windows

package windows

import (
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
	"fmt"
)

type Processor struct{}

func NewProcessor() *Processor {
	return &Processor{}
}

func (p *Processor) ProcessPCAP(pcapPath string) (types.ProcessedData, error) {
	return types.ProcessedData{}, fmt.Errorf("ProcessPCAP not implemented for Windows yet")
}
