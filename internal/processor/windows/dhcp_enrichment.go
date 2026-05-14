//go:build windows

package windows

import types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"

func enrichDHCPLog(pcapPath, dhcpLogPath string) error {
	return types.EnrichDHCPLog(pcapPath, dhcpLogPath)
}
