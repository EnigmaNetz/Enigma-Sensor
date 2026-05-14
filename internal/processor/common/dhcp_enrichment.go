package types

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// EnrichDHCPLog parses DHCP option 55 (parameter request list) from the
// pcapng file and writes the values into the param_req_list column of the
// Zeek-generated dhcp.log. Non-fatal: errors are logged and the function
// returns nil so the main processing path is never interrupted.
func EnrichDHCPLog(pcapPath, dhcpLogPath string) error {
	fingerprints, err := ExtractDHCPFingerprints(pcapPath)
	if err != nil {
		log.Printf("[processor] Warning: DHCP fingerprint extraction failed: %v", err)
		return nil
	}
	if len(fingerprints) == 0 {
		return nil
	}
	if err := PatchDHCPLog(dhcpLogPath, fingerprints); err != nil {
		log.Printf("[processor] Warning: DHCP log enrichment failed: %v", err)
	}
	return nil
}

// packetReader is the common interface satisfied by both pcapgo.Reader and pcapgo.NgReader.
type packetReader interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
}

// ExtractDHCPFingerprints reads a pcap or pcapng file and returns a map from
// client MAC address to comma-separated DHCP option 55 (parameter request list).
// Only BOOTREQUEST packets are examined; the first fingerprint seen per MAC
// is kept since option 55 is a stable property of the client OS/stack.
func ExtractDHCPFingerprints(pcapPath string) (map[string]string, error) {
	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	// Try pcapng first (Windows pktmon output); fall back to regular pcap (Linux tcpdump output).
	var reader packetReader
	if ngr, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions); err == nil {
		reader = ngr
	} else {
		if _, err := f.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("seek pcap: %w", err)
		}
		r, err := pcapgo.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("pcap reader: %w", err)
		}
		reader = r
	}

	result := make(map[string]string)
	src := gopacket.NewPacketSource(reader, reader.LinkType())
	src.DecodeOptions.Lazy = true

	for packet := range src.Packets() {
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			continue
		}
		dhcp, ok := dhcpLayer.(*layers.DHCPv4)
		if !ok || dhcp.Operation != layers.DHCPOpRequest {
			continue
		}
		mac := dhcp.ClientHWAddr.String()
		if _, seen := result[mac]; seen {
			continue
		}
		for _, opt := range dhcp.Options {
			if opt.Type == layers.DHCPOptParamsRequest && len(opt.Data) > 0 {
				parts := make([]string, len(opt.Data))
				for i, b := range opt.Data {
					parts[i] = strconv.Itoa(int(b))
				}
				result[mac] = strings.Join(parts, ",")
				break
			}
		}
	}
	return result, nil
}

// PatchDHCPLog reads the Zeek dhcp.log TSV, fills in the param_req_list
// column for any row whose MAC address appears in fingerprints, and writes
// the file back in place.
func PatchDHCPLog(logPath string, fingerprints map[string]string) error {
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read dhcp log: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	macIdx, paramIdx := -1, -1
	for _, line := range lines {
		if strings.HasPrefix(line, "#fields\t") {
			fields := strings.Split(line, "\t")[1:] // drop "#fields" prefix so indices match data columns
			for i, f := range fields {
				switch f {
				case "mac":
					macIdx = i
				case "param_req_list":
					paramIdx = i
				}
			}
			break
		}
	}
	if macIdx < 0 || paramIdx < 0 {
		return nil
	}

	changed := false
	for i, line := range lines {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if macIdx >= len(cols) || paramIdx >= len(cols) {
			continue
		}
		if fp, ok := fingerprints[cols[macIdx]]; ok && cols[paramIdx] == "-" {
			cols[paramIdx] = fp
			lines[i] = strings.Join(cols, "\t")
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return os.WriteFile(logPath, []byte(strings.Join(lines, "\n")), 0644)
}
