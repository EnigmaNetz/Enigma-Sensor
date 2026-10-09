package types

import (
	"encoding/json"
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
// capture and writes the values into the param_req_list field of the
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

// PatchDHCPLog reads the Zeek dhcp.log (JSON, one record per line), sets param_req_list on any
// record whose mac appears in fingerprints and has no param_req_list yet, and replaces the log
// if anything changed. A line that is not a JSON record is copied unchanged: enrichment is best
// effort, and the subnet filter refuses such a line afterwards.
func PatchDHCPLog(logPath string, fingerprints map[string]string) error {
	_, err := rewriteLog(logPath, func(line []byte) ([]byte, error) {
		if patched, ok := patchRecord(line, fingerprints); ok {
			return patched, nil
		}
		return line, nil
	})
	if err != nil {
		return fmt.Errorf("dhcp log: %w", err)
	}
	return nil
}

// patchRecord returns the record with param_req_list set, and true, when the record's mac has a
// fingerprint and param_req_list is not already set.
func patchRecord(line []byte, fingerprints map[string]string) ([]byte, bool) {
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, false
	}
	if _, set := rec["param_req_list"]; set {
		return nil, false
	}
	var mac string
	if err := json.Unmarshal(rec["mac"], &mac); err != nil {
		return nil, false
	}
	fp, ok := fingerprints[mac]
	if !ok {
		return nil, false
	}
	value, err := json.Marshal(fp)
	if err != nil {
		return nil, false
	}
	rec["param_req_list"] = value
	patched, err := json.Marshal(rec)
	if err != nil {
		return nil, false
	}
	return patched, true
}
