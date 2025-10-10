//go:build windows

package windows

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/gopacket/pcap"
)

// InterfaceMapper maps pktmon component IDs to Npcap device names
type InterfaceMapper struct {
	idToDevice map[string]string // pktmon ID -> Npcap device name
	idToDesc   map[string]string // pktmon ID -> description
}

// NewInterfaceMapper creates a new mapper by querying both pktmon and Npcap
func NewInterfaceMapper() (*InterfaceMapper, error) {
	mapper := &InterfaceMapper{
		idToDevice: make(map[string]string),
		idToDesc:   make(map[string]string),
	}

	// Get pktmon component list
	pktmonComponents, err := mapper.getPktmonComponents()
	if err != nil {
		return nil, fmt.Errorf("failed to get pktmon components: %w", err)
	}

	// Get Npcap devices
	npcapDevices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate Npcap devices: %w", err)
	}

	// Log all pktmon components found
	log.Printf("[capture] Found %d pktmon components:", len(pktmonComponents))
	for id, desc := range pktmonComponents {
		log.Printf("[capture]   pktmon ID %s: %s", id, desc)
	}

	// Map pktmon IDs to Npcap devices by matching descriptions
	matchCount := 0
	for id, desc := range pktmonComponents {
		mapper.idToDesc[id] = desc

		// Try to find matching Npcap device
		matched := false
		for _, npcapDev := range npcapDevices {
			normalizedPktmon := normalizeDescription(desc)
			normalizedNpcap := normalizeDescription(npcapDev.Description)

			if normalizedPktmon == normalizedNpcap {
				mapper.idToDevice[id] = npcapDev.Name
				log.Printf("[capture] ✓ Mapped pktmon ID %s (%s) to Npcap device %s", id, desc, npcapDev.Name)
				matched = true
				matchCount++
				break
			}
		}

		if !matched {
			log.Printf("[capture] ✗ No Npcap match for pktmon ID %s (%s)", id, desc)
		}
	}

	log.Printf("[capture] Interface mapper: %d/%d pktmon IDs mapped to Npcap devices", matchCount, len(pktmonComponents))

	return mapper, nil
}

// TranslateToNpcapDevice converts a pktmon interface ID to Npcap device name
// Returns the input unchanged if it's not a numeric ID or already a device name
func (m *InterfaceMapper) TranslateToNpcapDevice(interfaceID string) string {
	// Check if it's already an Npcap device name
	if strings.HasPrefix(interfaceID, "\\Device\\NPF_") {
		return interfaceID
	}

	// Check if we have a mapping for this ID
	if deviceName, ok := m.idToDevice[interfaceID]; ok {
		log.Printf("[capture] Translated pktmon ID %s to Npcap device: %s", interfaceID, deviceName)
		return deviceName
	}

	// If numeric but no mapping found, warn and return as-is
	if isNumeric(interfaceID) {
		log.Printf("[capture] WARNING: No Npcap device found for pktmon ID %s", interfaceID)
	}

	return interfaceID
}

// getPktmonComponents parses pktmon comp list output to get ID -> Description mapping
func (m *InterfaceMapper) getPktmonComponents() (map[string]string, error) {
	cmd := exec.Command("pktmon", "comp", "list")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pktmon comp list failed: %w", err)
	}

	return parsePktmonCompList(out.String()), nil
}

// parsePktmonCompList parses the output of "pktmon comp list"
// Example format:
// Id  Component
// --  ---------
// 12  AA-BB-CC-DD-EE-FF Intel(R) Ethernet Connection
// 34  Hyper-V Virtual Ethernet Adapter
func parsePktmonCompList(output string) map[string]string {
	components := make(map[string]string)

	// Match lines with pattern: <number> <description>
	// Example: "12  AA-BB-CC-DD-EE-FF Intel(R) Ethernet Connection"
	re := regexp.MustCompile(`^\s*(\d+)\s+(.+)$`)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		matches := re.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) == 3 {
			id := matches[1]
			desc := strings.TrimSpace(matches[2])

			// Strip MAC address prefix if present (format: AA-BB-CC-DD-EE-FF)
			desc = stripMACAddress(desc)

			components[id] = desc
		}
	}

	return components
}

// stripMACAddress removes MAC address prefix from pktmon component descriptions
// Example: "AA-BB-CC-DD-EE-FF Some Network Adapter" -> "Some Network Adapter"
func stripMACAddress(desc string) string {
	// Match MAC address pattern at start: XX-XX-XX-XX-XX-XX followed by space
	macPattern := regexp.MustCompile(`^[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}\s+`)
	return macPattern.ReplaceAllString(desc, "")
}

// normalizeDescription normalizes device descriptions for comparison
func normalizeDescription(desc string) string {
	// Convert to lowercase, remove extra spaces
	desc = strings.ToLower(desc)
	desc = strings.Join(strings.Fields(desc), " ")

	// Remove common prefixes/suffixes that differ between pktmon and Npcap
	desc = strings.TrimPrefix(desc, "microsoft ")
	desc = strings.TrimSuffix(desc, " adapter")
	desc = strings.TrimSuffix(desc, " controller")

	return desc
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
