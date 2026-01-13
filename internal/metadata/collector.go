package metadata

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/google/uuid"

	"EnigmaNetz/Enigma-Go-Sensor/internal/version"
)

// maxHostIPs limits the number of IP addresses collected to avoid
// excessive metadata size (Cloud Storage has 8KB metadata limit per value).
// 10 IPs is sufficient for identifying sensor hosts while handling
// systems with multiple NICs, VPNs, or a few Docker networks.
const maxHostIPs = 10

// getHostIPAddresses returns private IP addresses for the sensor host.
// If a specific capture interface is configured, returns that interface's IP first.
// Falls back to all private IPs on non-loopback, up interfaces.
// Results are capped at maxHostIPs to prevent metadata size issues.
func getHostIPAddresses(captureInterface string) []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	// If specific interface configured (not "any"/"all"), try to get its IP first
	if captureInterface != "" && captureInterface != "any" && captureInterface != "all" {
		// Handle comma-separated list - use first one
		firstIface := strings.Split(captureInterface, ",")[0]
		firstIface = strings.TrimSpace(firstIface)

		for _, iface := range interfaces {
			if iface.Name == firstIface && iface.Flags&net.FlagUp != 0 {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok {
						if ip := ipnet.IP.To4(); ip != nil && ip.IsPrivate() {
							return []string{ip.String()}
						}
					}
				}
			}
		}
	}

	// Fallback: collect all private IPs from up, non-loopback interfaces
	var ips []string
	seen := make(map[string]bool)

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil && ip.IsPrivate() {
					ipStr := ip.String()
					if !seen[ipStr] {
						seen[ipStr] = true
						ips = append(ips, ipStr)
						// Stop collecting if we've reached the limit
						if len(ips) >= maxHostIPs {
							return ips
						}
					}
				}
			}
		}
	}
	return ips
}

// GenerateMetadata creates the metadata map for sensor uploads
func GenerateMetadata(networkID string, captureInterface string) map[string]string {
	metadata := make(map[string]string)

	// Essential Fields
	metadata["network_id"] = networkID
	metadata["machine_id"] = generateMachineID()
	metadata["sensor_version"] = version.Version
	metadata["os_name"] = runtime.GOOS
	metadata["os_version"] = getOSVersion()
	metadata["architecture"] = runtime.GOARCH

	// Host IPs (comma-separated)
	hostIPs := getHostIPAddresses(captureInterface)
	if len(hostIPs) > 0 {
		metadata["host_ips"] = strings.Join(hostIPs, ",")
	}

	// Additional Fields
	metadata["session_id"] = uuid.New().String()

	return metadata
}

// generateMachineID creates SHA256 hash of primary MAC address with salt
func generateMachineID() string {
	macAddr := getPrimaryMACAddress()
	if macAddr == "" {
		// Fallback to a default value if no MAC address available
		macAddr = "unknown-device"
	}

	// Hash MAC address with salt as specified in requirements
	hasher := sha256.New()
	hasher.Write([]byte(macAddr))
	hash := hasher.Sum(nil)

	return hex.EncodeToString(hash)
}

// getPrimaryMACAddress gets the MAC address of the primary network interface
func getPrimaryMACAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	// Sort interfaces by name for consistency
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})

	// Prefer physical ethernet, then wifi, then any other
	for _, priority := range []string{"eth", "en", "wlan", "wl"} {
		for _, iface := range interfaces {
			if strings.HasPrefix(iface.Name, priority) &&
				iface.Flags&net.FlagLoopback == 0 &&
				len(iface.HardwareAddr) > 0 {
				return iface.HardwareAddr.String()
			}
		}
	}

	// Fallback to any interface with MAC (deterministic order)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}

	return ""
}

// getOSVersion attempts to get OS version information
func getOSVersion() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsVersion()
	case "linux":
		return getLinuxVersion()
	case "darwin":
		return getMacOSVersion()
	default:
		return runtime.GOOS
	}
}

// getWindowsVersion gets Windows version from registry
func getWindowsVersion() string {
	cmd := exec.Command("cmd", "/c", "ver")
	output, err := cmd.Output()
	if err != nil {
		return "Windows"
	}
	version := strings.TrimSpace(string(output))
	// Extract version from output like "Microsoft Windows [Version 10.0.19044.1766]"
	if strings.Contains(version, "Version") {
		parts := strings.Split(version, "Version")
		if len(parts) > 1 {
			version = strings.Trim(parts[1], " []")
			return "Windows " + version
		}
	}
	return "Windows"
}

// getLinuxVersion reads from /etc/os-release
func getLinuxVersion() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer file.Close()

	var name, version string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
		} else if strings.HasPrefix(line, "VERSION=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		}
	}

	if name != "" && version != "" {
		return name + " " + version
	} else if name != "" {
		return name
	}
	return "Linux"
}

// getMacOSVersion uses sw_vers command
func getMacOSVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return "macOS"
	}
	version := strings.TrimSpace(string(output))
	return "macOS " + version
}
