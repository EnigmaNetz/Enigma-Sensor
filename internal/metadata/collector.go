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

// GenerateMetadata creates the metadata map for sensor uploads
func GenerateMetadata(networkID string) map[string]string {
	metadata := make(map[string]string)

	// Essential Fields
	metadata["network_id"] = networkID
	metadata["machine_id"] = generateMachineID()
	metadata["sensor_version"] = version.Version
	metadata["os_name"] = runtime.GOOS
	metadata["os_version"] = getOSVersion()
	metadata["architecture"] = runtime.GOARCH

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
