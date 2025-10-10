//go:build windows

package windows

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
)

// NpcapCapturer implements packet capture using Npcap library with promiscuous mode
type NpcapCapturer struct {
	outputDir string
}

// NewNpcapCapturer creates a new Npcap-based capturer
func NewNpcapCapturer() *NpcapCapturer {
	return &NpcapCapturer{}
}

// IsNpcapAvailable checks if Npcap is installed and usable
func IsNpcapAvailable() bool {
	// Check if Npcap service is running
	npcapDllPath := filepath.Join(os.Getenv("WINDIR"), "System32", "Npcap", "wpcap.dll")
	if _, err := os.Stat(npcapDllPath); err == nil {
		log.Printf("[capture] Npcap detected at %s", npcapDllPath)
		return true
	}

	// Fallback: try to get device list (will fail if Npcap not installed)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("[capture] Npcap not available: %v", err)
		return false
	}

	log.Printf("[capture] Npcap available with %d devices", len(devices))
	return len(devices) > 0
}

// Capture runs Npcap capture with promiscuous mode and returns the output file path
// If interface is "any" or "all", captures from all active interfaces in parallel
func (c *NpcapCapturer) Capture(ctx context.Context, config common.CaptureConfig) (string, error) {
	c.outputDir = config.OutputDir

	// Clean output directory of .pcap files before capture
	entries, err := os.ReadDir(c.outputDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".pcap" {
				os.Remove(filepath.Join(c.outputDir, entry.Name()))
			}
		}
	}

	// Get device names for Npcap
	deviceNames, err := getDeviceNamesForInterface(config.Interface)
	if err != nil {
		return "", fmt.Errorf("failed to find devices for interface %s: %w", config.Interface, err)
	}

	if len(deviceNames) == 0 {
		return "", fmt.Errorf("no suitable devices found for interface %s", config.Interface)
	}

	// Create output PCAP file
	timestamp := time.Now().Format("20060102_150405")
	pcapFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.pcap", timestamp))

	f, err := os.Create(pcapFile)
	if err != nil {
		return "", fmt.Errorf("failed to create pcap file: %w", err)
	}
	defer f.Close()

	// For multi-interface capture, we need to use a consistent link type
	// We'll use Ethernet (1) as the standard link type
	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65536, 1); err != nil { // LinkType 1 = Ethernet
		return "", fmt.Errorf("failed to write pcap header: %w", err)
	}

	if len(deviceNames) == 1 {
		// Single interface capture
		log.Printf("[capture] Starting Npcap capture on device: %s (interface: %s)", deviceNames[0].Name, config.Interface)
		err := c.captureSingleInterface(ctx, deviceNames[0].Name, writer, config.CaptureWindow)
		return pcapFile, err
	}

	// Multi-interface capture
	log.Printf("[capture] Starting Npcap capture on %d interfaces with promiscuous mode", len(deviceNames))
	for _, dev := range deviceNames {
		log.Printf("[capture]   - %s (%s)", dev.Name, dev.Description)
	}

	return c.captureMultipleInterfaces(ctx, deviceNames, writer, config.CaptureWindow, pcapFile)
}

// captureSingleInterface captures from a single device
func (c *NpcapCapturer) captureSingleInterface(ctx context.Context, deviceName string, writer *pcapgo.Writer, duration time.Duration) error {
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", deviceName, err)
	}
	defer handle.Close()

	log.Printf("[capture] Capturing for %v with promiscuous mode enabled...", duration)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(duration)
	packetCount := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("[capture] Capture cancelled by context")
			return ctx.Err()

		case <-timeout:
			log.Printf("[capture] Capture completed: %d packets captured", packetCount)
			return nil

		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				log.Printf("[capture] Warning: failed to write packet: %v", err)
				continue
			}
			packetCount++
		}
	}
}

// captureMultipleInterfaces captures from multiple devices in parallel
func (c *NpcapCapturer) captureMultipleInterfaces(ctx context.Context, devices []deviceInfo, writer *pcapgo.Writer, duration time.Duration, pcapFile string) (string, error) {
	type packetData struct {
		info gopacket.CaptureInfo
		data []byte
	}

	packetChan := make(chan packetData, 1000) // Buffered channel for packets from all interfaces
	doneChan := make(chan struct{})
	errorChan := make(chan error, len(devices))

	// Start capture on each interface
	for _, device := range devices {
		go func(devName, devDesc string) {
			handle, err := pcap.OpenLive(devName, 65536, true, pcap.BlockForever)
			if err != nil {
				log.Printf("[capture] Failed to open device %s: %v", devName, err)
				errorChan <- err
				return
			}
			defer handle.Close()

			log.Printf("[capture] Started capture on %s (%s)", devName, devDesc)

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			timeout := time.After(duration)

			for {
				select {
				case <-ctx.Done():
					return
				case <-timeout:
					return
				case <-doneChan:
					return
				case packet := <-packetSource.Packets():
					if packet == nil {
						continue
					}
					// Copy packet data to avoid race conditions
					dataCopy := make([]byte, len(packet.Data()))
					copy(dataCopy, packet.Data())

					select {
					case packetChan <- packetData{info: packet.Metadata().CaptureInfo, data: dataCopy}:
					case <-doneChan:
						return
					}
				}
			}
		}(device.Name, device.Description)
	}

	// Writer goroutine collects packets from all interfaces
	log.Printf("[capture] Capturing for %v from %d interfaces...", duration, len(devices))

	timeout := time.After(duration)
	packetCount := 0

	for {
		select {
		case <-ctx.Done():
			close(doneChan)
			log.Printf("[capture] Capture cancelled by context")
			return pcapFile, ctx.Err()

		case <-timeout:
			close(doneChan)
			// Give a moment for remaining packets to arrive
			time.Sleep(100 * time.Millisecond)

			// Drain remaining packets from channel
			for {
				select {
				case pkt := <-packetChan:
					if err := writer.WritePacket(pkt.info, pkt.data); err != nil {
						log.Printf("[capture] Warning: failed to write packet: %v", err)
					} else {
						packetCount++
					}
				default:
					log.Printf("[capture] Capture completed: %d packets captured from %d interfaces", packetCount, len(devices))
					return pcapFile, nil
				}
			}

		case pkt := <-packetChan:
			if err := writer.WritePacket(pkt.info, pkt.data); err != nil {
				log.Printf("[capture] Warning: failed to write packet: %v", err)
				continue
			}
			packetCount++

		case err := <-errorChan:
			// Log error but don't fail - other interfaces might work
			log.Printf("[capture] Interface error (continuing): %v", err)
		}
	}
}

// deviceInfo holds device name and description
type deviceInfo struct {
	Name        string
	Description string
}

// getDeviceNamesForInterface converts an interface identifier to Npcap device name(s)
// Returns multiple devices for "any" or "all", single device otherwise
func getDeviceNamesForInterface(interfaceID string) ([]deviceInfo, error) {
	// If interfaceID is "any" or "all", return ALL active devices
	if interfaceID == "any" || interfaceID == "all" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate devices: %w", err)
		}
		if len(devices) == 0 {
			return nil, fmt.Errorf("no network devices found")
		}

		// Collect all devices with IP addresses (indicates active interface)
		var activeDevices []deviceInfo
		for _, device := range devices {
			if len(device.Addresses) > 0 {
				// Skip loopback adapter
				if device.Name == "\\Device\\NPF_Loopback" {
					continue
				}
				activeDevices = append(activeDevices, deviceInfo{
					Name:        device.Name,
					Description: device.Description,
				})
			}
		}

		if len(activeDevices) > 0 {
			log.Printf("[capture] Found %d active interfaces with IP addresses", len(activeDevices))
			return activeDevices, nil
		}

		// Fallback: if no device has IP addresses, use first non-loopback device
		for _, device := range devices {
			if device.Name != "\\Device\\NPF_Loopback" {
				log.Printf("[capture] WARNING: No devices with IP addresses found, using first device: %s", device.Name)
				return []deviceInfo{{Name: device.Name, Description: device.Description}}, nil
			}
		}

		return nil, fmt.Errorf("no suitable network devices found")
	}

	// Single specific interface requested
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate devices: %w", err)
	}

	// Try exact match first
	for _, device := range devices {
		if device.Name == interfaceID {
			return []deviceInfo{{Name: device.Name, Description: device.Description}}, nil
		}
	}

	// Try partial match on description
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			log.Printf("[capture] Checking device: %s (description: %s)", device.Name, device.Description)
			if interfaceID != "" {
				log.Printf("[capture] Using device %s for interface %s", device.Name, interfaceID)
				return []deviceInfo{{Name: device.Name, Description: device.Description}}, nil
			}
		}
	}

	// If no match found, return first available device with a warning
	if len(devices) > 0 {
		log.Printf("[capture] WARNING: Could not find exact match for interface %s, using first available device: %s", interfaceID, devices[0].Name)
		return []deviceInfo{{Name: devices[0].Name, Description: devices[0].Description}}, nil
	}

	return nil, fmt.Errorf("no suitable device found for interface %s", interfaceID)
}
