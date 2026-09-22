//go:build linux || darwin

package linux

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/config"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
)

type LinuxCapturer struct {
	cmds      []*exec.Cmd
	outputDir string
}

var commandContext = exec.Command

func NewLinuxCapturer() *LinuxCapturer {
	return &LinuxCapturer{}
}

// Capture runs a single tcpdump capture and returns the output file path or error
func (c *LinuxCapturer) Capture(ctx context.Context, config common.CaptureConfig) (string, error) {
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
	return c.runCapture(ctx, config)
}

// runCapture executes simultaneous tcpdump processes for multiple interfaces
func (c *LinuxCapturer) runCapture(ctx context.Context, captureConfig common.CaptureConfig) (string, error) {
	// Parse all valid interfaces from comma-separated list
	cfg := &config.Config{}
	cfg.Capture.Interface = captureConfig.Interface
	interfaces, err := cfg.GetAllInterfaces()
	if err != nil {
		return "", fmt.Errorf("failed to parse interface configuration: %w", err)
	}

	// Generate timestamp for consistent naming
	timestamp := time.Now().Format("20060102_150405")

	// Single interface: use simple single capture
	if len(interfaces) == 1 {
		return c.runSingleCapture(ctx, interfaces[0], timestamp, captureConfig)
	}

	// Multiple interfaces: run simultaneous capture and merge
	return c.runMultiInterfaceCapture(ctx, interfaces, timestamp, captureConfig)
}

// runSingleCapture handles single interface or "any" capture
func (c *LinuxCapturer) runSingleCapture(ctx context.Context, iface string, timestamp string, captureConfig common.CaptureConfig) (string, error) {
	outputFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.pcap", timestamp))

	args := []string{
		"-i", iface, // Capture on specified interface
		"-w", outputFile, // Write to file
		"-G", fmt.Sprintf("%d", int(captureConfig.CaptureWindow.Seconds())), // Rotate after duration
		"-W", "1", // Create only one file
		"-K",      // Don't verify checksums
		"-n",      // Don't convert addresses
		"-q",      // Quick output
		"-s", "0", // Capture entire packet
	}

	cmd := commandContext("tcpdump", args...)
	c.cmds = []*exec.Cmd{cmd}

	// Capture stdout and stderr (must be before Start)
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	// Start the process
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("tcpdump start failed for interface %s: %v", iface, err)
	}

	log.Printf("[capture] Started tcpdump for interface: %s", iface)

	// Log stdout and stderr in goroutines if pipes are valid
	if stdoutPipe != nil {
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
			}
		}()
	}
	if stderrPipe != nil {
		go func() {
			scanner := bufio.NewScanner(stderrPipe)
			for scanner.Scan() {
			}
		}()
	}

	err := cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("tcpdump capture failed for interface %s: %v", iface, err)
	}

	return outputFile, nil
}

// runMultiInterfaceCapture handles simultaneous capture from multiple interfaces
func (c *LinuxCapturer) runMultiInterfaceCapture(ctx context.Context, interfaces []string, timestamp string, captureConfig common.CaptureConfig) (string, error) {
	log.Printf("[capture] Starting simultaneous capture on %d interfaces: %v", len(interfaces), interfaces)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var captureErrors []error
	var outputFiles []string

	// Start tcpdump process for each interface
	for i, iface := range interfaces {
		wg.Add(1)
		go func(interfaceIndex int, interfaceName string) {
			defer wg.Done()

			// Create unique output file for each interface
			outputFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s_iface%d_%s.pcap", timestamp, interfaceIndex, interfaceName))

			args := []string{
				"-i", interfaceName, // Capture on this specific interface
				"-w", outputFile, // Write to interface-specific file
				"-G", fmt.Sprintf("%d", int(captureConfig.CaptureWindow.Seconds())), // Rotate after duration
				"-W", "1", // Create only one file
				"-K",      // Don't verify checksums
				"-n",      // Don't convert addresses
				"-q",      // Quick output
				"-s", "0", // Capture entire packet
			}

			cmd := commandContext("tcpdump", args...)

			// Thread-safe command tracking
			mu.Lock()
			c.cmds = append(c.cmds, cmd)
			mu.Unlock()

			// Capture stdout and stderr
			stdoutPipe, _ := cmd.StdoutPipe()
			stderrPipe, _ := cmd.StderrPipe()

			// Start the process
			if err := cmd.Start(); err != nil {
				mu.Lock()
				captureErrors = append(captureErrors, fmt.Errorf("failed to start tcpdump for interface %s: %v", interfaceName, err))
				mu.Unlock()
				return
			}

			log.Printf("[capture] Started tcpdump for interface: %s", interfaceName)

			// Log stdout and stderr in goroutines
			if stdoutPipe != nil {
				go func() {
					scanner := bufio.NewScanner(stdoutPipe)
					for scanner.Scan() {
					}
				}()
			}
			if stderrPipe != nil {
				go func() {
					scanner := bufio.NewScanner(stderrPipe)
					for scanner.Scan() {
					}
				}()
			}

			// Wait for process to complete
			if err := cmd.Wait(); err != nil {
				// Nothing will process a failed interface's partial capture
				os.Remove(outputFile)
				mu.Lock()
				captureErrors = append(captureErrors, fmt.Errorf("tcpdump capture failed for interface %s: %v", interfaceName, err))
				mu.Unlock()
				return
			}

			// Add successful output file
			mu.Lock()
			outputFiles = append(outputFiles, outputFile)
			mu.Unlock()

			log.Printf("[capture] Completed tcpdump for interface: %s", interfaceName)
		}(i, iface)
	}

	// Wait for all capture processes to complete
	wg.Wait()

	// Check for any capture errors
	if len(captureErrors) > 0 {
		// Log all errors but don't fail if at least one interface succeeded
		for _, err := range captureErrors {
			log.Printf("[capture] Error: %v", err)
		}
		if len(outputFiles) == 0 {
			return "", fmt.Errorf("all interface captures failed: %d errors", len(captureErrors))
		}
	}

	// If only one interface succeeded, return that file directly
	if len(outputFiles) == 1 {
		return outputFiles[0], nil
	}

	// Multiple files: merge them into a single output file
	mergedFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.pcap", timestamp))
	if err := mergePcapFiles(outputFiles, mergedFile); err != nil {
		// Nothing will process these files, so don't leave full-packet captures on disk
		for _, file := range outputFiles {
			os.Remove(file)
		}
		return "", fmt.Errorf("failed to merge pcap files: %w", err)
	}

	// Clean up individual interface files after successful merge
	for _, file := range outputFiles {
		os.Remove(file)
	}

	log.Printf("[capture] Successfully merged %d interface captures into: %s", len(outputFiles), mergedFile)
	return mergedFile, nil
}
