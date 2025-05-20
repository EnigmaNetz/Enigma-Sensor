//go:build linux || darwin

package linux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
)

type LinuxCapturer struct {
	cmd       *exec.Cmd
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

// runCapture executes tcpdump and returns the output file path or error
func (c *LinuxCapturer) runCapture(ctx context.Context, config common.CaptureConfig) (string, error) {
	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	outputFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.pcap", timestamp))

	// Choose interface: use config.Interface if set, otherwise 'any'
	iface := "any"
	if config.Interface != "" {
		iface = config.Interface
	}

	// Build tcpdump command
	args := []string{
		"-i", iface, // Capture on selected interface
		"-w", outputFile, // Write to file
		"-G", fmt.Sprintf("%d", int(config.CaptureWindow.Seconds())), // Rotate after duration
		"-W", "1", // Create only one file
		"-K",      // Don't verify checksums
		"-n",      // Don't convert addresses
		"-q",      // Quick output
		"-s", "0", // Capture entire packet
	}

	c.cmd = commandContext("tcpdump", args...)

	// Capture stdout and stderr (must be before Start)
	stdoutPipe, _ := c.cmd.StdoutPipe()
	stderrPipe, _ := c.cmd.StderrPipe()

	// Start the process
	if err := c.cmd.Start(); err != nil {
		return "", fmt.Errorf("tcpdump start failed: %v", err)
	}

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

	err := c.cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("tcpdump capture failed: %v", err)
	}

	return outputFile, nil
}
