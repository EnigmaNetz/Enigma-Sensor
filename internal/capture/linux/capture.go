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
	return c.runCapture(ctx, config)
}

// runCapture executes tcpdump and returns the output file path or error
func (c *LinuxCapturer) runCapture(ctx context.Context, config common.CaptureConfig) (string, error) {
	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	outputFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.pcap", timestamp))

	// Build tcpdump command
	args := []string{
		"-i", "any", // Capture on all interfaces
		"-w", outputFile, // Write to file
		"-G", fmt.Sprintf("%d", int(config.CaptureWindow.Seconds())), // Rotate after duration
		"-W", "1", // Create only one file
		"-K",      // Don't verify checksums
		"-n",      // Don't convert addresses
		"-q",      // Quick output
		"-s", "0", // Capture entire packet
	}

	log.Printf("[capture] Running tcpdump command: tcpdump %v", args)

	c.cmd = commandContext("tcpdump", args...)

	// Capture stdout and stderr
	stdoutPipe, _ := c.cmd.StdoutPipe()
	stderrPipe, _ := c.cmd.StderrPipe()

	if err := c.cmd.Start(); err != nil {
		log.Printf("[capture] Failed to start tcpdump: %v", err)
		return "", fmt.Errorf("tcpdump start failed: %v", err)
	}

	// Log stdout and stderr in goroutines
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			log.Printf("[capture][tcpdump stdout] %s", scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[capture][tcpdump stderr] %s", scanner.Text())
		}
	}()

	err := c.cmd.Wait()
	if err != nil {
		log.Printf("[capture] tcpdump capture failed: %v", err)
		return "", fmt.Errorf("tcpdump capture failed: %v", err)
	}

	// Log file size after capture
	fileInfo, statErr := os.Stat(outputFile)
	if statErr != nil {
		log.Printf("[capture] Could not stat output file: %v", statErr)
	} else {
		log.Printf("[capture] Output file %s size: %d bytes", outputFile, fileInfo.Size())
		if fileInfo.Size() == 0 {
			log.Printf("[capture][warning] Output PCAP file is empty!")
		}
	}

	return outputFile, nil
}
