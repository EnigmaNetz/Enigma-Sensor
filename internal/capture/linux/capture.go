package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
)

type LinuxCapturer struct {
	cmd        *exec.Cmd
	outputDir  string
	lastStatus common.CaptureStatus
}

func NewLinuxCapturer() *LinuxCapturer {
	return &LinuxCapturer{
		lastStatus: common.CaptureStatus{
			IsRunning: false,
		},
	}
}

func (c *LinuxCapturer) Start(ctx context.Context, config common.CaptureConfig) error {
	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	c.outputDir = config.OutputDir

	// Start capture loop in background
	go c.captureLoop(ctx, config)

	return nil
}

func (c *LinuxCapturer) Stop() error {
	if c.cmd != nil && c.cmd.Process != nil {
		if err := c.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to stop tshark: %v", err)
		}
	}
	c.lastStatus.IsRunning = false
	return nil
}

func (c *LinuxCapturer) Status() (common.CaptureStatus, error) {
	return c.lastStatus, nil
}

func (c *LinuxCapturer) captureLoop(ctx context.Context, config common.CaptureConfig) {
	ticker := time.NewTicker(config.CaptureInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.runCapture(config); err != nil {
				c.lastStatus.Error = err
				continue
			}
		}
	}
}

func (c *LinuxCapturer) runCapture(config common.CaptureConfig) error {
	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	outputFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.pcapng", timestamp))

	// Build tshark command
	args := []string{
		"-i", "any", // Capture on all interfaces
		"-a", fmt.Sprintf("duration:%d", int(config.CaptureWindow.Seconds())), // Capture duration
		"-w", outputFile, // Output file
	}

	// Start tshark
	c.cmd = exec.Command("tshark", args...)
	c.lastStatus.IsRunning = true
	c.lastStatus.LastCapture = time.Now()

	// Run capture
	if err := c.cmd.Run(); err != nil {
		return fmt.Errorf("tshark capture failed: %v", err)
	}

	return nil
}
