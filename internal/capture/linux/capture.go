package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	"EnigmaNetz/Enigma-Go-Agent/internal/logger"
)

type LinuxCapturer struct {
	cmd        *exec.Cmd
	outputDir  string
	lastStatus common.CaptureStatus
	log        *logger.Logger
}

func NewLinuxCapturer() *LinuxCapturer {
	return &LinuxCapturer{
		lastStatus: common.CaptureStatus{
			IsRunning: false,
		},
		log: logger.GetLogger(),
	}
}

func (c *LinuxCapturer) Start(ctx context.Context, config common.CaptureConfig) error {
	c.log.Info("Starting Linux capture with config: %+v", config)

	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		c.log.Error("Failed to create output directory: %v", err)
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	c.outputDir = config.OutputDir
	c.log.Debug("Output directory set to: %s", config.OutputDir)

	// Start capture loop in background
	go c.captureLoop(ctx, config)

	return nil
}

func (c *LinuxCapturer) Stop() error {
	c.log.Info("Stopping Linux capture")
	if c.cmd != nil && c.cmd.Process != nil {
		if err := c.cmd.Process.Kill(); err != nil {
			c.log.Error("Failed to stop tshark: %v", err)
			return fmt.Errorf("failed to stop tshark: %v", err)
		}
		c.log.Debug("Successfully stopped tshark process")
	}
	c.lastStatus.IsRunning = false
	return nil
}

func (c *LinuxCapturer) Status() (common.CaptureStatus, error) {
	c.log.Debug("Current capture status: %+v", c.lastStatus)
	return c.lastStatus, nil
}

func (c *LinuxCapturer) captureLoop(ctx context.Context, config common.CaptureConfig) {
	ticker := time.NewTicker(config.CaptureInterval)
	defer ticker.Stop()

	c.log.Info("Starting capture loop with interval: %v", config.CaptureInterval)

	for {
		select {
		case <-ctx.Done():
			c.log.Info("Capture loop terminated by context")
			return
		case <-ticker.C:
			if err := c.runCapture(config); err != nil {
				c.log.Error("Capture failed: %v", err)
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

	c.log.Debug("Starting new capture to file: %s", outputFile)

	// Build tshark command
	args := []string{
		"-i", "any", // Capture on all interfaces
		"-a", fmt.Sprintf("duration:%d", int(config.CaptureWindow.Seconds())), // Capture duration
		"-w", outputFile, // Output file
	}

	c.log.Debug("Running tshark with args: %v", args)

	// Start tshark
	c.cmd = exec.Command("tshark", args...)
	c.lastStatus.IsRunning = true
	c.lastStatus.LastCapture = time.Now()

	// Run capture
	if err := c.cmd.Run(); err != nil {
		c.log.Error("Tshark capture failed: %v", err)
		return fmt.Errorf("tshark capture failed: %v", err)
	}

	// Check capture file size
	if info, err := os.Stat(outputFile); err == nil {
		c.log.Info("Capture completed. File size: %d bytes", info.Size())
	}

	return nil
}
