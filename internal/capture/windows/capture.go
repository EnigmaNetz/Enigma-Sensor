package windows

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
)

type WindowsCapturer struct {
	cmd        *exec.Cmd
	outputDir  string
	lastStatus common.CaptureStatus
}

func NewWindowsCapturer() *WindowsCapturer {
	return &WindowsCapturer{
		lastStatus: common.CaptureStatus{
			IsRunning: false,
		},
	}
}

func (c *WindowsCapturer) Start(ctx context.Context, config common.CaptureConfig) error {
	c.outputDir = config.OutputDir

	// Start capture loop in background
	go c.captureLoop(ctx, config)

	return nil
}

func (c *WindowsCapturer) Stop() error {
	if c.cmd != nil && c.cmd.Process != nil {
		if err := c.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to stop pktmon: %v", err)
		}
	}
	c.lastStatus.IsRunning = false
	return nil
}

func (c *WindowsCapturer) Status() (common.CaptureStatus, error) {
	return c.lastStatus, nil
}

func (c *WindowsCapturer) captureLoop(ctx context.Context, config common.CaptureConfig) {
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

func (c *WindowsCapturer) runCapture(config common.CaptureConfig) error {
	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	outputFile := fmt.Sprintf("%s/capture_%s.etl", c.outputDir, timestamp)

	// Start pktmon capture
	c.cmd = exec.Command("pktmon", "start", "--capture", "--file", outputFile)
	c.lastStatus.IsRunning = true
	c.lastStatus.LastCapture = time.Now()

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start pktmon: %v", err)
	}

	// Wait for capture duration
	time.Sleep(config.CaptureWindow)

	// Stop capture
	stopCmd := exec.Command("pktmon", "stop")
	if err := stopCmd.Run(); err != nil {
		return fmt.Errorf("failed to stop pktmon: %v", err)
	}

	return nil
}
