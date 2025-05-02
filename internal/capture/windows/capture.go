//go:build windows

package windows

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
)

type WindowsCapturer struct {
	cmd       *exec.Cmd
	outputDir string
}

var commandContext = exec.Command

func NewWindowsCapturer() *WindowsCapturer {
	return &WindowsCapturer{}
}

// Capture runs a single pktmon capture and returns the output file path or error
func (c *WindowsCapturer) Capture(ctx context.Context, config common.CaptureConfig) (string, error) {
	c.outputDir = config.OutputDir
	return c.runCapture(ctx, config)
}

// runCapture executes pktmon and returns the output file path or error
func (c *WindowsCapturer) runCapture(ctx context.Context, config common.CaptureConfig) (string, error) {
	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	outputFile := fmt.Sprintf("%s/capture_%s.etl", c.outputDir, timestamp)

	// Start pktmon capture
	c.cmd = commandContext("pktmon", "start", "--capture", "--file", outputFile)

	if err := c.cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start pktmon: %v", err)
	}

	// Wait for capture duration
	time.Sleep(config.CaptureWindow)

	// Stop capture
	stopCmd := commandContext("pktmon", "stop")
	if err := stopCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to stop pktmon: %v", err)
	}

	return outputFile, nil
}
