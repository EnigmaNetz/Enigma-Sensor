//go:build windows

package windows

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
	// Clean output directory of .etl files before capture
	entries, err := os.ReadDir(c.outputDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".etl" {
				os.Remove(c.outputDir + "/" + entry.Name())
			}
		}
	}
	return c.runCapture(ctx, config)
}

// runCapture executes pktmon and returns the output file path or error
func (c *WindowsCapturer) runCapture(ctx context.Context, config common.CaptureConfig) (string, error) {
	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	etlFile := fmt.Sprintf("%s/capture_%s.etl", c.outputDir, timestamp)

	// Start pktmon capture
	log.Printf("[capture] Running pktmon command: pktmon start --capture --file %s", etlFile)
	c.cmd = commandContext("pktmon", "start", "--capture", "--file", etlFile)

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

	// Detect available pktmon conversion subcommand
	subcommand, err := detectPktmonConversionSubcommand()
	if err != nil {
		return "", err
	}

	// Convert ETL to PCAPNG
	pcapngFile := fmt.Sprintf("%s/capture_%s.pcapng", c.outputDir, timestamp)
	log.Printf("[capture] Running conversion: pktmon %s %s -o %s", subcommand, etlFile, pcapngFile)
	convertCmd := commandContext("pktmon", subcommand, etlFile, "-o", pcapngFile)
	var outBuf, errBuf bytes.Buffer
	convertCmd.Stdout = &outBuf
	convertCmd.Stderr = &errBuf
	if err := convertCmd.Run(); err != nil {
		log.Printf("[capture] pktmon %s stdout: %s", subcommand, outBuf.String())
		log.Printf("[capture] pktmon %s stderr: %s", subcommand, errBuf.String())
		return "", fmt.Errorf("failed to convert ETL to PCAPNG: %v", err)
	}

	return pcapngFile, nil
}

// detectPktmonConversionSubcommand checks which pktmon conversion subcommand is available.
func detectPktmonConversionSubcommand() (string, error) {
	// Try etl2pcapng first
	cmd := exec.Command("pktmon", "etl2pcapng", "/?")
	if err := cmd.Run(); err == nil {
		return "etl2pcapng", nil
	}
	// Fallback to etl2pcap
	cmd = exec.Command("pktmon", "etl2pcap", "/?")
	if err := cmd.Run(); err == nil {
		return "etl2pcap", nil
	}
	return "", fmt.Errorf("neither 'etl2pcapng' nor 'etl2pcap' subcommands are available in pktmon; please update Windows or pktmon")
}
