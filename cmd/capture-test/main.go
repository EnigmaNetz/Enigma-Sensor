package main

import (
	"flag"
	"log"
	"os"
	"runtime"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
)

func main() {
	// Parse command line flags
	outputDir := flag.String("output", "logs", "Directory for output files")
	window := flag.Int("window", 30, "Capture window in seconds")
	flag.Parse()

	// Create config
	cfg := capture.Config{
		OutputDir:     *outputDir,
		CaptureWindow: *window,
	}

	// Ensure output directory exists
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Create platform-specific capturer
	var capturer capture.PacketCapturer
	switch runtime.GOOS {
	case "windows":
		capturer = capture.NewWindowsCapturer(cfg)
	case "linux":
		capturer = capture.NewLinuxCapturer(cfg)
	default:
		log.Fatalf("Unsupported platform: %s", runtime.GOOS)
	}

	// Start capture
	log.Printf("Starting capture for %d seconds...", cfg.CaptureWindow)
	if err := capturer.StartCapture(); err != nil {
		log.Fatalf("Capture failed: %v", err)
	}

	// Get output files
	dnsLog, connLog, err := capturer.OutputFiles()
	if err != nil {
		log.Fatalf("Failed to get output files: %v", err)
	}

	log.Printf("Capture complete. Output files:\n  DNS Log: %s\n  Conn Log: %s", dnsLog, connLog)
}
