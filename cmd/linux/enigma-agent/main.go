package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/linux"
	"EnigmaNetz/Enigma-Go-Agent/internal/processor"
)

func main() {
	// Parse command line flags
	baseDir := flag.String("dir", "/opt/enigma", "Base directory for Enigma agent")
	captureWindow := flag.Duration("window", 30*time.Second, "Duration of each capture")
	captureInterval := flag.Duration("interval", 2*time.Minute, "Interval between captures")
	flag.Parse()

	// Set up directory structure
	captureDir := filepath.Join(*baseDir, "captures")
	logsDir := filepath.Join(*baseDir, "logs")

	// Create directories
	for _, dir := range []string{captureDir, logsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Error creating directory %s: %v\n", dir, err)
			os.Exit(1)
		}
	}

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and start capturer
	capturer := linux.NewLinuxCapturer()
	config := common.CaptureConfig{
		CaptureWindow:   *captureWindow,
		CaptureInterval: *captureInterval,
		OutputDir:       captureDir,
	}

	if err := capturer.Start(ctx, config); err != nil {
		fmt.Printf("Error starting capture: %v\n", err)
		os.Exit(1)
	}

	// Create and start processor
	proc := processor.NewPcapProcessor(captureDir, logsDir)
	if err := proc.Start(ctx); err != nil {
		fmt.Printf("Error starting processor: %v\n", err)
		os.Exit(1)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Clean shutdown
	fmt.Println("\nShutting down...")
	cancel()
	if err := capturer.Stop(); err != nil {
		fmt.Printf("Error stopping capture: %v\n", err)
	}
}
