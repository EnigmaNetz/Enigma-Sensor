//go:build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("[Enigma] ")
	log.Println("[INFO] Enigma Go Agent starting up (Linux)...")

	cfg := capture.Config{
		OutputDir:       "./logs", // Example path
		CaptureWindow:   30,
		CaptureInterval: 120,
		RetentionDays:   7,
	}
	log.Printf("[DEBUG] Loaded config: %+v\n", cfg)

	// Create the capture manager with our Linux capturer
	capturer := capture.NewLinuxCapturer(cfg)
	manager := capture.NewCaptureManager(cfg, capturer)

	log.Println("[INFO] Starting capture manager...")
	if err := manager.Start(); err != nil {
		log.Printf("[ERROR] Failed to start capture manager: %v\n", err)
		return
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("[INFO] Capture manager started. Agent is running.")
	<-sigChan // Wait for shutdown signal

	log.Println("[INFO] Shutting down...")
	if err := manager.Stop(); err != nil {
		log.Printf("[ERROR] Error during shutdown: %v\n", err)
	}
}
