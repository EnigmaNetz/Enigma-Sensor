//go:build windows || linux
// +build windows linux

// Package main is the entrypoint for the Enigma Go Agent.
package main

import (
	"log"
	"runtime"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
)

// stubLinuxManager is a placeholder for non-Linux builds.
func stubLinuxManager(cfg capture.Config) capture.CaptureManager {
	log.Println("[INFO] Linux capture manager not implemented.")
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("[Enigma] ")
	log.Println("[INFO] Enigma Go Agent starting up...")

	// TODO: Load config from file/env
	cfg := capture.Config{
		OutputDir:       "./logs", // Example path
		CaptureWindow:   30,
		CaptureInterval: 120,
		RetentionDays:   7,
	}
	log.Printf("[DEBUG] Loaded config: %+v\n", cfg)

	var manager capture.CaptureManager
	log.Printf("[INFO] Detected OS: %s\n", runtime.GOOS)
	switch runtime.GOOS {
	case "windows":
		log.Println("[INFO] Initializing Windows capture manager...")
		manager = capture.NewWindowsCaptureManager(cfg)
	case "linux":
		log.Println("[INFO] Initializing Linux capture manager...")
		// Use stub if not implemented
		manager = stubLinuxManager(cfg)
	default:
		log.Printf("[ERROR] Unsupported OS: %s\n", runtime.GOOS)
		return
	}

	if manager == nil {
		log.Println("[ERROR] No capture manager available for this OS.")
		return
	}

	log.Println("[INFO] Starting capture manager...")
	if err := manager.Start(); err != nil {
		log.Printf("[ERROR] Failed to start capture manager: %v\n", err)
		return
	}

	log.Println("[INFO] Capture manager started. Agent is running.")
	// TODO: Implement graceful shutdown (signal handling)
	for {
		time.Sleep(10 * time.Second)
	}
}
