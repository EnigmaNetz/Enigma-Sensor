//go:build windows

package main

import (
	"log"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("[Enigma] ")
	log.Println("[INFO] Enigma Go Agent starting up (Windows)...")

	cfg := capture.Config{
		OutputDir:       "./logs", // Example path
		CaptureWindow:   30,
		CaptureInterval: 120,
		RetentionDays:   7,
	}
	log.Printf("[DEBUG] Loaded config: %+v\n", cfg)

	log.Println("[INFO] Initializing Windows capture manager...")
	manager := capture.NewWindowsCaptureManager(cfg)

	log.Println("[INFO] Starting capture manager...")
	if err := manager.Start(); err != nil {
		log.Printf("[ERROR] Failed to start capture manager: %v\n", err)
		return
	}

	log.Println("[INFO] Capture manager started. Agent is running.")
	for {
		time.Sleep(10 * time.Second)
	}
}
