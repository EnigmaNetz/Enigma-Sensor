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
	"EnigmaNetz/Enigma-Go-Agent/internal/logger"
	"EnigmaNetz/Enigma-Go-Agent/internal/processor"
)

func main() {
	// Parse command line flags
	baseDir := flag.String("dir", "/opt/enigma", "Base directory for Enigma agent")
	captureWindow := flag.Duration("window", 30*time.Second, "Duration of each capture")
	captureInterval := flag.Duration("interval", 2*time.Minute, "Interval between captures")
	logLevel := flag.String("loglevel", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	// Initialize logger
	level, err := logger.ParseLogLevel(*logLevel)
	if err != nil {
		fmt.Printf("Invalid log level %s: %v\n", *logLevel, err)
		os.Exit(1)
	}

	logConfig := logger.Config{
		LogLevel: level,
		LogFile:  filepath.Join(*baseDir, "logs", "agent.log"),
		MaxSize:  100, // 100MB max file size
	}

	log, err := logger.NewLogger(logConfig)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	if err := run(*baseDir, *captureWindow, *captureInterval, *log); err != nil {
		log.Error("Fatal error: %v", err)
		os.Exit(1)
	}
}

func run(baseDir string, captureWindow, captureInterval time.Duration, log logger.Logger) error {
	// Set up directory structure
	captureDir := filepath.Join(baseDir, "captures")
	logsDir := filepath.Join(baseDir, "logs")

	// Create directories
	for _, dir := range []string{captureDir, logsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and start capturer
	capturer := linux.NewLinuxCapturer()
	config := common.CaptureConfig{
		CaptureWindow:   captureWindow,
		CaptureInterval: captureInterval,
		OutputDir:       captureDir,
	}

	if err := capturer.Start(ctx, config); err != nil {
		return fmt.Errorf("starting capture: %w", err)
	}

	// Create and start processor
	proc := processor.NewPcapProcessor(captureDir, logsDir)
	if err := proc.Start(ctx); err != nil {
		return fmt.Errorf("starting processor: %w", err)
	}

	log.Info("%s: captureDir=%s logsDir=%s window=%v interval=%v",
		"Agent started successfully",
		captureDir,
		logsDir,
		captureWindow,
		captureInterval)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	// Clean shutdown
	log.Info("%s: signal=%v", "Initiating shutdown", sig)
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- capturer.Stop()
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return fmt.Errorf("stopping capture: %w", err)
		}
	case <-shutdownCtx.Done():
		return fmt.Errorf("shutdown timeout")
	}

	log.Info("Agent shutdown complete")
	return nil
}
