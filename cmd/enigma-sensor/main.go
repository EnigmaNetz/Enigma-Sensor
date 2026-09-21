package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/config"
	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
	collect_logs "EnigmaNetz/Enigma-Go-Sensor/internal/collect_logs"
	"EnigmaNetz/Enigma-Go-Sensor/internal/processor"
	"EnigmaNetz/Enigma-Go-Sensor/internal/sensor"
	"EnigmaNetz/Enigma-Go-Sensor/internal/version"

	"gopkg.in/natefinch/lumberjack.v2"
)

func printHelp() {
	fmt.Print(`Enigma Sensor - Network Capture & Processing Tool

Usage: enigma-sensor [collect-logs] [--version|-v] [--help|-h]

Runs a network capture and processing session using config.json.

Options:
  collect-logs    Package logs, captures, config (API key masked), and diagnostics for support
  --version, -v   Print version and exit
  --help, -h      Show this help message and exit

Configuration:
  The sensor loads /etc/enigma-sensor/config.json (C:\ProgramData\EnigmaSensor\config.json on
  Windows) if it exists, otherwise config.json in the working directory.
  You can customize logging, capture, and Enigma API settings in this file.
  See config.example.json for a template and documentation of all options.

Example:
  enigma-sensor
    Runs a single capture and processing session using config.json.

  enigma-sensor collect-logs
    Packages logs, captures, config, and diagnostics into an archive for support.

  enigma-sensor --help
    Shows this help message.

  enigma-sensor --version
    Prints the sensor version.
`)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--help", "-h":
			printHelp()
			return
		case "--version", "-v":
			fmt.Println(version.Version)
			return
		case "collect-logs":
			outName := fmt.Sprintf("enigma-logs-%s%s", time.Now().Format("20060102-150405"), collect_logs.ArchiveExt)
			size, err := collect_logs.CollectLogs(outName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to collect logs: %v\n", err)
				os.Exit(1)
			}
			if abs, err := filepath.Abs(outName); err == nil {
				outName = abs
			}
			fmt.Printf("Created %s (%d bytes) with logs, config, and diagnostics.\n", outName, size)
			return
		}
	}
	// Load the first config file that exists. A file that exists but fails
	// validation stops startup rather than falling through to the next path.
	configPath, err := config.FindPath(config.Paths(runtime.GOOS))
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", configPath, err)
	}

	// Set up standard logger to log to file if specified
	if cfg.Logging.File != "" {
		logDir := filepath.Dir(cfg.Logging.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			log.Fatalf("Failed to create log directory: %v", err)
		}
		// Use lumberjack for log rotation based on config
		logWriter := &lumberjack.Logger{
			Filename:   cfg.Logging.File,
			MaxSize:    int(cfg.Logging.MaxSizeMB),   // megabytes
			MaxAge:     cfg.Logging.LogRetentionDays, // days
			MaxBackups: cfg.Logging.MaxBackups,       // number of old log files to retain
			Compress:   true,                         // compress rotated logs
		}
		log.SetOutput(io.MultiWriter(os.Stdout, logWriter))
		log.Printf("Log rotation configured: max size %dMB, retention %d days, max backups %d", cfg.Logging.MaxSizeMB, cfg.Logging.LogRetentionDays, cfg.Logging.MaxBackups)
	}

	log.Printf("Loaded config from %s: %+v", configPath, cfg.Redacted())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Prepare capturer, processor, uploader for sensor.RunSensor
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	capCfg := common.CaptureConfig{
		CaptureWindow: window,
		OutputDir:     cfg.Capture.OutputDir, // Will be overridden per iteration
		Interface:     cfg.Capture.Interface,
	}
	capturer := capture.NewCapturer(capCfg)
	proc := processor.NewProcessor()

	var uploader sensor.Uploader
	if cfg.EnigmaAPI.Upload {
		server := cfg.EnigmaAPI.Server
		apiKey := cfg.EnigmaAPI.APIKey
		if server == "" || apiKey == "" {
			log.Printf("enigma_api.server and enigma_api.api_key must be set to upload logs; skipping upload.")
		} else {
			u, err := api.NewLogUploader(server, apiKey, cfg.NetworkID, cfg.Capture.Interface, cfg.EnigmaAPI.MaxPayloadSizeMB, cfg.Buffering.Dir, cfg.Buffering.MaxAgeHours, cfg.EnigmaAPI.CACertFile)
			if err != nil {
				log.Printf("Failed to initialize LogUploader: %v", err)
			} else {
				uploader = u
			}
		}
	}

	if err := sensor.RunSensor(ctx, cfg, capturer, proc, uploader); err != nil {
		if err == api.ErrAPIGone || err == sensor.ErrAPIGone {
			log.Printf("Sensor stopped due to 410 Gone from API because the API key is invalid. Exiting as instructed.")
			os.Exit(0)
		}
		log.Fatalf("Sensor exited with error: %v", err)
	}
}
