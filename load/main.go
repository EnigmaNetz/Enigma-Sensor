package main

import (
	"context"
	"flag"
	"log"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	"EnigmaNetz/Enigma-Go-Agent/internal/processor"
	"EnigmaNetz/Enigma-Go-Agent/load"
)

func main() {
	duration := flag.Duration("duration", 5*time.Second, "traffic generation duration")
	output := flag.String("output", "./captures", "capture output directory")
	server := flag.String("server", "api.enigmaai.net:443", "API server")
	apiKey := flag.String("api-key", "", "API key")
	flag.Parse()

	capCfg := common.CaptureConfig{CaptureWindow: *duration, OutputDir: *output}
	capturer := capture.NewCapturer(capCfg)
	processor := processor.NewProcessor()
	uploader, err := api.NewLogUploader(*server, *apiKey)
	if err != nil {
		log.Fatalf("failed to create uploader: %v", err)
	}

	cfg := load.Config{Duration: *duration, OutputDir: *output}
	if err := load.RunSyntheticCaptureLoad(context.Background(), capturer, processor, uploader, cfg); err != nil {
		log.Fatalf("synthetic capture failed: %v", err)
	}
}
