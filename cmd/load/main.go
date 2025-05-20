package main

import (
	"context"
	"flag"
	"fmt"
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
	server := flag.String("server", "api.enigmaai.net:443", "API server")
	apiKey := flag.String("api-key", "", "API key")
	rps := flag.Int("rps", 100, "target requests per second (default 100)")
	throughput := flag.Int("throughput", 1, "target network throughput in MB/sec (default 1)")
	flag.Parse()

	capCfg := common.CaptureConfig{CaptureWindow: *duration, OutputDir: "./captures", Interface: "lo"}
	capturer := capture.NewCapturer(capCfg)
	processor := processor.NewProcessor()
	uploader, err := api.NewLogUploader(*server, *apiKey)
	if err != nil {
		log.Fatalf("failed to create uploader: %v", err)
	}

	cfg := load.Config{Duration: *duration, RPS: *rps, Throughput: *throughput}
	if err := load.RunSyntheticCaptureLoad(context.Background(), capturer, processor, uploader, cfg); err != nil {
		// Try to extract status code and message from error string
		errStr := err.Error()
		var code int
		var msg string
		// Look for pattern: "upload failed: <msg> (code: <code>)"
		if n, _ := fmt.Sscanf(errStr, "upload failed: %s (code: %d)", &msg, &code); n == 2 {
			log.Fatalf("synthetic capture failed: server responded with code %d, message: %s", code, msg)
		} else {
			log.Fatalf("synthetic capture failed: %v", err)
		}
	}
}
