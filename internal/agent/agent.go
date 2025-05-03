package agent

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/config"
	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
)

// Capturer abstracts the capture logic
// (You can use mockgen for tests)
//
//go:generate mockgen -destination=mock_capturer.go -package=agent . Capturer
type Capturer interface {
	Capture(ctx context.Context, cfg common.CaptureConfig) (string, error)
}

type Processor interface {
	ProcessPCAP(pcapPath string) (types.ProcessedData, error)
}

type Uploader interface {
	UploadLogs(ctx context.Context, files api.LogFiles) error
}

// RunAgent orchestrates capture, processing, and upload with graceful shutdown
func RunAgent(ctx context.Context, cfg *config.Config, capturer Capturer, processor Processor, uploader Uploader) error {
	outputDir := cfg.Capture.OutputDir
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	loop := cfg.Capture.Loop

	pcapQueue := make(chan string, 4)
	var wg sync.WaitGroup

	// Processing worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		for pcapPath := range pcapQueue {
			absPCAPPath, err := filepath.Abs(pcapPath)
			if err != nil {
				log.Printf("[worker] Failed to get absolute path for PCAP: %v", err)
				continue
			}
			if _, err := os.Stat(absPCAPPath); err != nil {
				log.Printf("[worker] PCAP file does not exist or is not accessible: %v", err)
				continue
			}
			log.Printf("[worker] Processing PCAP file at absolute path: %s", absPCAPPath)

			result, err := processor.ProcessPCAP(absPCAPPath)
			if err != nil {
				log.Printf("[worker] Processing failed: %v", err)
				continue
			}
			log.Printf("[worker] Processing complete. Conn XLSX: %s, DNS XLSX: %s, Metadata: %+v", result.ConnPath, result.DNSPath, result.Metadata)

			if uploader != nil {
				uploadErr := uploader.UploadLogs(ctx, api.LogFiles{
					DNSPath:  result.DNSPath,
					ConnPath: result.ConnPath,
				})
				if uploadErr != nil {
					log.Printf("[worker] Log upload failed: %v", uploadErr)
				} else {
					log.Printf("[worker] Log upload successful.")
				}
			}
		}
	}()

	// Handle Ctrl+C for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	stopped := false

	for {
		select {
		case sig := <-sigCh:
			log.Printf("Received signal %v, shutting down after current capture...", sig)
			stopped = true
			close(pcapQueue)
			break
		default:
		}
		if stopped {
			break
		}
		timestamp := time.Now().UTC().Format("20060102T150405Z")
		zeekOutDir := filepath.Join(outputDir, "zeek_out_"+timestamp)
		if err := os.MkdirAll(zeekOutDir, 0755); err != nil {
			return err
		}
		capCfg := common.CaptureConfig{
			CaptureWindow: window,
			OutputDir:     zeekOutDir,
		}
		log.Printf("Starting capture iteration at %s", timestamp)
		pcapPath, err := capturer.Capture(ctx, capCfg)
		if err != nil {
			return err
		}
		log.Printf("Captured file: %s", pcapPath)
		select {
		case pcapQueue <- pcapPath:
			log.Printf("Enqueued PCAP for processing: %s", pcapPath)
		default:
			log.Printf("[warning] PCAP queue full, dropping capture: %s", pcapPath)
		}
		if !loop {
			break
		}
	}
	log.Printf("Waiting for processing worker to finish...")
	wg.Wait()
	log.Printf("Shutdown complete.")
	return nil
}
