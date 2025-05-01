package processor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/processor/pcap"
)

type PcapProcessor struct {
	inputDir  string
	outputDir string
	processed map[string]bool
}

func NewPcapProcessor(inputDir, outputDir string) *PcapProcessor {
	return &PcapProcessor{
		inputDir:  inputDir,
		outputDir: outputDir,
		processed: make(map[string]bool),
	}
}

func (p *PcapProcessor) Start(ctx context.Context) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(p.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Start processing loop in background
	go p.processLoop(ctx)

	return nil
}

func (p *PcapProcessor) processLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.checkAndProcessFiles(); err != nil {
				fmt.Printf("Error processing files: %v\n", err)
			}
		}
	}
}

func (p *PcapProcessor) checkAndProcessFiles() error {
	files, err := filepath.Glob(filepath.Join(p.inputDir, "*.pcap*"))
	if err != nil {
		return fmt.Errorf("failed to list pcap files: %v", err)
	}

	for _, file := range files {
		if !p.processed[file] {
			if err := p.processFile(file); err != nil {
				return fmt.Errorf("failed to process %s: %v", file, err)
			}
			p.processed[file] = true
		}
	}

	return nil
}

func (p *PcapProcessor) processFile(filePath string) error {
	// Create timestamped output directory for this capture
	timestamp := time.Now().Format("20060102_150405")
	outputDir := filepath.Join(p.outputDir, fmt.Sprintf("logs_%s", timestamp))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Use the PCAP parser
	parser := pcap.NewPcapParser(filePath, outputDir)
	stats, err := parser.ProcessFile()
	if err != nil {
		return fmt.Errorf("failed to process file: %v", err)
	}

	// Log statistics
	fmt.Printf("Processed %s:\n%s\n", filePath, stats)

	return nil
}
