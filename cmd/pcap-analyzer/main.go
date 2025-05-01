package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
)

func main() {
	// Parse command line flags
	inputFile := flag.String("input", "", "Input pcap/pcapng file to analyze")
	outputDir := flag.String("output", "zeek_logs", "Output directory for Zeek logs")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Error: -input flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Create parser
	parser := capture.NewPcapParser(*inputFile, *outputDir)

	// Process the file
	stats, err := parser.ProcessFile()
	if err != nil {
		fmt.Printf("Error processing file: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("\nProcessing complete!\n")
	fmt.Printf("Output files:\n")
	fmt.Printf("- %s\n", filepath.Join(*outputDir, "conn.log"))
	fmt.Printf("- %s\n", filepath.Join(*outputDir, "dns.log"))
	fmt.Printf("\nPacket Statistics:\n%s\n", stats)
}
