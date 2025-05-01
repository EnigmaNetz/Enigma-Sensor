# Enigma Go Agent

A cross-platform network capture agent that collects and processes network traffic data.

## Project Structure

```
.
├── cmd/
│   ├── enigma-agent/          # Main application entry point
│   └── windows/
│       └── pcap-analyzer/    # Windows PCAP analysis CLI tool
├── internal/
│   ├── api/                   # API client for Enigma backend
│   ├── capture/
│   │   ├── common/           # Common capture interfaces and types
│   │   ├── windows/          # Windows-specific capture (pktmon)
│   │   │   └── pcap/        # PCAP processing implementation
│   │   └── linux/            # Linux-specific capture (Zeek)
│   ├── config/               # Configuration management
│   ├── processor/            # Unified Zeek data processing
│   │   ├── parser/          # Zeek format parsing
│   │   │   └── zeekconv/   # Zeek format conversion logic
│   │   ├── validator/       # Data validation
│   │   └── storage/         # Data storage management
│   ├── proto/                # Protocol definitions
│   └── platform/             # Platform-specific utilities
├── pkg/                      # Public packages (if any)
├── scripts/                  # Build and utility scripts
└── test/                     # Integration tests
```

## Component Overview

- `capture`: Platform-specific packet capture implementations
  - `windows`: Pktmon-based capture and conversion to Zeek format
  - `linux`: Direct Zeek integration
  - `common`: Shared interfaces and types for capture implementations

- `processor`: Platform-agnostic Zeek data processing
  - Handles data validation, transformation, and preparation for upload
  - Common storage management and cleanup policies
  - Unified processing pipeline for both capture methods

- `api`: Enigma API client implementation
  - gRPC-based communication
  - Upload management and retry logic

## Development

[Development instructions here]

## Building

[Build instructions here]

## Testing

[Testing instructions here]

## Setup

1. Install Go 1.20+
2. Copy .env.example to .env and fill in config.
3. Build: go build -o bin/enigma-agent ./cmd/enigma-agent
4. Run: ./bin/enigma-agent

## Testing

1. Run all tests: `go test ./...`
2. Run tests with output: `go test -v ./...`
3. Run specific package tests: `go test -v ./internal/capture/...`
4. Run a specific test: `go test -v -run TestPcapParser_ProcessFile ./internal/capture/...`

Test files are located in their respective package directories. The main test data files are in the `test/` directory.

## Tools

### Windows PCAP Analyzer
The PCAP analyzer tool converts Windows pktmon ETL and PCAP/PCAPNG files to Zeek log format. This tool is only needed for Windows captures.

1. Build the tool:
```bash
go build -o bin/pcap-analyzer ./cmd/windows/pcap-analyzer
```

2. Run the analyzer:
```bash
./bin/pcap-analyzer -input <pcap-file> -output <output-dir>
```

Example:
```bash
./bin/pcap-analyzer -input test/package-capture.pcapng -output logs
```

This will generate:
- logs/conn.log: Connection tracking in Zeek format
- logs/dns.log: DNS queries and responses in Zeek format
