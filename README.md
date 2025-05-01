# Enigma Go Agent

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

### PCAP Analyzer
The PCAP analyzer tool converts pcap/pcapng files to Zeek log format.

1. Build the tool:
```bash
go build -o bin/pcap-analyzer ./cmd/pcap-analyzer
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
