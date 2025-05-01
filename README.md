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
