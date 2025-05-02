# Enigma Go Agent

A cross-platform network capture agent that collects, processes, and optionally uploads network traffic data in standardized Zeek-format logs.

---

## Architecture Overview

- **Platform-Agnostic Core:**
  Unified agent logic with platform-specific capture implementations.
- **Capture Layer:**
  - **Windows:** Uses `pktmon` (ETL → PCAP).
  - **Linux/macOS:** Uses `tcpdump` (direct PCAP).
- **Processing Layer:**
  - Converts PCAP to Zeek-style logs (`conn.xlsx`, `dns.xlsx`).
  - Uses `gopacket` for analysis.
- **API Integration:**
  - Optional upload of processed logs to Enigma API.

---

## Directory Structure

```
.
├── cmd/
│   └── enigma-agent/         # Main application entry point
├── internal/
│   ├── api/                  # API client and protobufs
│   ├── capture/              # Capture logic (common, windows, linux)
│   ├── config/               # Configuration utilities
│   ├── logger/               # Logging utilities
│   └── processor/            # PCAP processing and Zeek log generation
├── captures/                 # Output directory for capture runs
├── logs/                     # Log output (if enabled)
├── config/                   # Configuration files
├── .env                      # Environment configuration
├── go.mod / go.sum           # Go dependencies
└── README.md
```

---

## Quick Start

1. **Install Go 1.24+**
2. **Configure Environment:**
   - Copy `.env.example` to `.env` and edit as needed.
3. **Build:**
   ```sh
   go build -o bin/enigma-agent ./cmd/enigma-agent
   ```
4. **Run:**
   ```sh
   ./bin/enigma-agent
   ```

---

## Configuration

- All configuration is via environment variables (see `.env.example`).
- Key variables:
  - `CAPTURE_OUTPUT_DIR` (default: `./captures`)
  - `CAPTURE_DURATION` (default: `60s`)
  - `CAPTURE_INTERVAL` (default: same as duration)
  - `ENIGMA_UPLOAD` (`true` to enable upload)
  - `ENIGMA_SERVER`, `ENIGMA_API_KEY` (required for upload)
  - `DISABLE_TLS` (`true` to disable TLS for API)

---

## Capture & Processing Flow

1. **Initialization:**
   Loads config, detects platform, prepares output directory.
2. **Capture:**
   Runs platform-specific capture, outputs PCAP.
3. **Processing:**
   Converts PCAP to Zeek-format logs (`conn.xlsx`, `dns.xlsx`).
4. **Upload (Optional):**
   If enabled, uploads logs to Enigma API.

---

## Log Formats

- **conn.xlsx:**
  TCP/UDP connection tracking (see sample in codebase).
- **dns.xlsx:**
  DNS queries, responses, and metadata.

All logs are in TSV format, suitable for Zeek-style analysis.

---

## Development & Testing

- **Build:**
  `go build -o bin/enigma-agent ./cmd/enigma-agent`
- **Run all tests:**
  `go test ./...`
- **Run specific package tests:**
  `go test -v ./internal/capture/...`
- **Test data:**
  Located in `test/` directory.

---

## Platform Requirements

- **Windows:**
  - Admin privileges (for `pktmon`)
  - Windows 10 1809+
- **Linux/macOS:**
  - Root privileges (for `tcpdump`)
  - `tcpdump` installed

---

## Notes

- Capture and processing intervals are configurable.
- Output directories are timestamped for each run.
- 7-day retention and file rotation are recommended (implement as needed).
- For API upload, both server URL and API key are required.

---

## Contributing

- Follow Go best practices and project style.
- Update/add tests for all functional changes.
- Keep documentation and code comments concise and relevant.