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
2. **Configure Agent:**
   - Copy `config.example.json` to `config.json` and edit as needed (e.g., set your API key, adjust capture/output settings).
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

- All configuration is via `config.json` (see `config.example.json` for a template).
- **Key fields:**
  - `logging`: Log level, file path, and max size.
  - `capture`: Output directory, interval, and window duration.
  - `enigma_api`: API server, API key, upload toggle, TLS toggle.
  - `zeek`: Path to Zeek binary (if needed).
  - `log_retention_days`: Number of days to keep log files. Logs older than this are deleted on startup. Default: 1
- **How to configure:**
  1. Copy `config.example.json` to `config.json`.
  2. Edit `config.json` to match your environment and secrets.

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

- **Do not commit your real `config.json`** (it is gitignored). Use `config.example.json` as a safe template for sharing or onboarding.