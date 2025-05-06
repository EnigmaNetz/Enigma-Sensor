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
   - On Windows, Zeek for Windows will be auto-extracted from `installer/windows/zeek-runtime-win64.zip` to `zeek-windows/` on first run. No manual setup required. The installer always overwrites the Zeek directory with the bundled version.

---

## Collecting Logs for Diagnostics

To package all logs and your config for support/diagnostics, run the following command based on your platform:

**On Linux/macOS:**

```sh
./enigma-agent collect-logs
```

**On Windows (default install location):**

```ps1
# Note: This requires running PowerShell as Administrator
& "C:\Program Files (x86)\EnigmaAgent\enigma-agent-windows-amd64.exe" collect-logs
```

On Windows, the resulting zip file will be in `C:\Program Files (x86)\EnigmaAgent\`.

This creates a zip archive (e.g., `enigma-logs-YYYYMMDD-HHMMSS.zip`) in your current directory, containing:

- all files from `logs/` (including rotated logs),
- all files and subdirectories from `captures/`,
- your `config.json`,
- a `version.txt` file with the agent version,
- and a `system-info.txt` file with OS, architecture, Go version, and basic CPU/memory info.

You can send this archive to Enigma support for troubleshooting.

---

## Configuration

- All configuration is via `config.json`.
- **On Windows, the installer writes config to:** `C:\ProgramData\EnigmaAgent\config.json` (this is always used if present).
- **Key fields:**
  - `logging`: Log level, file path, and max size.
  - `capture`: Output directory, interval, and window duration.
  - `enigma_api`: API server, API key, upload toggle (always enabled).
  - `log_retention_days`: Number of days to keep log files. Logs older than this are deleted on startup. Default: 1
- **How to configure:**
  1. On Windows, edit `C:\ProgramData\EnigmaAgent\config.json` after install if needed.
  2. On Linux/macOS, copy `config.example.json` to `config.json` and edit as needed.

---

## Capture & Processing Flow

1. **Initialization:**
   Loads config (Windows: `C:\ProgramData\EnigmaAgent\config.json` if present, else `config.json`). Detects platform, prepares output directory.
2. **Capture:**
   - **Windows:** Runs `pktmon` to produce `.etl` and then converts to `.pcapng`. Both files are cleaned up after processing.
   - **Linux/macOS:** Runs `tcpdump` to produce `.pcap`.
3. **Processing:**
   Converts PCAP/PCAPNG to Zeek-format logs (`conn.xlsx`, `dns.xlsx`).
4. **Upload (Always Enabled):**
   Uploads logs to Enigma API if configured.
5. **Cleanup:**
   All processed capture files (`.pcap`, `.pcapng`, `.etl`) are deleted after successful processing and upload.

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
  - Zeek for Windows is always extracted from `installer/windows/zeek-runtime-win64.zip` to `zeek-windows/` on first run and on every agent start. No manual setup required.
  - Config is always loaded from `C:\ProgramData\EnigmaAgent\config.json` if present.
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

## Windows Installer (Service Mode)

The Windows installer sets up Enigma Agent as a Windows service using NSSM with the following characteristics:

- **Service Name:** EnigmaAgent
- **Account:** LocalSystem (runs with admin privileges)
- **Startup:** Automatic (runs on boot)
- **Log Location:** `C:\ProgramData\EnigmaAgent\logs\enigma-agent.log`
- **Config Location:** `C:\ProgramData\EnigmaAgent\config.json`
- **No Start Menu shortcut** is created.
- **No advanced options** are shown during install; only API key and API host are prompted (host defaults to `enigmaai.net:443`).
- **No user password is required or prompted.**
- The service is always run as LocalSystem.
- **Uninstalling** will stop and remove the service.
- **Zeek for Windows** is bundled as `zeek-runtime-win64.zip` and always extracted to `zeek-windows/` on agent start (overwriting any previous version).

### To build the installer:

1. Download [NSSM](https://nssm.cc/download) and place `nssm.exe` in your `bin/` directory.
2. Build the agent executable for Windows (already present as `bin/enigma-agent-windows-amd64.exe`).
3. Place `zeek-runtime-win64.zip` in `installer/windows/`.
4. Open `installer/windows/enigma-agent-installer.iss` in Inno Setup and click 'Compile'.
5. The installer (`enigma-agent-installer.exe`) will be created in the output directory.

### Troubleshooting

- The installer uses `WorkingDir: {app}` for all NSSM commands, so only the executable filename is used (not the full path). This avoids issues with spaces in the install path.
- All paths passed to NSSM are properly quoted with double quotes. Do **not** use single or triple quotes in the .iss file.
- If the service fails to start, ensure that `enigma-agent-windows-amd64.exe` exists in the install directory and that you have admin rights.
- If Zeek is not extracted, ensure `zeek-runtime-win64.zip` is present in `installer/windows/` and that the agent has permission to write to `zeek-windows/`.
- Config changes should be made in `C:\ProgramData\EnigmaAgent\config.json`.
