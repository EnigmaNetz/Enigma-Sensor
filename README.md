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
   - On Windows, copy `config.example.json` to `config.json` and edit as needed (e.g., set your API key, adjust capture/output settings).
   - On Linux, the install script creates `/etc/enigma-agent/config.json` if it does not exist.
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
- **On Linux, the install script creates config at:** `/etc/enigma-agent/config.json` if it does not exist. Edit this file after install to adjust settings.
- **Key fields:**
  - `logging`: Log level, file path, and max size.
  - `capture`: Output directory, interval, and window duration.
  - `enigma_api`: API server, API key, upload toggle (always enabled).
  - `log_retention_days`: Number of days to keep log files. Logs older than this are deleted on startup. Default: 1
- **How to configure:**
  1. On Windows, edit `C:\ProgramData\EnigmaAgent\config.json` after install if needed.
  2. On Linux, edit `/etc/enigma-agent/config.json` after install if needed.

### Logging & Log Rotation

The agent supports automatic log rotation and compression. Configure these options in your `config.json`:

```json
"logging": {
  "level": "info",                // Log level: debug, info, warn, error
  "file": "logs/enigma-agent.log", // Log file path (if empty, logs to stdout only)
  "max_size_mb": 100,              // Maximum size (in MB) before rotating log file
  "log_retention_days": 7          // Number of days to keep old log files (rotated logs are compressed)
}
```

- When the log file exceeds `max_size_mb`, it is rotated and compressed (gzip).
- Up to 3 rotated log files are kept by default.
- Rotated logs older than `log_retention_days` are deleted automatically.
- All logs are also output to stdout for convenience.

---

### Changing API Host for Staging/Development

By default, the agent uses the production API host (`api.enigmaai.net:443`).

To use the staging or development API host (`dev.getenigma.ai:443`):

- **Windows:**
  1. Open `C:\ProgramData\EnigmaAgent\config.json` in a text editor (as Administrator).
  2. Change the value of `enigma_api.server` to `dev.getenigma.ai:443`.
- **Linux/macOS:**
  1. Open your `config.json` in a text editor.
  2. Change the value of `enigma_api.server` to `dev.getenigma.ai:443`.

Example:

```json
{
  "enigma_api": {
    "server": "dev.getenigma.ai:443",
    "api_key": "YOUR_API_KEY",
    "upload": true
  }
  // ... other config fields ...
}
```

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

### Building and Testing the Debian Package

1. **Build the .deb package:**

   ```sh
   cd installer/debian
   ./build-deb.sh
   ```

   - This script will automatically build the Go binary if it is missing and package it as a Debian installer.
   - The resulting `.deb` file will be named `enigma-agent_*.deb` (or similar) in the current directory.

2. **Test install in a clean Debian environment:**
   - **Recommended:** Use a VM or Docker container running your target Debian version.
   - **Install the package:**

     ```sh
     sudo dpkg -i enigma-agent_*.deb
     sudo apt-get install -f  # Fix dependencies if needed
     ```

   - **Verify:**
     - The agent binary is installed to `/usr/local/bin/enigma-agent`.
     - The systemd service is installed and can be started with `sudo systemctl start enigma-agent`.
     - Uninstall with `sudo dpkg -r enigma-agent` and verify cleanup.

3. **Optional: Lint the package**

   ```sh
   lintian ./enigma-agent_0.1.0.deb
   ```

   - Fix any errors or warnings for best Debian compliance.

---

## Platform Requirements

- **Windows:**
  - Admin privileges (for `pktmon`)
  - Windows 10 1809+
  - Zeek for Windows is always extracted from `installer/windows/zeek-runtime-win64.zip` to `zeek-windows/` on first run and on every agent start. No manual setup required.
  - Config is always loaded from `C:\ProgramData\EnigmaAgent\config.json` if present.
- **Linux/macOS:**
  - Root privileges (for `tcpdump`)
  - `tcpdump` and `zeek` are required and installed by the install script

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
- **No advanced options** are shown during install; only API key and API host are prompted (host defaults to `api.enigmaai.net:443`).
- **No user password is required or prompted.**
- The service is always run as LocalSystem.
- **Uninstalling** will stop and remove the service.
- **Zeek for Windows** is bundled as `zeek-runtime-win64.zip` and always extracted to `zeek-windows/` on agent start (overwriting any previous version).

### To build the installer

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

## Installing on Linux

1. **Download the latest Linux release zip** from the [GitHub Releases](https://github.com/<your-org>/<your-repo>/releases) page. The file will be named like:

   ```
   enigma-agent-<version>-linux-release.zip
   ```

2. **Unzip the release:**

   ```sh
   unzip enigma-agent-<version>-linux-release.zip
   cd enigma-agent-<version>-linux-release
   ```

3. **Run the install script:**

   ```sh
   export ENIGMA_API_KEY=YOUR_API_KEY
   sudo bash install-enigma-agent.sh
   ```

   - The script will:
     - Detect your Linux distribution and install dependencies (currently supports Debian/Ubuntu; CentOS/RHEL support coming soon).
     - Install `zeek` and `tcpdump` if missing.
     - Install the agent `.deb` package (on Debian/Ubuntu).
     - Create `/etc/enigma-agent/config.json` if it does not exist.
     - Restart the agent service (if systemd is present).

4. **Edit `/etc/enigma-agent/config.json`** to adjust settings as needed.
