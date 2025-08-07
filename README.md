# Enigma Go Sensor

A cross-platform network capture sensor that collects, processes, and optionally uploads network traffic data in standardized Zeek-format logs.

---

## Architecture Overview

- **Platform-Agnostic Core:**
  Unified sensor logic with platform-specific capture implementations.
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
│   └── enigma-sensor/         # Main application entry point
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
2. **Configure Sensor:**
   - On Windows, copy `config.example.json` to `config.json` and edit as needed (e.g., set your API key, adjust capture/output settings).
   - On Linux, the install script creates `/etc/enigma-sensor/config.json` if it does not exist.
3. **Build:**

   ```sh
   go build -o bin/enigma-sensor ./cmd/enigma-sensor
   ```

4. **Run:**

   ```sh
   ./bin/enigma-sensor
   ```

   - On Windows, Zeek for Windows will be auto-extracted from `installer/windows/zeek-runtime-win64.zip` to `zeek-windows/` on first run. No manual setup required. The installer always overwrites the Zeek directory with the bundled version.

---

## Collecting Logs for Diagnostics

To package all logs and your config for support/diagnostics, run the following command based on your platform:

**On Linux/macOS:**

```sh
./enigma-sensor collect-logs
```

**On Windows (default install location):**

```ps1
# Note: This requires running PowerShell as Administrator
& "C:\Program Files (x86)\EnigmaSensor\enigma-sensor-windows-amd64.exe" collect-logs
```

On Windows, the resulting zip file will be in `C:\Program Files (x86)\EnigmaSensor\`.

This creates a zip archive (e.g., `enigma-logs-YYYYMMDD-HHMMSS.zip`) in your current directory, containing:

- all files from `logs/` (including rotated logs),
- all files and subdirectories from `captures/`,
- your `config.json`,
- a `version.txt` file with the sensor version,
- and a `system-info.txt` file with OS, architecture, Go version, and basic CPU/memory info.

You can send this archive to Enigma support for troubleshooting.

---

## Configuration

- All configuration is via `config.json`.
- **On Windows, the installer writes config to:** `C:\ProgramData\EnigmaSensor\config.json` (this is always used if present).
- **On Linux, the install script creates config at:** `/etc/enigma-sensor/config.json` if it does not exist. Edit this file after install to adjust settings.
- **Key fields:**
  - `logging`: Log level, file path, and max size.
  - `capture`: Output directory, interval, window duration, and interface.
  - `enigma_api`: API server, API key, upload toggle (always enabled).
  - `zeek`: Traffic sampling configuration.
  - `log_retention_days`: Number of days to keep log files. Logs older than this are deleted on startup. Default: 1
- **How to configure:**
  1. On Windows, edit `C:\ProgramData\EnigmaSensor\config.json` after install if needed.
  2. On Linux, edit `/etc/enigma-sensor/config.json` after install if needed.

### Traffic Sampling

The sensor supports random sampling to reduce processing load. Configure `zeek.sampling_percentage` (0-100) to process a percentage of network connections and DNS queries. Default is 100 (no sampling).

### Logging & Log Rotation

The sensor supports automatic log rotation and compression. Configure these options in your `config.json`:

```json
"logging": {
  "level": "info",                // Log level: debug, info, warn, error
  "file": "logs/enigma-sensor.log", // Log file path (if empty, logs to stdout only)
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

By default, the sensor uses the production API host (`api.enigmaai.net:443`).

To use the staging or development API host (`api.staging.getenigma.ai:443`):

- **Windows:**
  1. Open `C:\ProgramData\EnigmaSensor\config.json` in a text editor (as Administrator).
  2. Change the value of `enigma_api.server` to `api.staging.getenigma.ai:443`.
- **Linux/macOS:**
  1. Open your `config.json` in a text editor.
  2. Change the value of `enigma_api.server` to `api.staging.getenigma.ai:443`.

Example:

```json
{
  "enigma_api": {
    "server": "api.staging.getenigma.ai:443",
    "api_key": "YOUR_API_KEY",
    "upload": true
  }
  // ... other config fields ...
}
```

---

## Capture & Processing Flow

1. **Initialization:**
   Loads config (Windows: `C:\ProgramData\EnigmaSensor\config.json` if present, else `config.json`). Detects platform, prepares output directory.
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
  `go build -o bin/enigma-sensor ./cmd/enigma-sensor`
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
   - The resulting `.deb` file will be named `enigma-sensor_*.deb` (or similar) in the current directory.

2. **Test install in a clean Debian environment:**
   - **Recommended:** Use a VM or Docker container running your target Debian version.
   - **Install the package:**

     ```sh
     sudo dpkg -i enigma-sensor_*.deb
     sudo apt-get install -f  # Fix dependencies if needed
     ```

   - **Verify:**
     - The sensor binary is installed to `/usr/local/bin/enigma-sensor`.
     - The systemd service is installed and can be started with `sudo systemctl start enigma-sensor`.
     - Uninstall with `sudo dpkg -r enigma-sensor` and verify cleanup.

3. **Optional: Lint the package**

   ```sh
   lintian ./enigma-sensor_0.1.0.deb
   ```

   - Fix any errors or warnings for best Debian compliance.

---

## Platform Requirements

- **Windows:**
  - Admin privileges (for `pktmon`)
  - Windows 10 1809+
  - Zeek for Windows is always extracted from `installer/windows/zeek-runtime-win64.zip` to `zeek-windows/` on first run and on every sensor start. No manual setup required.
  - Config is always loaded from `C:\ProgramData\EnigmaSensor\config.json` if present.
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

The Windows installer sets up Enigma Sensor as a Windows service using NSSM with the following characteristics:

- **Service Name:** EnigmaSensor
- **Account:** LocalSystem (runs with admin privileges)
- **Startup:** Automatic (runs on boot)
- **Log Location:** `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log`
- **Config Location:** `C:\ProgramData\EnigmaSensor\config.json`
- **No Start Menu shortcut** is created.
- **No advanced options** are shown during install; only API key and API host are prompted (host defaults to `api.enigmaai.net:443`).
- **No user password is required or prompted.**
- The service is always run as LocalSystem.
- **Uninstalling** will stop and remove the service.
- **Zeek for Windows** is bundled as `zeek-runtime-win64.zip` and always extracted to `zeek-windows/` on sensor start (overwriting any previous version).

### To build the installer

1. Download [NSSM](https://nssm.cc/download) and place `nssm.exe` in your `bin/` directory.
2. Build the sensor executable for Windows (already present as `bin/enigma-sensor-windows-amd64.exe`).
3. Place `zeek-runtime-win64.zip` in `installer/windows/`.
4. Open `installer/windows/enigma-sensor-installer.iss` in Inno Setup and click 'Compile'.
5. The installer (`enigma-sensor-installer.exe`) will be created in the output directory.

### Troubleshooting

- The installer uses `WorkingDir: {app}` for all NSSM commands, so only the executable filename is used (not the full path). This avoids issues with spaces in the install path.
- All paths passed to NSSM are properly quoted with double quotes. Do **not** use single or triple quotes in the .iss file.
- If the service fails to start, ensure that `enigma-sensor-windows-amd64.exe` exists in the install directory and that you have admin rights.
- If Zeek is not extracted, ensure `zeek-runtime-win64.zip` is present in `installer/windows/` and that the sensor has permission to write to `zeek-windows/`.
- Config changes should be made in `C:\ProgramData\EnigmaSensor\config.json`.

## Installing on Linux

1. **Download the latest Linux release zip** from the [GitHub Releases](https://github.com/<your-org>/<your-repo>/releases) page. The file will be named like:

   ```
   enigma-sensor-<version>-linux-release.zip
   ```

2. **Unzip the release:**

   ```sh
   unzip enigma-sensor-<version>-linux-release.zip
   cd enigma-sensor-<version>-linux-release
   ```

3. **Run the install script:**

   ```sh
   export ENIGMA_API_KEY=YOUR_API_KEY
   sudo bash install-enigma-sensor.sh
   ```

   - The script will:
     - Detect your Linux distribution and install dependencies (currently supports Debian/Ubuntu; CentOS/RHEL support coming soon).
     - Install `zeek` and `tcpdump` if missing.
     - Install the sensor `.deb` package (on Debian/Ubuntu).
     - Create `/etc/enigma-sensor/config.json` if it does not exist.
     - Restart the sensor service (if systemd is present).

4. **Edit `/etc/enigma-sensor/config.json`** to adjust settings as needed.
