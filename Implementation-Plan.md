# Enigma Go Agent Implementation Plan

## 1. Go Project Setup
- Initialize a Go module (`go mod init`).
- Use idiomatic Go project structure: `cmd/`, `pkg/`, `internal/`, `scripts/`, etc.
- Dependencies:
  - gRPC client (for API upload, matching `grpc_config.proto`)
  - Zeek process management (invoke Zeek binary, parse logs)
  - Cross-platform service/daemon management (see below)
  - Logging (zap or logrus, with secure handling of API keys)
- Configuration via `.env` or config file (API key, endpoints, Zeek paths, etc.).

## 2. Zeek Packet Capture Replication
- **Windows:**
  - Use Zeek for packet capture if available, else fallback to `pktmon` (as in PowerShell script).
  - Automate Zeek invocation, monitor output directory for new logs.
  - Parse/transform Zeek logs to required format (e.g., compress, encode as needed for API).
- **Linux:**
  - Invoke Zeek directly (or via wrapper script), ensure correct permissions (may require `cap_net_raw` or root).
  - Store output in `/opt/enigma/data` or similar.
- **General:**
  - Implement log rotation and cleanup (7-day retention, as in Linux client).
  - Ensure capture interval matches existing clients (every 2 minutes, 30s capture window).

## 3. API Upload Logic (Replicate Enigma-Docker)
- Implement gRPC client in Go using `grpc_config.proto`:
  - `uploadExcelMethod` for data upload (send compressed, base64-encoded Zeek logs as in TS client).
  - Handle API key securely.
  - Implement retry/backoff for upload failures.
- Compress and encode Zeek logs before upload (zlib, base64).
- On success, archive or delete logs as per config.
- Log all upload attempts and errors (securely, redact API key in logs).

## 4. Windows Installer & Service Setup
- Build the Go binary for Windows (x64, static if possible).
- Use NSSM or native Windows service APIs to install the agent as a service:
  - Service should run as `LocalSystem` for NIC access.
  - Service auto-starts on boot.
  - Store config/API key in a secure location (e.g., `C:\ProgramData\Enigma-Go-Agent\`).
- Provide an Inno Setup or similar installer:
  - Installs binary, config, and NSSM if needed.
  - Registers and starts the service.
  - Uninstall script removes service, files, and scheduled tasks.
- **Risk:** Ensure service recovery and logging are robust (see PowerShell installer for recovery options).

## 5. Linux Installer & Startup
- Build the Go binary for major distros (static, x64, ARM if needed).
- Provide install script:
  - Installs binary to `/usr/local/bin` or `/opt/enigma/`.
  - Sets up systemd service (preferred) or cron job for legacy support.
  - Service auto-starts on boot, runs as root or with required capabilities.
  - Installs Zeek if not present, or validates Zeek installation.
  - Handles log/data directory creation and permissions.
- Uninstall script removes service, binary, and data.

## 6. Security, Logging, and Maintenance
- Never log API keys or sensitive data.
- Use secure file permissions for config and logs.
- Provide clear logs for troubleshooting (file-based, rotate as needed).
- Document all config options and operational steps.

## 7. Testing & Validation
- Unit tests for log parsing, upload logic, and error handling.
- Integration tests for end-to-end capture and upload (mock API).
- Manual install/uninstall validation on Windows and Linux.

---

**Risks/Notes:**
- Zeek installation/compatibility on Windows is less common; fallback to pktmon if Zeek is unavailable.
- Service permissions must be carefully managed for NIC access.
- Ensure cross-platform compatibility and minimal external dependencies.
- All code and install scripts must be auditable and maintainable.
