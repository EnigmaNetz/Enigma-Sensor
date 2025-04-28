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

**Success Criteria:**
- Go module initializes without errors; dependencies install and build cleanly.
- Project structure matches Go best practices and is easy to navigate.
- Configuration loads correctly from `.env` or config file.

**Tests:**
- Run `go build ./...` and `go mod tidy` with no errors.
- Lint and static analysis pass (e.g., `golangci-lint`).
- Unit test: config loader returns expected values for valid/invalid files.

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

**Success Criteria:**
- Zeek or pktmon captures packets and produces logs on both platforms.
- Logs are parsed, transformed, and stored in the correct format and location.
- Log rotation and cleanup work as specified.
- Capture interval and window match requirements.

**Tests:**
- Manual: Trigger capture, verify logs appear and are rotated after 7 days.
- Automated: Unit test log parser with sample Zeek/pktmon logs.
- Integration: Simulate 2-minute capture cycles, verify output and cleanup.

## 3. API Upload Logic (Replicate Enigma-Docker)
- Implement gRPC client in Go using `grpc_config.proto`:
  - `uploadExcelMethod` for data upload (send compressed, base64-encoded Zeek logs as in TS client).
  - Handle API key securely.
  - Implement retry/backoff for upload failures.
- Compress and encode Zeek logs before upload (zlib, base64).
- On success, archive or delete logs as per config.
- Log all upload attempts and errors (securely, redact API key in logs).

**Success Criteria:**
- gRPC client uploads logs successfully, with retries on failure.
- API key is never logged or exposed.
- Logs are compressed, encoded, and archived/deleted on success.

**Tests:**
- Unit: Test log compression/encoding and upload logic with mock API.
- Integration: Simulate upload failures, verify retry/backoff and error logging.
- Security: Scan logs for accidental API key exposure.

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

**Success Criteria:**
- Installer sets up service, config, and dependencies; service starts on boot.
- Service runs with correct permissions and recovers from failure.
- Uninstall removes all files, service, and scheduled tasks.

**Tests:**
- Manual: Install/uninstall on clean Windows VM, verify service and cleanup.
- Automated: Scripted install/uninstall, check service status and logs.
- Security: Validate config/API key file permissions.

## 5. Linux Installer & Startup
- Build the Go binary for major distros (static, x64, ARM if needed).
- Provide install script:
  - Installs binary to `/usr/local/bin` or `/opt/enigma/`.
  - Sets up systemd service (preferred) or cron job for legacy support.
  - Service auto-starts on boot, runs as root or with required capabilities.
  - Installs Zeek if not present, or validates Zeek installation.
  - Handles log/data directory creation and permissions.
- Uninstall script removes service, binary, and data.

**Success Criteria:**
- Installer sets up binary, service, and directories with correct permissions.
- Service starts on boot and runs with required capabilities.
- Uninstall script fully cleans up.

**Tests:**
- Manual: Install/uninstall on supported distros, verify service and cleanup.
- Automated: Scripted install, check service status, permissions, and logs.
- Integration: Simulate Zeek absence, verify installer handles it.

## 6. Security, Logging, and Maintenance
- Never log API keys or sensitive data.
- Use secure file permissions for config and logs.
- Provide clear logs for troubleshooting (file-based, rotate as needed).
- Document all config options and operational steps.

**Success Criteria:**
- No sensitive data in logs; config and logs have secure permissions.
- Logs are clear, actionable, and rotated as needed.
- Documentation is up to date and accurate.

**Tests:**
- Security: Attempt to access config/logs as non-privileged user.
- Automated: Scan logs for sensitive data.
- Manual: Review documentation for completeness and accuracy.

## 7. Testing & Validation
- Unit tests for log parsing, upload logic, and error handling.
- Integration tests for end-to-end capture and upload (mock API).
- Manual install/uninstall validation on Windows and Linux.

**Success Criteria:**
- All unit and integration tests pass.
- Manual install/uninstall validation is successful on all platforms.
- End-to-end data capture and upload works as intended.

**Tests:**
- Run all unit/integration tests (CI pipeline).
- Manual: End-to-end test on Windows and Linux (capture, upload, cleanup).
- Regression: Add new tests for any discovered bugs.

---

**Risks/Notes:**
- Zeek installation/compatibility on Windows is less common; fallback to pktmon if Zeek is unavailable.
- Service permissions must be carefully managed for NIC access.
- Ensure cross-platform compatibility and minimal external dependencies.
- All code and install scripts must be auditable and maintainable.
