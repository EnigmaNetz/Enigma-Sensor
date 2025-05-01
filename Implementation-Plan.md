# Enigma Go Agent Implementation Plan

## 1. Go Project Setup
- Initialize a Go module (`go mod init`).
- Use idiomatic Go project structure: `cmd/`, `pkg/`, `internal/`, `scripts/`, etc.
- Dependencies:
  - gRPC client (for API upload, matching `grpc_config.proto`)
  - gopacket for PCAP parsing
  - Cross-platform service/daemon management
  - Logging (zap for structured logging)
- Configuration via `.env` or config file (API key, endpoints, capture settings).

**Success Criteria:**
- Go module initializes without errors; dependencies install and build cleanly.
- Project structure matches Go best practices and is easy to navigate.
- Configuration loads correctly from `.env` or config file.

**Tests:**
- Run `go build ./...` and `go mod tidy` with no errors.
- Lint and static analysis pass (e.g., `golangci-lint`).
- Unit test: config loader returns expected values for valid/invalid files.

## 2. Platform-Specific Packet Capture Implementation
### Windows Capture (Pktmon)
- Implement pktmon wrapper for packet capture:
  - Execute pktmon commands with appropriate privileges
  - Capture in ETL format, convert to PCAP
  - Handle Windows-specific paths and permissions
  - Clean up temporary ETL files after conversion
- Windows-specific configuration and error handling

### Linux Capture (tcpdump)
- Implement tcpdump wrapper for packet capture:
  - Execute tcpdump with appropriate privileges
  - Direct PCAP file capture
  - Handle Linux-specific paths and permissions
  - Monitor tcpdump process health

### Common Capture Management
- Platform-agnostic capture orchestration:
  - Implement capture interval (2 minutes) and window (30s)
  - Abstract storage locations based on OS
  - Implement log rotation and cleanup (7-day retention)
  - Common error handling and retry logic

## 3. Unified PCAP Processing
- Common interface for processing PCAP data:
  - Platform-agnostic PCAP parsing using gopacket
  - Connection and DNS log generation
  - Standardized data structure handling
  - Unified error handling and logging
  - Common compression and preparation for upload
- Storage management:
  - Platform-agnostic file organization
  - Consistent cleanup policies
  - Unified archival strategy

**Success Criteria:**
- Windows: Pktmon successfully captures and converts to PCAP
- Linux: tcpdump capture works correctly
- Common processing pipeline handles both sources identically
- Capture timing matches requirements (2-min interval, 30s window)
- Log rotation and cleanup work consistently across platforms

**Tests:**
- Platform-specific capture tests
- Common PCAP processing pipeline tests
- Integration tests for each capture method
- Cross-platform compatibility verification
- Unified processing validation

## 4. API Upload Logic
- Implement gRPC client using `grpc_config.proto`:
  - Upload processed log data
  - Handle API key securely
  - Implement retry/backoff for upload failures
- Compress and encode data before upload
- Archive or delete processed files
- Log all upload attempts and errors securely

**Success Criteria:**
- gRPC client uploads data successfully
- API key is never logged or exposed
- Files are properly archived/deleted after upload
- Failed uploads are retried with backoff

**Tests:**
- Unit test upload logic with mock API
- Integration test with real API endpoint
- Security test for API key handling
- Test retry/backoff behavior

## 5. Windows Service Implementation
- Build Windows service wrapper:
  - Run as LocalSystem for network access
  - Auto-start on boot
  - Proper error handling and recovery
- Create installer:
  - Install binary and config
  - Register Windows service
  - Set up logging directory
  - Create uninstall cleanup

**Success Criteria:**
- Service installs and runs correctly
- Captures start automatically on boot
- Service recovers from errors
- Clean uninstall removes all components

**Tests:**
- Test service installation/uninstallation
- Verify auto-start functionality
- Test error recovery scenarios
- Validate cleanup on uninstall

## 6. Security and Maintenance
- Secure storage of API keys
- Proper file permissions
- Structured logging for debugging
- Performance monitoring
- Resource cleanup

**Success Criteria:**
- No sensitive data exposure
- Logs provide adequate debugging info
- Resource usage remains stable
- Cleanup works reliably

**Tests:**
- Security audit of file permissions
- Log analysis for sensitive data
- Resource usage monitoring
- Long-running stability tests

---

**Risks/Notes:**
- Pktmon requires admin privileges
- tcpdump requires root privileges
- Network adapter compatibility
- Resource usage during capture
- Service recovery after network changes
