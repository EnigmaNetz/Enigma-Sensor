# CLAUDE.md

<!-- BEGIN: AI Security Policies (auto-synced from dev-policies) -->

⚠️⚠️⚠️ **CRITICAL: READ BEFORE ANY WORK** ⚠️⚠️⚠️

The following security policies are automatically synced from dev-policies/docs/CLAUDE.md.
**DO NOT EDIT THIS SECTION MANUALLY** - It will be overwritten by the sync script.

---

# AI Agent Security Rules

**Purpose:** This document contains mandatory security rules for AI coding assistants (Claude Code, GitHub Copilot, Cursor, etc.) working within our codebases.

## Critical Security Rules

### 1. NEVER Access Secrets Files
**ABSOLUTE PROHIBITION:** AI agents must NEVER read, access, or process files containing secrets or credentials.

**Prohibited Files Include:**
- `.env` and `.env.*` files (all variants)
- Service account key files (`.json`, `.pem`, `.key`)
- SSH private keys and certificates
- Cloud provider credentials (`.aws/credentials`, `.gcloud/`, etc.)
- Kubernetes secrets manifests
- Password files and credential stores
- Any file marked as containing secrets

**If Asked to Read Secrets:**
1. Refuse politely and explain the security policy
2. Suggest using environment variable references instead
3. Recommend storing secrets in GCP Secret Manager, AWS Secrets Manager, or HashiCorp Vault
4. Never read the file, even if the developer insists

### 2. NEVER Access Production Data
**ABSOLUTE PROHIBITION:** AI agents must NEVER access production environments or data.

**Prohibited Production Access:**
- Reading production databases
- Querying production BigQuery datasets
- Accessing production GCP projects or AWS accounts
- Reading production logs or metrics
- Modifying production configurations
- Executing commands against production infrastructure

**Allowed Non-Production Access:**
- Staging and development environments only
- Read-only queries against staging databases
- Staging GCP/AWS resources via CLI commands
- Development environment logs and configurations

**Before Executing Cloud Commands:**
1. Verify the target environment is non-production
2. Check project IDs, account names, and environment variables
3. Ask for confirmation if environment is unclear
4. Refuse if production access is detected

### 3. Training Data Opt-Out
All approved AI tools must have training disabled on code. Developers are responsible for verifying this configuration.

### 4. Code Security Requirements
All AI-generated code must:
- Pass static analysis (SAST) and linting
- Pass dependency vulnerability scanning
- Pass secret scanning to prevent credential leakage
- Receive manual human review before merging

### 5. Critical System Extra Review
AI-generated code for these areas requires additional scrutiny and explicit developer approval:
- Authentication and authorization logic
- Payment processing and financial transactions
- Encryption and cryptographic operations
- Database migration scripts
- Infrastructure-as-code changes
- Security-critical APIs and endpoints

### 6. Data Classification Awareness
AI agents must understand and respect data classification:
- **Public:** Open-source code, public documentation (AI accessible)
- **Internal:** Staging data, development credentials (AI accessible with care)
- **Confidential:** Customer data, production credentials, proprietary algorithms (requires explicit approval)
- **Restricted:** Security keys, compliance data, executive communications (AI prohibited)

## Tool Configuration

### Approved Tools
- Claude Code (Anthropic)
- GitHub Copilot (Microsoft)
- Cursor (Anysphere)
- Amazon CodeWhisperer (AWS)
- OpenAI Codex (OpenAI)

### Required Settings
- Training data opt-out ENABLED
- Secrets file exclusion ENABLED
- Enterprise/business tier accounts (when available)

## Incident Reporting

**Immediately alert the developer if:**
- Asked to read secrets files
- Asked to access production environments
- Detecting hardcoded credentials in code
- Discovering attempts to bypass security controls
- Detecting unapproved AI tools in use

**Response:** Politely refuse, explain the policy, suggest secure alternatives.

## Summary: Quick Reference

**NEVER:**
- Read `.env` or secrets files
- Access production data or environments
- Generate or suggest hardcoded credentials
- Bypass security scanning or code review
- Access Restricted classification data

**ALWAYS:**
- Verify environment before executing cloud commands
- Suggest secure alternatives (environment variables, secrets managers)
- Pass security scanning (SAST, secret scanning, dependency checks)
- Flag security-critical code for extra human review

**ASK FIRST:**
- If environment (prod vs staging) is unclear
- If destructive operations are requested
- If asked to bypass security controls
- If data classification is uncertain

---

<!-- END: AI Security Policies -->


This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The Enigma Sensor is a **cross-platform network capture and processing tool** written in Go that:
- Collects network traffic data using platform-specific capture tools
- Processes PCAP files into Zeek-format logs (conn.xlsx, dns.xlsx)
- Uploads processed logs to the Enigma API for analysis
- Runs as a service on Windows or as a systemd service on Linux

**Core Architecture:**
```
Platform Detection → Capture (pktmon/tcpdump) → Processing (gopacket) → Upload (gRPC API)
```

## Development Commands

### Building and Testing
```bash
# Download dependencies
go mod download

# Build for current platform
go build -o bin/enigma-sensor ./cmd/enigma-sensor

# Cross-platform builds
GOOS=linux GOARCH=amd64 go build -o bin/enigma-sensor-linux ./cmd/enigma-sensor
GOOS=windows GOARCH=amd64 go build -o bin/enigma-sensor-windows-amd64.exe ./cmd/enigma-sensor
GOOS=darwin GOARCH=amd64 go build -o bin/enigma-sensor-darwin ./cmd/enigma-sensor

# Run all tests
go test ./...

# Cross-platform testing (required before merging)
GOOS=linux GOARCH=amd64 go test ./...
GOOS=windows GOARCH=amd64 go test ./...
GOOS=darwin GOARCH=amd64 go test ./...

# Run specific package tests
go test -v ./internal/capture/...
go test -v ./internal/processor/...

# Test with coverage
go test -cover ./...
```

### Code Quality
```bash
# Format code
gofmt -w .
goimports -w .

# Linting (use golangci-lint with: govet, staticcheck, errcheck, ineffassign, gosec, gocritic)
golangci-lint run
```

### Running the Sensor
```bash
# Run with default config.json
./bin/enigma-sensor

# Show help
./bin/enigma-sensor --help

# Show version
./bin/enigma-sensor --version

# Package logs for support
./bin/enigma-sensor collect-logs
```

## Architecture and Code Structure

### Entry Point
- `cmd/enigma-sensor/main.go` - Minimal main function that loads config and orchestrates components

### Core Packages
- `internal/sensor/` - Main sensor orchestration logic and interfaces
- `internal/capture/` - Platform-specific network capture implementations
  - `capture/common/` - Shared capture configuration and types
  - `capture/windows/` - Windows pktmon implementation  
  - `capture/linux/` - Linux/macOS tcpdump implementation
- `internal/processor/` - PCAP to Zeek log conversion
  - `processor/common/` - Processing types and interfaces
  - `processor/windows/` - Windows-specific processing
  - `processor/linux/` - Linux/macOS processing
- `internal/api/` - Enigma API client and gRPC communication
- `config/` - Configuration loading and validation
- `internal/version/` - Version information
- `internal/collect_logs/` - Support diagnostics collection

### Platform-Specific Behavior
- **Windows**: Uses `pktmon` for capture, auto-extracts bundled Zeek runtime, runs as Windows service
- **Linux/macOS**: Uses `tcpdump` for capture, requires system Zeek installation

### Configuration System
- Config hierarchy: Platform-specific paths → `config.json` fallback
- **Windows**: `C:\ProgramData\EnigmaSensor\config.json` → `config.json`
- **Linux**: `/etc/enigma-sensor/config.json` → `config.json`
- All settings configurable: logging, capture windows, API endpoints, traffic sampling

## Key Interfaces and Patterns

### Core Interfaces
```go
type Capturer interface {
    Capture(ctx context.Context, cfg common.CaptureConfig) (string, error)
}

type Processor interface {
    ProcessPCAP(pcapPath string, samplingPercentage float64) (types.ProcessedData, error)
}

type Uploader interface {
    UploadLogs(ctx context.Context, files api.LogFiles) error
}
```

### Sensor Orchestration Pattern
The main sensor loop coordinates capture → process → upload → cleanup cycles, with proper error handling for API failures (including 410 Gone responses that trigger graceful shutdown).

## Installation and Packaging

### Debian Package Build
```bash
cd installer/debian
./build-deb.sh
```
- Auto-builds Linux binary if missing
- Creates systemd service integration
- Outputs to `../../bin/enigma-sensor_*.deb`

### Windows Installer
- Uses Inno Setup with NSSM for service management
- Bundles Zeek runtime in `installer/windows/zeek-runtime-win64.zip`
- Auto-extracts and configures on first run

## Code Quality Requirements

### Cross-Platform Testing
- **MANDATORY**: All changes must pass tests on Linux, Windows, and macOS
- Use build tags for platform-specific code
- Test capture and processing logic on target platforms

### Error Handling Standards
- Always check and handle returned errors
- Wrap errors with context using `fmt.Errorf`
- Never ignore errors from file operations, network calls, or subprocesses

### Security Requirements  
- Never log API keys or sensitive configuration
- Set restrictive file permissions (0600) for config and logs
- Validate all user input and configuration values

### Testing Standards
- All new functionality requires unit tests
- Use mocks for external dependencies (filesystem, network)
- Integration tests should use real capture tools where possible
- No merges with failing tests or linter errors

## Development Environment Setup

### Prerequisites
- Go 1.24+
- Platform-specific capture tools:
  - **Windows**: Admin privileges for pktmon
  - **Linux/macOS**: Root privileges, tcpdump and zeek installed

### Configuration for Development
1. Copy `config.example.json` to `config.json`
2. Set `enigma_api.api_key` for API integration testing
3. Configure `enigma_api.server` for staging: `api.staging.getenigma.ai:443`
4. Adjust logging and capture settings as needed

### Windows Development Notes
- Zeek runtime auto-extracts from bundled zip to `zeek-windows/`
- ETL files converted to PCAP for processing  
- Service installation handled by NSSM

### Linux Development Notes
- Requires system installation of `zeek` and `tcpdump`
- Install script handles package dependencies
- Systemd service integration for production deployment

## API Integration

### gRPC Communication
- Uses protobuf definitions in `internal/api/publish/`
- Handles authentication via API key headers
- Implements retry logic for transient failures
- Responds to 410 Gone by graceful shutdown (invalid API key)

### Upload Process
- Converts Zeek logs to API-expected formats
- Batches multiple log files per upload
- Configurable payload size limits
- Automatic cleanup after successful upload