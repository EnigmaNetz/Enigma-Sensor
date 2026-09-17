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

## Start here

`README.md` is the source of truth for how the sensor behaves and is configured. `DEVELOPMENT.md`
covers building, testing, CI, packaging and releasing. Read the relevant section before changing
behaviour, and link to those files rather than copying their content here.

Other references: `installer/linux/zeek/README.md` (bundled Zeek packages), `installer/windows/README.md`
(Windows installer).

## Git Workflow
**Branch naming convention:**
- Format: `task/[TICKET-ID]-[short-description]`
- Example: `task/B1CF-1234-add-user-authentication`
- Use lowercase with hyphens for description
- Always include ticket ID in branch name
- Branch from `main`; PRs target `main` (this repo has no `stage` branch)

**Commit message requirements:**
- MUST include ticket reference at end: `Ref [TICKET-ID]`
- Example: `Ref B1CF-1234`
- If branch name contains no numbers, do not reference any ticket
- NEVER reference Claude, Claude Code, or other AI tools in commit messages
- Never use `git add .`; stage files explicitly

## Project Overview

The Enigma AI Sensor is a Go 1.24 agent installed on customer machines. Each loop it:

PCAP is packet capture; gRPC is gRPC Remote Procedure Calls.

```
Capture (tcpdump | Npcap | pktmon) → PCAP → Zeek → 5 logs → excluded-subnet filter → gRPC upload → Enigma-Publisher
```

- **Capture**: `tcpdump` on Linux and macOS. On Windows, Npcap (via gopacket) when
  `wpcap.dll` is present, otherwise `pktmon`, whose ETL (Event Trace Log) output is converted with
  `pktmon etl2pcapng`.
- **Process**: Zeek writes `conn`, `dns`, `dhcp`, `ja3_ja4` and `ja4s` logs. On every platform
  `dhcp.log` is then enriched with DHCP (Dynamic Host Configuration Protocol) option 55 read from
  the PCAP with gopacket. The logs are renamed to `.xlsx`, but they are still Zeek tab-separated text, not Excel.
- **Upload**: to Enigma-Publisher, then the PCAP is deleted.

The same binary serves cloud and on-prem; on-prem only changes `enigma_api.server` and
`enigma_api.ca_cert_file`.

## Development Commands

```bash
go mod download
go build -o bin/enigma-sensor ./cmd/enigma-sensor
go test ./...
go test -race ./...                       # continuous integration (CI) runs this on Ubuntu, Windows and macOS
GOOS=windows GOARCH=amd64 go vet ./...    # compile-check Windows code and tests from Linux
GOOS=darwin GOARCH=amd64 go vet ./...
gofmt -l .                                # no lint or format gate in CI; keep this empty
bash scripts/test-linux-install.sh        # needs docker, dos2unix, fakeroot
```

`GOOS=windows go test` does not work from Linux (exec format error). There is no golangci-lint
config in the repo.

## Code Map

- `cmd/enigma-sensor/main.go`: argument handling (`collect-logs`, `--version`, `--help`), config
  path lookup, log rotation, wiring
- `config/`: `Config` struct, defaults and validation (`ValidateAndSetDefaults`), `SENSOR_*`
  environment overrides by reflection (`env_override.go`)
- `internal/sensor/`: the capture loop, processing worker pool, PCAP and `zeek_out_*` cleanup,
  Windows Zeek extraction
- `internal/capture/`: `factory.go` picks the capturer; `linux/` (tcpdump, also macOS), `windows/`
  (`capture_npcap.go`, `capture.go` for pktmon, `interface_mapper.go`)
- `internal/processor/`: `linux/` and `windows/` run Zeek; `common/` holds `ZeekLogFiles`,
  `subnet_filter.go`, `dhcp_enrichment.go` and the embedded scripts in `zeekscripts/`
- `internal/api/`: `client.go` (compress, chunk, retry, disk buffer, upload) and the generated
  gRPC code in `publish/`
- `internal/metadata/`: metadata sent with every upload
- `internal/pcapingest/`: offline PCAP directory watcher
- `internal/collect_logs/`: support bundle (tar.gz on Unix, zip on Windows)
- `installer/`: Linux installer script, Debian package, bundled Zeek debs, Windows Inno Setup script
  and Zeek runtime zip
- `loadtest/`: Docker Compose load generator, currently broken

## Upload Contract

- The sensor calls one RPC (remote procedure call), `publishService.uploadExcelMethod`, defined with
  an unused `getMethod` in
  `internal/api/publish/grpc_config.proto`.
- The **API key is sent in the `employeeId` field**, not a header.
- `data` is zlib-compressed JSON `{"dns","conn","ja3ja4","ja4s","dhcp"}`; each value is a
  base64-encoded, zlib-compressed Zeek log. `conn` is required; missing others are sent empty.
- `metadata` is a string map from `internal/metadata/collector.go`: `network_id`, `machine_id`,
  `sensor_version`, `os_name`, `os_version`, `architecture`, `host_ips`, `zeek_version`,
  `session_id`.
- Success is `statusCode` 200 in the response body. `statusCode` 410 means the key is invalid and is
  meant to stop the sensor (exit 0), but see the 410 trap below.
- Payloads over `enigma_api.max_payload_size_mb` are split by line into several uploads.
- An upload is tried 3 times, 5 seconds apart, then written to `buffering.dir`. Buffered payloads
  are retried oldest first before the next upload and purged after `buffering.max_age_hours`.

Enigma-Publisher (`grpc_config.proto`) receives this, and Enigma-Data-Generator
(`demo_generator/client/proto/publisher.proto`) imitates the sensor with the same contract.
Subscriber's fan-out reads the five log types by name, and Enigma-Analytics uses the JA3/JA4 data for
device role classification. Sensors in the field are updated only by
reinstalling, so old versions keep sending the old shape: changes must stay backward compatible,
and a contract change touches all of those repos.

## Traps

- **Zeek path is hardcoded.** Linux and macOS run `/opt/zeek/bin/zeek`; Windows runs
  `zeek-windows/zeek-runtime-win64/bin/zeek.exe` relative to the working directory. `zeek.path`
  exists in the config struct but is never read.
- **Zeek scripts differ by platform.** Linux and macOS pass the scripts embedded in
  `internal/processor/common/zeekscripts/` on the command line. Windows loads
  `site/custom-scripts/main.zeek` from `installer/windows/zeek-runtime-win64.zip`, which carries
  its own copy of the JA3/JA4 script plus ASN (autonomous system number) and hostname enrichment;
  on start the sensor writes the embedded sampling and DHCP scripts into that directory and adds
  them to `main.zeek`. A change to the embedded JA3/JA4 script does not reach Windows unless the zip is rebuilt.
- **`ZeekLogFiles`** (`internal/processor/common/processor.go`) is the single list of uploaded logs.
  Both the subnet filter and the rename to `.xlsx` use it, so a new log added there is filtered
  automatically. The uploader's `LogFiles` and `CombinedLogs` still need the field added by hand.
- **Subnet filtering fails closed.** If `FilterExcludedSubnets` errors, the capture is not
  uploaded. Keep it that way: the setting promises excluded traffic never leaves the host.
- **Sampling** is applied in Zeek to `conn` and `dns` records only. `sampling_percentage: 0` is
  replaced by 100 during validation.
- **`capture.retention_hours` is a pointer.** `nil` means "fall back to `log_retention_days`",
  `0` means delete straight after upload. Keep the distinction.
- **Config lookup order**: the system path (`/etc/enigma-sensor/config.json` or
  `C:\ProgramData\EnigmaSensor\config.json`) wins over `./config.json`. A file that exists but fails
  validation stops startup; it does not fall through to the next path.
- **New config fields** must be string, int, int64, float64, bool or a pointer to one, so the
  reflection-based `SENSOR_*` overrides can set them. Lists are comma-separated strings (see
  `zeek.excluded_subnets`). Add a default and bounds in `ValidateAndSetDefaults` and a row in the
  README configuration table.
- **410 shutdown does not trigger today (known, to be ticketed).** `client.go` wraps `ErrAPIGone`,
  but `sensor.go`, `pcapingest/watcher.go` and `main.go` compare errors with `==`, so a rejected key
  is retried and buffered like any failure. Use `errors.Is`. The mock uploaders in `sensor_test.go`
  and `watcher_test.go` return the bare error, which is why tests pass.
- **The API key is logged today (known, to be ticketed).** `main.go` logs the whole config with
  `%+v` at startup, key included, and `collect-logs` archives config and logs unredacted. Do not add
  more of this; see Code Standards.
- **`logging.level` has no effect.** Logging uses the standard `log` package with no levels.
- **Installers duplicate validation and config.** The Network ID rules exist in `config/config.go`,
  `installer/install-enigma-sensor.sh` and `installer/windows/enigma-sensor-installer.iss`. The
  Linux installer writes its own config JSON; Windows copies `config.example.json`; Docker copies
  `config.example.json` and applies environment variables in `docker-entrypoint.sh`.
- **Version** lives in three files; change it only with `scripts/bump-version.sh`.
- **Dependabot** covers GitHub Actions only.

## Code Standards

- Platform-specific code goes behind build tags with a stub for other platforms; check it compiles
  with the `GOOS=... go vet` commands above.
- Check every returned error and wrap with context (`fmt.Errorf("...: %w", err)`).
- Never log or archive the API key or other secrets. New files that hold secrets get 0600.
- Validate anything passed to an external command (see `validateInterfaceName` in `config/config.go`).
- New behaviour needs unit tests with the external tool mocked; the capture and processor packages
  inject command runners and file systems for this.
- Sensor changes reach customers only through a reinstall, and customer machines are memory
  constrained. Prefer changes that do not raise memory use or require a new Zeek build.
