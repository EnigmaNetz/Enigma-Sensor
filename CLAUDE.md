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

The Enigma AI Sensor is a Go 1.25 agent installed on customer machines. Each loop it:

PCAP is packet capture; gRPC is gRPC Remote Procedure Calls.

```
Capture (tcpdump | Npcap | pktmon) → PCAP → Zeek → 5 logs → excluded-subnet filter → gRPC upload → Enigma-Publisher
```

- **Capture**: `tcpdump` on Linux and macOS. On Windows, Npcap (via gopacket) when
  `wpcap.dll` is present, otherwise `pktmon`, whose ETL (Event Trace Log) output is converted with
  `pktmon etl2pcapng`.
- **Process**: Zeek writes `conn`, `dns`, `dhcp`, `ja3_ja4` and `ja4s` logs as JSON, one record
  per line. On every platform `dhcp.log` is then enriched with DHCP (Dynamic Host Configuration
  Protocol) option 55 read from the PCAP with gopacket. The logs are renamed to `.xlsx`, but they
  are still Zeek JSON logs, not Excel.
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
- `internal/api/`: `client.go` (batch, retry, disk buffer, upload), the generated gRPC code for
  `uploadRecords` in `ingest/` and for the old `uploadExcelMethod` in `publish/`
- `internal/records/`: maps Zeek JSON logs into the typed records of `sensor_records.proto`
- `internal/metadata/`: metadata sent with every upload
- `internal/pcapingest/`: offline PCAP directory watcher
- `internal/collect_logs/`: support bundle (tar.gz on Unix, zip on Windows)
- `installer/`: Linux installer script, Debian package, bundled Zeek debs, Windows Inno Setup script
  and Zeek runtime zip
- `loadtest/`: Docker Compose load generator, currently broken

## Upload Contract

- The sensor calls `SensorIngest.uploadRecords` (B1CF-2108), defined in
  `internal/api/ingest/sensor_records.proto`. That file is a byte-identical copy of
  Enigma-Publisher's `sensor_records.proto`; CI (`proto-drift.yml`) fails if it drifts. Change the
  Publisher's first, copy it here, then regenerate the Go code (DEVELOPMENT.md).
- Zeek writes JSON logs (`LogAscii::use_json=T`, `types.ZeekJSONLogsArg`). `internal/records` maps
  each log line into a typed record by field name, converting values the way the tab-separated
  log wrote them so the Subscriber stores the same values; `records_test.go` proves it on one
  capture written in both formats (`internal/records/testdata`, `regenerate.sh`). A Zeek field
  with no slot in the proto is dropped, and a record that cannot be decoded is skipped and counted
  in the log (the subnet filter has already run on the file, so this cannot leak excluded data).
- The request: `apiKey`, `schemaVersion` 1, `sensorVersion`, per-log `counts`,
  `COMPRESSION_ZLIB`, the `metadata` map from `internal/metadata/collector.go` (`network_id`,
  `machine_id`, `sensor_version`, `os_name`, `os_version`, `architecture`, `host_ips`,
  `zeek_version`, `session_id`), and `records`: a zlib-compressed `RecordBatch`, streamed from the
  logs so memory holds one compressed batch.
- Batches are at most `enigma_api.max_payload_size_mb` uncompressed (capped at 96 MiB, under the
  Subscriber's 128 MiB inflate cap) and 1,000,000 records (the Publisher's limit). A window with
  no records is not uploaded.
- Success is `statusCode` 200 in the response body. 410 means the key is invalid: not retried or
  buffered, and the sensor stops and exits 0. 400 means the Publisher refused the request itself:
  not retried or buffered, and a buffered request that gets a 400 is deleted.
- Each upload RPC has a 4m30s deadline (under Cloud Run's 300 s request timeout), and the connection
  uses keepalive pings while an RPC is in flight. A batch is tried 3 times, then written to
  `buffering.dir` as `buf_<time>_<nanos>.rec` (the request without its API key, which is added back
  when it is sent); a cancelled upload is buffered too, and so is every remaining batch. Once one
  batch fails every retry, the rest of the window is buffered without trying, so an outage does not
  hold the worker (and fill the PCAP queue) for a full set of retries per batch. Every failed batch
  is logged. Between
  attempts it waits half to all of `retryDelay` (5 s), doubled per retry, and the wait ends early on
  cancellation. Buffered payloads are retried oldest first before the next upload and purged after
  `buffering.max_age_hours`. Delivery is at least once. Only one worker flushes the buffer at a
  time (`flushMu`), and buffer files are written under a `.tmp` name and renamed.
- `.bin` buffer files are old Zeek-log payloads from a sensor version before typed uploads. They
  are still sent through `publishService.uploadExcelMethod` (`internal/api/publish/`, API key in
  `employeeId`), so an upgrade loses nothing buffered. Nothing else uses that method.

Enigma-Publisher receives this and Enigma-Subscriber decodes it; Enigma-Data-Generator imitates
the sensor with the same contract. Enigma-Analytics uses the JA3/JA4 data for device role
classification. Sensors in the field are updated only by reinstalling, so old versions keep
sending the old shape: the Publisher and Subscriber keep accepting it, and a contract change
touches all of those repos.

## Traps

- **Zeek path is hardcoded.** Linux and macOS run `/opt/zeek/bin/zeek`; Windows runs
  `zeek-windows/zeek-runtime-win64/bin/zeek.exe` relative to the working directory. `zeek.path`
  exists in the config struct but is never read.
- **Zeek scripts differ by platform.** Linux and macOS pass the scripts embedded in
  `internal/processor/common/zeekscripts/` on the command line. Windows loads
  `site/custom-scripts/main.zeek` from `installer/windows/zeek-runtime-win64.zip`, which carries
  its own copy of the JA3/JA4 script; on start the sensor writes the embedded sampling and DHCP
  scripts into that directory and adds them to `main.zeek`. The zip is built and published by the
  Enigma-Zeek repository, so a change to the embedded JA3/JA4 script reaches Windows only through a
  new Enigma-Zeek release.
- **`ZeekLogFiles`** (`internal/processor/common/processor.go`) is the single list of uploaded logs.
  Both the subnet filter and the rename to `.xlsx` use it, so a new log added there is filtered
  automatically. Uploading it also needs a record type and a `RecordBatch` field in the Publisher's
  `sensor_records.proto` first, then an entry in `records.Read` and a field in the uploader's
  `LogFiles`.
- **Subnet filtering fails closed.** If `FilterExcludedSubnets` errors, the capture is not
  uploaded. Keep it that way: the setting promises excluded traffic never leaves the host. A line
  that is not a JSON record is an error too, so a Zeek that writes tab-separated logs uploads
  nothing. The logs are filtered in place, not only in the upload, because support bundles archive
  the capture directories.
- **Sampling** is applied in Zeek to `conn` and `dns` records only. `sampling_percentage: 0` is
  replaced by 100 during validation.
- **`capture.retention_hours` is a pointer.** `nil` means "fall back to `log_retention_days`",
  `0` means delete straight after upload. Keep the distinction.
- **Config lookup order**: the system path (`/etc/enigma-sensor/config.json` or
  `C:\ProgramData\EnigmaSensor\config.json`) wins over `./config.json`. A file that exists but fails
  validation stops startup; it does not fall through to the next path. `config.Paths` and
  `config.FindPath` hold this order for both the sensor and `collect-logs`.
- **New config fields** must be string, int, int64, float64, bool or a pointer to one, so the
  reflection-based `SENSOR_*` overrides can set them. Lists are comma-separated strings (see
  `zeek.excluded_subnets`). Add a default and bounds in `ValidateAndSetDefaults` and a row in the
  README configuration table.
- **`ErrAPIGone` is always wrapped.** `client.go` wraps it, and the records reader and `UploadLogs` wrap it again.
  Check it with `errors.Is`, never `==`; the test mocks return wrapped errors to catch this. Exit 0
  is how the sensor says "stay stopped": systemd (`Restart=on-failure`) and NSSM (`AppExit 0 Exit`)
  honour it, Docker's `--restart=unless-stopped` does not.
- **Never print the config directly.** `%+v` on `Config` prints `enigma_api.api_key`; log
  `cfg.Redacted()` instead. `collect-logs` masks `config.json` by its JSON structure
  (`internal/collect_logs/redact_config.go`): every string under `enigma_api` except `server` and
  `ca_cert_file`, and any field named like a secret. A config that is not valid JSON is left out.
  Logs are masked line by line (`redact.go`) for the literal key plus the `"api_key": "..."` and
  `APIKey:...` shapes older sensors logged; masking keeps file length so tar sizes stay valid. A new
  secret field needs `Redacted()`, and a new public `enigma_api` field is masked in bundles unless
  added to `publicAPISettings`. Captures are archived unmasked.
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
