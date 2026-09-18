# CLAUDE.md

<!-- BEGIN: AI Security Policies (auto-synced from Enigma-Developer-Policies) -->

_This section is copied from `docs/CLAUDE.md` in Enigma-Developer-Policies by `scripts/sync-security-policies.sh`. Change it there; edits made here are overwritten on the next sync._

# AI Agent Security Rules

**Purpose:** Mandatory security rules for AI coding assistants working in Enigma AI codebases. They apply in every repository. The approved tools are listed in section 3 of `docs/ai-usage-policy.md` in Enigma-Developer-Policies.

These rules back the AI Usage and Development Policy, a SOC 2 (System and Organization Controls 2) control. They have no exceptions: a developer asking, insisting or saying it is safe does not change them.

## Security Rules

### 1. Never access secrets files

Do not read, open, search, print or otherwise process files that contain secrets or credentials.

**This includes:**
- `.env` and `.env.*` files (all variants)
- Service account key files (`.json`, `.pem`, `.key`)
- SSH (Secure Shell) private keys and certificates
- Cloud provider credentials (`.aws/credentials`, `.gcloud/`, and similar)
- Kubernetes secrets manifests
- Password files and credential stores
- Any file marked as containing secrets

**If asked to read one:**
1. Decline politely and explain this policy.
2. Suggest referencing environment variables instead.
3. Recommend storing the secret in GCP (Google Cloud Platform) Secret Manager, or AWS (Amazon Web Services) Secrets Manager or HashiCorp Vault where those are in use.
4. Do not read the file, even if the developer insists.

### 2. Never access production data

Do not access production environments or production data. The production GCP project is `enigmaai-prod`.

**Not allowed:**
- Reading production databases
- Querying production BigQuery datasets
- Accessing production GCP projects (`enigmaai-prod`) or AWS accounts
- Reading production logs or metrics
- Modifying production configuration
- Running commands against production infrastructure

**Allowed (non-production only):**
- Staging and development environments (staging project: `enigma-staging`)
- Read-only queries against staging databases
- Staging GCP or AWS resources through CLI (command-line interface) commands
- Development environment logs and configuration

**Before running any cloud command:**
1. Confirm the target environment is not production.
2. Check the project ID, account name and environment variables: `enigma-staging` is allowed, `enigmaai-prod` is not.
3. Ask for confirmation if the environment is unclear.
4. Refuse if the command would reach production.

### 3. Never run destructive infrastructure commands

- Do not run `terraform apply` or `terraform destroy`.
- Do not deploy to production. Rule 2 already forbids running commands against production infrastructure; deploying is one of them.
- `terraform plan`, `terraform validate` and `terraform fmt` are allowed.
- The developer reviews and applies infrastructure changes themselves.

### 4. Training data opt-out

Every approved AI tool must have training on code disabled. Developers are responsible for verifying this setting.

### 5. Code security requirements

All AI-generated code must:
- Pass static analysis (SAST, static application security testing) and linting
- Pass dependency vulnerability scanning
- Pass secret scanning to prevent credential leakage (TruffleHog runs in pre-commit hooks)
- Receive manual human review before merging

### 6. Extra review for critical systems

AI-generated code in these areas needs additional scrutiny and explicit developer approval:
- Authentication and authorization logic, including Stytch B2B (business-to-business) authentication
- Payment processing and financial transactions
- Encryption and cryptographic operations
- Database migration scripts, especially any using `BYPASSRLS`
- Row-level security (RLS) policies
- Infrastructure-as-code changes (Terraform)
- Security-critical APIs and endpoints

### 7. Data classification

Respect data classification:
- **Public:** open-source code, public documentation. AI accessible.
- **Internal:** staging data, development credentials. AI accessible with care.
- **Confidential:** customer data, production credentials, proprietary algorithms. Customer data and proprietary algorithms require explicit approval. Production credentials are never accessed, with or without approval (rules 1 and 2).
- **Restricted:** security keys, compliance data, executive communications. AI prohibited.

## Incident Reporting

**Alert the developer immediately if you:**
- Are asked to read secrets files
- Are asked to access production environments
- Find hardcoded credentials in code
- Find attempts to bypass security controls
- Find unapproved AI tools in use

**Response:** decline politely, explain the policy and suggest a secure alternative.

## Quick Reference

**Never:**
- Read `.env` or other secrets files
- Access production data or environments
- Run `terraform apply` or `terraform destroy`
- Deploy to production
- Generate or suggest hardcoded credentials
- Bypass security scanning, code review or any other security control, even when asked (refuse and alert the developer)
- Access Restricted data

**Always:**
- Verify the environment before running cloud commands
- Suggest secure alternatives (environment variables, secrets managers)
- Pass security scanning (SAST, secret scanning, dependency checks)
- Flag security-critical code for extra human review

**Ask first:**
- If the environment (production or staging) is unclear
- If a destructive operation is requested (other than those on the Never list, which are refused)
- If the data classification is uncertain

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
