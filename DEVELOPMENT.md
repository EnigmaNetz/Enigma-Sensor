# Development & Operations

This document covers local development, configuration, building, testing, and packaging.

---

## Prerequisites

- Go 1.24+
- Linux/macOS: `tcpdump`, `zeek` for full flow; Windows: admin for `pktmon`

---

## Local Setup

1) Install deps and test tooling:
```sh
go mod download
go test -i ./...
```

2) Create `config.json` from example and adjust as needed:
```json
{
  "network_id": "YOUR_NETWORK_ID",
  "logging": { "file": "logs/enigma-sensor.log" },
  "capture": { "output_dir": "./captures", "window_seconds": 60, "loop": true, "interface": "any" },
  "enigma_api": { "server": "api.enigmaai.net:443", "api_key": "YOUR_API_KEY", "upload": true },
  "buffering": { "dir": "logs/buffer", "max_age_hours": 2 },
  "zeek": { "sampling_percentage": 100 }
}
```

3) Build and run:
```sh
go build -o bin/enigma-sensor ./cmd/enigma-sensor
./bin/enigma-sensor
```

---

## Configuration Locations

- Linux (installed): `/etc/enigma-sensor/config.json`
- Windows (installed): `C:\\ProgramData\\EnigmaSensor\\config.json`
- Repo/local dev: `./config.json`

## Log Locations

- Linux (installed): `/var/log/enigma-sensor/enigma-sensor.log`
- Windows (installed): `C:\\ProgramData\\EnigmaSensor\\logs\\enigma-sensor.log`
- Repo/local dev: `./logs/enigma-sensor.log`

Rotation is handled via built-in rotation (lumberjack): `max_size_mb`, `log_retention_days`, 3 backups, gzip.

---

## Commands

```sh
# Show help/version
./bin/enigma-sensor --help
./bin/enigma-sensor --version

# Collect diagnostics
./bin/enigma-sensor collect-logs

# Run tests (host OS)
go test ./...

# Cross-platform tests (CI/local)
GOOS=linux GOARCH=amd64 go test ./...
GOOS=windows GOARCH=amd64 go test ./...
GOOS=darwin GOARCH=amd64 go test ./...
```

---

## Packaging

### Debian (.deb)
```sh
cd installer/debian
./build-deb.sh
```
- Installs systemd unit, default config at `/etc/enigma-sensor/config.json`

### Windows Installer
- Inno Setup with NSSM; logs at `C:\\ProgramData\\EnigmaSensor\\logs\\enigma-sensor.log`

---

## Version Management

Bump version across all files:
```sh
./scripts/bump-version.sh patch   # 1.5.0 -> 1.5.1
./scripts/bump-version.sh minor   # 1.5.0 -> 1.6.0
./scripts/bump-version.sh major   # 1.5.0 -> 2.0.0
```

Updates `internal/version/version.go`, `installer/debian/DEBIAN/control`, and `installer/windows/enigma-sensor-installer.iss`, then commits and creates a git tag.

---

## Notes and Standards

- Follow existing code patterns and conventions
- Update/add tests for functional changes
- Avoid logging secrets; keep permissions restrictive
- Consider Linux, Windows, macOS impacts for changes


