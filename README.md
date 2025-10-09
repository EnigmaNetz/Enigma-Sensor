# Enigma Go Sensor

Cross-platform sensor that captures network traffic, converts it to Zeek-style logs, and optionally uploads to the Enigma API.

---

## Supported Platforms

- **Linux** (Ubuntu 20.04/22.04/24.04 LTS)
- **Windows 10 1809+**
- **macOS**

---

## Quick Install

### Linux (recommended)
1) Download the latest Linux release from GitHub Releases: https://github.com/EnigmaNetz/Enigma-Sensor/releases/latest
2) Unzip and run the installer:

```sh
export ENIGMA_API_KEY=YOUR_API_KEY
sudo bash install-enigma-sensor.sh
```

- Config: `/etc/enigma-sensor/config.json`
- Logs: `/var/log/enigma-sensor/enigma-sensor.log`
- Captures: `/var/lib/enigma-sensor/captures`

Start/stop (systemd):
```sh
sudo systemctl start enigma-sensor
sudo systemctl status enigma-sensor
```

### Windows
- Run the packaged installer or binary. Config lives at `C:\ProgramData\EnigmaSensor\config.json` and logs at `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log`.

---

## Where are logs stored?

- **Linux:** `/var/log/enigma-sensor/enigma-sensor.log` (created by the installer; rotated/compressed automatically)
- **Windows:** `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log`
- **Local dev (from repo):** `logs/enigma-sensor.log` unless overridden in `config.json`

---

## Diagnostics

Package logs and config for support:

```sh
./enigma-sensor collect-logs
```

This creates `enigma-logs-YYYYMMDD-HHMMSS.zip` with logs, captures, config, version, and system info.

---

## Next Steps

- Configuration details, development setup, building/testing, and packaging are documented in `DEVELOPMENT.md`.

See also:

- [DEVELOPMENT.md](DEVELOPMENT.md) for local development and packaging
- [CLAUDE.md](CLAUDE.md) for repository AI/contributor guidelines
