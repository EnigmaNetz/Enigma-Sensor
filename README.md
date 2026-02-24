# Enigma Go Sensor

Cross-platform sensor that captures network traffic, converts it to Zeek-style logs, and optionally uploads to the Enigma API.

---

## Supported Platforms

- **Linux** (Ubuntu 20.04/22.04/24.04 LTS)
- **Windows 10 1809+**
- **macOS**
- **Docker** (any Linux distribution with Docker installed)

---

## Quick Install

### Linux (recommended)
1) Download the latest Linux release from GitHub Releases: https://github.com/EnigmaNetz/Enigma-Sensor/releases/latest
2) Unzip and run the installer:

```sh
export ENIGMA_API_KEY=YOUR_API_KEY
export ENIGMA_NETWORK_ID="HQ-Firewall-01"
sudo bash install-enigma-sensor.sh
```

The `ENIGMA_NETWORK_ID` uniquely identifies the network the sensor is deployed in (1-64 characters, letters/numbers/spaces/hyphens).

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

### Docker (any Linux distribution)

Docker is the recommended approach for non-Ubuntu Linux distributions (RHEL, CentOS, Fedora, Arch, etc.).

```sh
docker run -d \
  --name enigma-sensor \
  --network=host \
  --restart=unless-stopped \
  -e ENIGMA_API_KEY=YOUR_API_KEY \
  -e ENIGMA_NETWORK_ID="HQ-Firewall-01" \
  ghcr.io/enigmanetz/enigma-sensor:latest
```

**Environment variables:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENIGMA_API_KEY` | Yes | | Your Enigma API key |
| `ENIGMA_NETWORK_ID` | No | `enigma-sensor-docker` | Identifies the monitored network |
| `ENIGMA_API_URL` | No | `api.enigmaai.net:443` | Enigma API endpoint |

View logs:
```sh
docker logs -f enigma-sensor
```

For persistent logs, mount a volume:
```sh
docker run -d \
  --name enigma-sensor \
  --network=host \
  --restart=unless-stopped \
  -e ENIGMA_API_KEY=YOUR_API_KEY \
  -e ENIGMA_NETWORK_ID="HQ-Firewall-01" \
  -v /var/log/enigma-sensor:/var/log/enigma-sensor \
  ghcr.io/enigmanetz/enigma-sensor:latest
```

> **Note:** `--network=host` is required so the sensor can capture traffic on the host network interfaces. The container runs as root to allow tcpdump packet capture.

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
