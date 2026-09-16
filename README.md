# Enigma AI Sensor

The Enigma AI Sensor captures network traffic, turns it into Zeek logs on the host, and uploads those
logs to Enigma AI over gRPC (gRPC Remote Procedure Calls) with TLS (Transport Layer Security).
Packets never leave the host; only the Zeek logs do.

It runs in a loop:

1. **Capture** one window of traffic (60 seconds by default) into a PCAP (packet capture) file:
   `tcpdump` on Linux and macOS; Npcap on Windows when it is installed, otherwise the built-in
   `pktmon`.
2. **Process** the PCAP with Zeek into five logs: connections (`conn`), DNS (Domain Name System)
   lookups (`dns`), DHCP (Dynamic Host Configuration Protocol) leases (`dhcp`), and JA3/JA4 TLS
   client fingerprints (`ja3_ja4`) and JA4S server fingerprints (`ja4s`).
3. **Filter** out any record that touches an excluded subnet, if configured.
4. **Upload** the logs to the Enigma AI API, then delete the PCAP.

For development, building and releasing, see [DEVELOPMENT.md](DEVELOPMENT.md).

---

## Supported platforms

| Platform | How to install |
| --- | --- |
| Ubuntu 22.04 and 24.04 LTS (long-term support) | Release zip with installer (recommended) |
| Windows 10 1809 or later | Windows installer |
| Other Linux distributions | Docker image |
| macOS | Release binary only; you install Zeek yourself |

Ubuntu 20.04 is not supported: it is end of life and ships glibc 2.31 and libssl1.1, below Zeek
8.0's `libc6 >= 2.34` and `libssl3` requirements. The installer refuses to run there. Use Docker on
20.04 hosts.

---

## Requirements

Size the sensor to the peak traffic volume it will inspect. The table below lists a bare-minimum
floor plus three recommended tiers aligned to common network link speeds.

| Tier                    | Cores | RAM   | Disk   |
|-------------------------|-------|-------|--------|
| Minimum                 | 2     | 4 GB  | 20 GB  |
| Small (up to 100 Mbps)  | 4     | 8 GB  | 100 GB |
| Medium (up to 1 Gbps)   | 8     | 16 GB | 500 GB |
| Large (up to 10 Gbps)   | 16    | 32 GB | 1 TB   |

Disk figures are general guidance and are not tied to a specific retention window. Large
deployments should tune `capture.retention_hours` to keep local disk usage minimal.

**Network**: one NIC (network interface card) for management plus one capture source: a SPAN
(Switched Port Analyzer) or mirror port, a network TAP (Test Access Point), or a NIC in promiscuous
mode. On Windows, Npcap is strongly recommended: `pktmon` only sees traffic that this computer
itself sends or receives.

**Platform guidance**: Linux is the preferred platform for production deployments; Windows with
Npcap is supported across all sizing tiers.

The sensor needs outbound access to the API server on port 443.

---

## Install

Every install needs two values:

- **API key**: from the Enigma AI dashboard.
- **Network ID**: a name for the network this sensor watches, for example `HQ-Firewall-01`.
  1 to 64 characters; letters, numbers, spaces, hyphens and underscores; must start and end with a
  letter or number.

### Linux (Ubuntu)

1. Download `enigma-sensor-<version>-linux-release.zip` from
   [GitHub Releases](https://github.com/EnigmaNetz/Enigma-Sensor/releases/latest).
2. Unzip it and run the installer:

```sh
sudo ENIGMA_NETWORK_ID="HQ-Firewall-01" bash install-enigma-sensor.sh
```

The installer prompts for anything not passed: the API key (input hidden) and the Network ID. For an
unattended install, pass `ENIGMA_API_KEY` the same way. `ENIGMA_API_URL` overrides the server
(default `api.enigmaai.net:443`). Put the variables after `sudo`: sudo drops variables exported
before it.

The installer:

- installs `tcpdump` from the distribution repositories;
- installs Zeek 8.0.5 from the packages bundled in the zip (checked against `SHA256SUMS`), so no
  third-party package repository is needed. If the bundle is missing or fails to install, it falls
  back to the OpenSUSE Zeek repository;
- installs the `enigma-sensor` package, a systemd service that starts at boot;
- writes `/etc/enigma-sensor/config.json` if it does not already exist, then restarts the service.

Re-running the installer upgrades the sensor and keeps the existing config.

| | Path |
| --- | --- |
| Binary | `/usr/local/bin/enigma-sensor` |
| Config | `/etc/enigma-sensor/config.json` |
| Log | `/var/log/enigma-sensor/enigma-sensor.log` |
| Captures | `/var/lib/enigma-sensor/captures` |
| Buffered uploads | `/logs/buffer` (the default `logs/buffer`, resolved from the service's working directory `/`) |

```sh
sudo systemctl status enigma-sensor
sudo systemctl restart enigma-sensor    # after editing config.json
sudo journalctl -u enigma-sensor -f
```

### Windows

Run `enigma-sensor-windows-<version>.exe` from
[GitHub Releases](https://github.com/EnigmaNetz/Enigma-Sensor/releases/latest) as an administrator.

- On a fresh install it asks for the API key and Network ID and writes
  `C:\ProgramData\EnigmaSensor\config.json`. An existing config is kept.
- If Npcap is not installed, it offers to download Npcap and launch its installer (unchecked by
  default). Without Npcap the sensor falls back to `pktmon`.
- It installs to `C:\Program Files\EnigmaSensor` and registers the `EnigmaSensor` service (managed
  by NSSM, the Non-Sucking Service Manager), set to start automatically.

The sensor writes its log twice:

- `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log`: the service's console output.
- `C:\Program Files\EnigmaSensor\logs\enigma-sensor.log`: the sensor's own rotated log.

```powershell
Restart-Service EnigmaSensor    # after editing config.json
```

On Windows, `capture.interface` takes `pktmon` component IDs (from `pktmon comp list`) or `any`.
The sensor maps those IDs to Npcap devices when Npcap is in use.

### Docker (any Linux distribution)

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

`--network=host` is required so the sensor sees the host's interfaces. The container runs as root so
`tcpdump` can capture. The image bundles the same Zeek 8.0.5 packages as the Linux release.

The container builds its config from `config.example.json` plus environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENIGMA_API_KEY` | Yes | | API key (alias for `SENSOR_ENIGMA_API_API_KEY`) |
| `ENIGMA_NETWORK_ID` | No | `enigma-sensor-docker` | Network ID (alias for `SENSOR_NETWORK_ID`) |
| `ENIGMA_API_URL` | No | `api.enigmaai.net:443` | API server (alias for `SENSOR_ENIGMA_API_SERVER`) |

Any other setting uses the `SENSOR_*` pattern described in Configuration. Logs go to
`/var/log/enigma-sensor` and captures to `/var/lib/enigma-sensor/captures` inside the container.

```sh
docker logs -f enigma-sensor
```

### macOS

Download the `enigma-sensor-darwin-<version>` binary (amd64) from the release. There is no installer:

- install Zeek 8.0.x so that it is at `/opt/zeek/bin/zeek` (the path is fixed);
- make sure `tcpdump` is available and run the sensor as root;
- put `config.json` in the working directory (copy `config.example.json`).

---

## Sending data to an on-prem Enigma AI install

The sensor is the same for cloud and on-prem; only the server and certificate change.

The on-prem installer sets up one sensor on the Enigma AI host itself. For each additional sensor:

1. Take the API key from `secrets/sensor_keys` on the Enigma AI host: the part before the colon.
2. Set `enigma_api.server` to that host's name on port 443, for example
   `enigma.acme.internal:443`. The name must resolve from the sensor and match the certificate.
3. If the host still uses its generated self-signed certificate (`nginx/certs/server.crt` in the
   install directory), copy that certificate to the sensor and set `enigma_api.ca_cert_file` to
   its path. Without it the TLS handshake fails and the sensor keeps retrying while appearing to
   run.

For the Linux installer, pass `ENIGMA_API_URL=enigma.acme.internal:443` after `sudo`, then add
`ca_cert_file` to `/etc/enigma-sensor/config.json` and restart the service. For Docker, mount the
certificate and set `SENSOR_ENIGMA_API_CA_CERT_FILE` to its path inside the container.

---

## Configuration

Settings live in `config.json`. The sensor reads the first file it finds:

- Linux and macOS: `/etc/enigma-sensor/config.json`, then `./config.json`
- Windows: `C:\ProgramData\EnigmaSensor\config.json`, then `./config.json`

Invalid values stop the sensor at startup with a message naming the field. The placeholder
`network_id` from `config.example.json` is rejected.

| Setting | Default | Description |
| --- | --- | --- |
| `network_id` | none (required) | Network ID, see Install |
| `enigma_api.server` | `api.enigmaai.net:443` | API server, `host:port` |
| `enigma_api.api_key` | none | API key. Without it (or with `upload: false`) the sensor captures and processes but uploads nothing |
| `enigma_api.upload` | `false` | Upload logs. The installers set `true` |
| `enigma_api.ca_cert_file` | none | PEM (Privacy-Enhanced Mail format) CA (certificate authority) certificate to trust instead of the system store; for on-prem |
| `enigma_api.max_payload_size_mb` | `25` | Logs larger than this are split and uploaded in several requests |
| `capture.interface` | `any` | Interface to capture on, or a comma-separated list. On Linux, capturing several named interfaces needs `mergecap` (from Wireshark) to combine them |
| `capture.window_seconds` | none | Length of each capture window. The installers and example config use `60` |
| `capture.loop` | `false` | Keep capturing. `false` runs one window and exits. The installers set `true` |
| `capture.output_dir` | none | Working directory for captures and Zeek output |
| `capture.retention_hours` | `log_retention_days` × 24 | How long Zeek output folders are kept after upload. `0` deletes them straight after upload. Maximum 720. The PCAP itself is always deleted after processing |
| `capture.max_processing_workers` | `10` | PCAPs processed at once (1 to 20). Up to the same number of captures can wait in a queue; when the queue is full, a new capture is dropped with a warning |
| `zeek.sampling_percentage` | `100` | Share of `conn` and `dns` records kept, chosen at random. `0` is treated as `100` |
| `zeek.excluded_subnets` | empty | Comma-separated CIDR (Classless Inter-Domain Routing) blocks, for example `10.0.0.0/8,172.20.10.0/24`. Any record whose addresses (including DNS answers) fall inside one is removed before upload. If filtering fails, nothing from that capture is uploaded |
| `buffering.dir` | `logs/buffer` | Where uploads that failed are kept for retry. Relative paths resolve from the working directory |
| `buffering.max_age_hours` | `2` | Buffered uploads older than this are discarded |
| `logging.file` | none | Log file. Output always also goes to the console |
| `logging.max_size_mb` | `50` | Rotate the log at this size (10 to 500) |
| `logging.log_retention_days` | `7` | Days to keep rotated logs (1 to 30) |
| `logging.max_backups` | `5` | Rotated logs to keep (1 to 10) |
| `pcap_ingest.*` | disabled | Offline PCAP processing, see below |

`logging.level` is accepted but currently has no effect.

### Environment variable overrides

Every setting can be overridden with `SENSOR_<SECTION>_<FIELD>` in upper case; top-level fields use
`SENSOR_<FIELD>`. For example, `logging.max_size_mb` becomes `SENSOR_LOGGING_MAX_SIZE_MB`,
`zeek.excluded_subnets` becomes `SENSOR_ZEEK_EXCLUDED_SUBNETS` and `network_id` becomes
`SENSOR_NETWORK_ID`. Overrides apply on top of `config.json` and are validated the same way.

### Uploading PCAP files instead of live capture

With `pcap_ingest.enabled: true`, the sensor also watches a directory for `.pcap` and `.pcapng`
files and runs them through the same processing and upload. Live capture keeps running alongside it.

| Setting | Default | Description |
| --- | --- | --- |
| `pcap_ingest.watch_dir` | none (required when enabled) | Directory to watch |
| `pcap_ingest.poll_interval_seconds` | `10` | How often to look for new files (1 to 300) |
| `pcap_ingest.file_stable_seconds` | `5` | A file must stop growing for this long before it is picked up (1 to 60) |

Drop files into `<watch_dir>/incoming/`. They move to `processing/`, then to `processed/` or
`failed/`. Nothing cleans up `processed/`, so remove old files yourself.

---

## What gets uploaded

Each upload carries the five Zeek logs (compressed) and a small set of sensor metadata: the network
ID, a machine ID, sensor and Zeek versions, operating system and architecture, up to ten private
IPv4 addresses of the sensor host, and a session ID.

If an upload fails three times, it is saved to `buffering.dir` and retried before the next upload,
until it is older than `buffering.max_age_hours`.

If the API rejects the API key (for example, a revoked key), the sensor currently treats it like any
other failed upload: it keeps capturing, retries, and buffers. Check the log for `410 Gone` if a
sensor's data stops arriving.

---

## Diagnostics

```sh
enigma-sensor --version
enigma-sensor collect-logs
```

`collect-logs` writes `enigma-logs-YYYYMMDD-HHMMSS.tar.gz` (Linux and macOS) or `.zip` (Windows) in
the current directory. It collects `logs/`, `captures/` and `config.json` **relative to the current
directory**, plus version and system information, and fails if it finds none of them:

- **Windows**: run it from `C:\Program Files\EnigmaSensor`. `C:\ProgramData\EnigmaSensor` is not
  included; attach its `config.json` and `logs\enigma-sensor.log` separately if support asks.
- **Linux package installs**: the files live in `/etc/enigma-sensor`, `/var/log/enigma-sensor` and
  `/var/lib/enigma-sensor`, so `collect-logs` finds nothing. Archive those directories instead.

The config and the sensor log both contain your API key. Share them only with Enigma AI support.
