# Development

Local development, testing, packaging and releasing for the Enigma AI Sensor. How the sensor works
and how to configure it is in [README.md](README.md).

The sensor is the first step of the platform's data flow: Sensor → Enigma-Publisher (gRPC) →
Pub/Sub in cloud or NATS on-prem → Enigma-Subscriber → warehouse → Enigma-Analytics and the UI.

The default branch is `main`. Branch from it and open pull requests against it.

---

## Prerequisites

- Go 1.25
- Linux or macOS, to run the sensor: root, `tcpdump`, and Zeek 8.0.x at `/opt/zeek/bin/zeek` (the
  path is fixed in `internal/processor/linux/processor.go`)
- Windows, to run the sensor: an administrator shell. `pktmon` is built in; Npcap is optional. Zeek
  comes from `installer/windows/zeek-runtime-win64.zip`, which the sensor extracts to
  `zeek-windows/` in its working directory on start
- For packaging and the Linux install test: `dos2unix`, `fakeroot` and Docker

---

## Run locally

```sh
go mod download
cp config.example.json config.json
```

Edit `config.json`:

- set `network_id` (the placeholder is rejected at startup);
- for uploads, set `enigma_api.api_key` and point `enigma_api.server` at staging:
  `api.staging.getenigma.ai:443`. The default in `config.example.json` is production;
- or set `enigma_api.upload` to `false` to capture and process without uploading.

`config.json` is gitignored. It holds an API key; never commit it.

```sh
go build -o bin/enigma-sensor ./cmd/enigma-sensor
sudo ./bin/enigma-sensor
```

On Linux the sensor looks for `/etc/enigma-sensor/config.json` before `./config.json`, so a
machine with an installed sensor uses the installed config.

Paths in `config.example.json` are relative, so logs go to `logs/`, captures and Zeek output to
`captures/zeek_out_<timestamp>/`, and failed uploads to `logs/buffer/`.

To process existing PCAP (packet capture) files instead of capturing, enable `pcap_ingest` (see README) and drop
files into `<watch_dir>/incoming/`.

---

## Test

```sh
go test ./...                      # host platform
go test -race ./...                # what continuous integration (CI) runs
go test -v ./internal/capture/...  # one package
```

Platform code sits behind build tags (`//go:build windows`, `//go:build linux || darwin`), so
`go test` on Linux never compiles the Windows files. You cannot run another platform's tests from
Linux (`GOOS=windows go test` fails with "exec format error"), but you can compile them:

```sh
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=darwin GOARCH=amd64 go vet ./...
```

CI runs the tests natively on each platform.

### Linux install test

```sh
bash scripts/test-linux-install.sh
```

Builds the `.deb`, assembles the release zip layout, and installs it in fresh `ubuntu:22.04`,
`ubuntu:24.04`, `debian:12` and `debian:13` containers with the OpenSUSE Zeek repository blocked, to
prove each host installs Zeek from its matching bundled packages. It also checks that a tampered
bundle is refused, upgrades a host running the previous release's Zeek 8.0.5 packages (taken from git
history) with edited Zeek config files, and checks that a failed Zeek upgrade keeps the sensor and
warns that Zeek is outdated. It also checks that an API key containing a quote and backslashes still
produces valid JSON, and that a key with a control character is refused.

### Windows install test

```powershell
pwsh scripts/test-windows-install.ps1
```

Runs the built Windows installer silently (in CI, `windows-install-test.yml` on a disposable
runner) and checks that `config.json` is valid JSON with a key containing a quote and backslashes,
that only SYSTEM and Administrators can access it, and that an upgrade locks down a config an earlier
installer left readable. It installs the sensor service, so run it only on a throwaway machine.

### Load test

`loadtest/` holds a Docker Compose traffic generator. It does not currently run; see
[loadtest/README.md](loadtest/README.md).

---

## CI

CI runs in GitHub Actions.

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `go-test.yml` | Push to `main`, every PR | `go test -v -race ./...` on Ubuntu, Windows and macOS; on Ubuntu, also fails if `THIRD_PARTY_NOTICES` is out of date |
| `linux-install-test.yml` | Push to `main`, every PR | `scripts/test-linux-install.sh`, then builds the Docker image and checks its Zeek is 8.0.x |
| `windows-install-test.yml` | Push to `main`, every PR | Builds the Windows installer and runs `scripts/test-windows-install.ps1` |
| `pr-build-artifacts.yml` | PR labelled `build:windows`, `build:linux`, `build:macos` or `build:all` | Builds installers and binaries as workflow artifacts (kept 7 days) |
| `go-build-release.yml` | Any tag push | Builds everything and attaches it to the GitHub Release for that tag |
| `docker-publish.yml` | `v*` tag push | Builds and pushes `ghcr.io/enigmanetz/enigma-sensor` tagged with the version, `major.minor`, `major` and `latest` |

`pr-build-artifacts.yml` and `go-build-release.yml` both call `build-artifacts-reusable.yml`. There
is no lint or format check in CI; run `gofmt -l .` before opening a PR.

Dependabot opens weekly grouped PRs for GitHub Actions versions.

---

## Package

### Debian package

```sh
cd installer/debian
./build-deb.sh
```

Always rebuilds `bin/enigma-sensor-linux`, then writes `bin/enigma-sensor_<version>_amd64.deb`. The
package installs `/usr/local/bin/enigma-sensor` and a systemd unit, depends on `zeek-lts-core`
(or the `zeek-core` earlier releases installed) and `tcpdump`, and enables and starts the service on install. It does not write a config; the installer
does.

### Linux release zip

Built in CI only. It holds `install-enigma-sensor.sh`, the `.deb`, `LICENSE`,
`THIRD_PARTY_NOTICES`, and the bundled Zeek packages under `zeek/ubuntu-22.04/` and `zeek/ubuntu-24.04/`. Running
`installer/install-enigma-sensor.sh` straight from a checkout does not find the bundle and falls back
to the OpenSUSE repository; see
[installer/linux/zeek/README.md](installer/linux/zeek/README.md).

### License and third-party notices

`LICENSE` (PolyForm Internal Use 1.0.0) and `THIRD_PARTY_NOTICES` at the repository root ship in
every release artifact: the Windows installer, the `.deb` (`/usr/share/doc/enigma-sensor/`), the Linux
release zip, the Linux and macOS binary archives, and the Docker image. Only the Windows installer
shows `LICENSE` for acceptance.

Regenerate `THIRD_PARTY_NOTICES` after changing `go.mod` or anything in `scripts/third-party-notices/`
(go-licenses is pinned in the script):

```sh
scripts/third-party-notices/generate.sh
```

The Go section is generated. The Zeek, Spicy, Windows Zeek runtime and NSSM sections are maintained by
hand in `scripts/third-party-notices/`; each subdirectory's README says what to update when the
bundled Zeek packages, the Windows Zeek runtime or `nssm.exe` change.

### Windows installer

See [installer/windows/README.md](installer/windows/README.md).

### Docker image

```sh
docker build -t enigma-sensor .
```

`.dockerignore` excludes `installer/` except the bundled Zeek packages, which the image installs.

---

## Release

1. On a branch, run the version bump. It needs a clean working tree and commits the change:

   ```sh
   ./scripts/bump-version.sh patch   # or minor, major
   ```

   It updates `internal/version/version.go`, `installer/debian/DEBIAN/control` and
   `installer/windows/enigma-sensor-installer.iss`. It does not tag.

2. Open a PR and merge it to `main`.
3. Tag the version bump commit `v<version>` (for example `v1.9.5`) and push the tag. That runs
   `go-build-release.yml` and `docker-publish.yml`.

Sensors in the field update only when someone reinstalls them, so older versions stay in use for a
long time. Keep the upload format backward compatible.
