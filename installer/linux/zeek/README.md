# Bundled Zeek runtime packages (Linux)

These Debian packages ship inside the Linux release zip under `zeek/` so
`install-enigma-sensor.sh` can install Zeek without reaching any third-party
package repository.

## Contents

| File | Version |
|------|---------|
| `zeek-core_8.0.5-0_amd64.deb` | 8.0.5-0 |
| `zeekctl_8.0.5-0_amd64.deb` | 8.0.5-0 |
| `zeek-client_8.0.5-0_all.deb` | 8.0.5-0 |

## Provenance

Downloaded from the OpenSUSE Build Service `security:zeek` project, `xUbuntu_22.04`
channel, upstream version 8.0.5-0:

- `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/amd64/zeek-core_8.0.5-0_amd64.deb`
- `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/amd64/zeekctl_8.0.5-0_amd64.deb`
- `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/all/zeek-client_8.0.5-0_all.deb`

The 22.04-built set is also used on Ubuntu 24.04; it is verified to install
cleanly on both releases. Ubuntu 20.04 is not supported: it is EOL and ships
glibc 2.31 and libssl1.1, below Zeek 8.0's `libc6 >= 2.34` and `libssl3`
requirements.

Zeek is BSD-licensed, so redistributing these packages inside Enigma's own
release artifact is cleared.

## Why this minimal set

The `zeek` metapackage pulls `zeek-zkg`, `zeek-spicy-dev` and `zeek-btest-data`,
roughly 58 MB of development and test payload the sensor never uses. The sensor
only invokes `/opt/zeek/bin/zeek`; `zeekctl` and `zeek-client` are included so
the on-disk layout matches a conventional Zeek runtime install.

Keeping those two is deliberate for a second reason: both declare
`Depends: zeek-core (= 8.0.5-0)`, an exact-version dependency, so apt holds
`zeek-core` back rather than letting a routine `apt upgrade` drift it off the
supported 8.0.x line. Dropping them would require an explicit apt pin instead.

## Running the installer from a repository checkout

`install-enigma-sensor.sh` resolves the bundle at `$SCRIPT_DIR/zeek`. Running it
directly from a checkout makes `SCRIPT_DIR` the `installer/` directory, while the
bundle lives at `installer/linux/zeek/`, so that invocation takes the OpenSUSE
fallback path rather than the bundled one. The bundled path is exercised through
the release zip layout, which `scripts/test-linux-install.sh` reproduces.

## Verifying

```sh
cd installer/linux/zeek
sha256sum -c SHA256SUMS
```

## Refresh procedure

1. Re-download the three packages from the URLs above at the new version.
2. Run `sha256sum *.deb > SHA256SUMS`.
3. Run `bash scripts/test-linux-install.sh` from the repository root.
4. Update the version references in this file, in the `Dockerfile` comment, and
   in the `installer/install-enigma-sensor.sh` comment.
