# Bundled Zeek runtime packages (Linux)

These Debian packages ship inside the Linux release zip under `zeek/` so
`install-enigma-sensor.sh` can install Zeek without reaching any third-party
package repository.

## Contents

One set per Ubuntu build channel, each with its own `SHA256SUMS`:

| Directory | Files | Version |
|-----------|-------|---------|
| `ubuntu-22.04/` | `zeek-lts-core_8.0.10-0_amd64.deb`, `zeekctl-lts_8.0.10-0_amd64.deb`, `zeek-lts-client_8.0.10-0_all.deb` | 8.0.10-0 |
| `ubuntu-24.04/` | the same three files, built for 24.04 | 8.0.10-0 |

The installer takes `ubuntu-24.04/` on Ubuntu 24.04 and later and `ubuntu-22.04/`
everywhere else (Ubuntu 22.04 and Debian 12 and 13). The 24.04 build needs `libc6 >= 2.38`,
which 22.04 does not have. The Docker image uses `ubuntu-24.04/`. Ubuntu 20.04 is
not supported: it is EOL and ships glibc 2.31 and libssl1.1, below Zeek 8.0's
`libc6 >= 2.34` and `libssl3` requirements.

## Provenance

Downloaded from the OpenSUSE Build Service `security:zeek` project, upstream
version 8.0.10-0, from the `xUbuntu_22.04` and `xUbuntu_24.04` channels:

- `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_<release>/amd64/zeek-lts-core_8.0.10-0_amd64.deb`
- `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_<release>/amd64/zeekctl-lts_8.0.10-0_amd64.deb`
- `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_<release>/all/zeek-lts-client_8.0.10-0_all.deb`

The project's plain `zeek-core`, `zeekctl` and `zeek-client` packages follow the
newest Zeek release (9.0 at the time of writing); the 8.0 line is published as
the `zeek-lts` packages. OBS keeps only the latest build of each, so older
versions disappear from these URLs once superseded.

The `zeek-lts` packages conflict with `zeek-core`, which releases up to Zeek
8.0.5 installed and which the sensor package depended on. The installer installs
the sensor package in the same apt transaction as Zeek so apt swaps both instead
of removing the sensor, and the sensor package depends on
`zeek-lts-core | zeek-core` so a host whose Zeek upgrade fails keeps its sensor.
The installer then prints a prominent warning that Zeek is below 8.0.10 and
missing security fixes, and exits 3 so whatever ran it sees the failure.

Zeek is BSD-licensed, so redistributing these packages inside Enigma's own
release artifact is cleared.

## Why this minimal set

The `zeek-lts` metapackage pulls `zeek-lts-zkg`, `zeek-lts-spicy-dev` and `zeek-lts-btest-data`,
roughly 58 MB of development and test payload the sensor never uses. The sensor
only invokes `/opt/zeek/bin/zeek`; `zeekctl` and `zeek-client` are included so
the on-disk layout matches a conventional Zeek runtime install.

Keeping those two is deliberate for a second reason: both declare
`Depends: zeek-lts-core (= 8.0.10-0)`, an exact-version dependency, so apt holds
`zeek-lts-core` back rather than letting a routine `apt upgrade` drift it off the
supported 8.0.x line. Dropping them would require an explicit apt pin instead.

## Running the installer from a repository checkout

`install-enigma-sensor.sh` resolves the bundle at `$SCRIPT_DIR/zeek/ubuntu-<release>`. Running it
directly from a checkout makes `SCRIPT_DIR` the `installer/` directory, while the
bundle lives at `installer/linux/zeek/`, so that invocation takes the OpenSUSE
fallback path rather than the bundled one. The bundled path is exercised through
the release zip layout, which `scripts/test-linux-install.sh` reproduces.

## Verifying

```sh
(cd installer/linux/zeek/ubuntu-22.04 && sha256sum -c SHA256SUMS)
(cd installer/linux/zeek/ubuntu-24.04 && sha256sum -c SHA256SUMS)
```

## Refresh procedure

1. For each of `ubuntu-22.04` and `ubuntu-24.04`, download the three packages from
   the URLs above at the new version into that directory and delete the old ones.
2. In each directory, run `sha256sum *.deb > SHA256SUMS`.
3. Before choosing the version, compare the `#fields` and `#types` headers of the
   logs the sensor uploads (conn, dns, dhcp, ja3_ja4, ja4s) against the current
   version over the same captures. The Subscriber drops columns it has no table
   column for, so a new column is lost until it is opted in there.
4. Run `bash scripts/test-linux-install.sh` from the repository root.
5. Update the version references in this file, in the `Dockerfile` comment, in
   the `installer/install-enigma-sensor.sh` comment and in `README.md`, then
   regenerate `THIRD_PARTY_NOTICES` with `scripts/third-party-notices/generate.sh`.
