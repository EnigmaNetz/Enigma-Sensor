# Windows Installer

The Windows installer is built with [Inno Setup](https://jrsoftware.org/isinfo.php) from
`enigma-sensor-installer.iss`. It installs the sensor as the `EnigmaSensor` Windows service, managed
by NSSM (the Non-Sucking Service Manager).

## Build

Release and pull request builds happen in continuous integration (`.github/workflows/build-artifacts-reusable.yml`), which
produces `enigma-sensor-windows-<version>.exe`. To build locally on Windows:

1. Build the sensor from the repository root. The installer expects this exact path:

   ```powershell
   go build -o bin/enigma-sensor-windows-amd64.exe ./cmd/enigma-sensor
   ```

   (`GOOS=windows GOARCH=amd64 go build ...` from Linux produces the same binary.)

2. Install Inno Setup 6 (`choco install innosetup`) and compile:

   ```powershell
   & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer/windows/enigma-sensor-installer.iss
   ```

The output is `installer/windows/Output/enigma-sensor-installer.exe`.

The installer packages:

| File | Source |
| --- | --- |
| `enigma-sensor-windows-amd64.exe` | `bin/`, built in step 1 |
| `nssm.exe` | `bin/nssm.exe`, committed |
| `zeek-runtime-win64.zip` | This directory, committed: the release asset built by Enigma-Zeek (see below). The sensor extracts it to `zeek-windows\` on every start |
| `config.example.json` | Repository root. Used only to create the config, not installed |
| `LICENSE.txt` | `LICENSE` at the repository root. Also shown as the license page |
| `THIRD_PARTY_NOTICES.txt` | `THIRD_PARTY_NOTICES` at the repository root |

Npcap is not packaged. The installer downloads it at install time if the user asks for it.

## What the installer does

It needs administrator rights and installs to `C:\Program Files (x86)\EnigmaSensor`. It opens with a
license page: the user must accept `LICENSE` (PolyForm Internal Use 1.0.0) to continue; a `/SILENT`
or `/VERYSILENT` install accepts it without showing the page. After the directory page it shows up to two pages of its own, Npcap first (both are inserted after the directory page,
and Inno Setup places the later-created page first).

1. **Npcap page** (skipped when `{sys}\Npcap\wpcap.dll` exists): an "Install Npcap (Recommended)"
   checkbox, unchecked by default. Npcap captures everything the network card receives; without it
   the sensor uses `pktmon`, which only sees this computer's own traffic. The page states that
   Npcap's free license covers up to five computers.
2. **Configuration page** (only when `C:\ProgramData\EnigmaSensor\config.json` does not exist): asks
   for the API key and Network ID. Both are required, and the Network ID is checked against the same
   rules as the sensor (1 to 64 characters; letters, numbers, spaces, hyphens and underscores;
   starting and ending with a letter or number). The fields start out filled from the
   `ENIGMA_API_KEY` and `ENIGMA_NETWORK_ID` environment variables, the same ones the Linux
   installer reads, so an unattended install takes its values from them. Run unattended installs with
   both `/VERYSILENT` and `/SUPPRESSMSGBOXES`: then a missing or invalid value makes setup exit with
   an error, where `/VERYSILENT` alone would show the error dialog and wait. Set the variables only in
   the elevated shell that runs the installer: a UAC prompt can start setup without them, and
   `setx /M` would leave the key readable by every user on the machine.
3. **Before installing**: on a fresh install, writes `C:\ProgramData\EnigmaSensor\config.json`
   from `config.example.json` with the API key and Network ID filled in (JSON-escaped). The config
   holds the API key, so before the key is written its owner becomes Administrators and its
   permissions are replaced with SYSTEM and Administrators only, with no inheritance from
   `C:\ProgramData`. An existing config keeps its content, but its owner and permissions are reset the
   same way, which locks down configs earlier installers left readable by every local user. If the
   permissions cannot be set, setup stops with an error and installs nothing; on a fresh install it
   also removes the incomplete config, so the next run asks for the key again. Then, if Npcap was
   chosen, downloads `https://npcap.com/dist/npcap-1.79.exe`; if the download fails it shows a
   message and carries on without Npcap.
4. **Installing**: stops an existing `EnigmaSensor` service and copies the files.
5. **After installing**:
   - launches the Npcap installer if it was downloaded; the user clicks through it and setup waits;
   - registers the service with NSSM: runs as LocalSystem, starts automatically, working directory
     `C:\Program Files (x86)\EnigmaSensor`, console output to
     `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log`;
   - starts the service.

Running a newer installer over an existing install upgrades it in place and keeps the config.

Uninstalling stops and removes the service. The config in `C:\ProgramData\EnigmaSensor` stays.

### Resulting files

| Path | Contents |
| --- | --- |
| `C:\ProgramData\EnigmaSensor\config.json` | Config, including the API key |
| `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log` | Service console output. NSSM rotates it once it passes 50 MB, checked at service start and while running; the sensor deletes rotated files older than `logging.log_retention_days` |
| `C:\Program Files (x86)\EnigmaSensor\logs\enigma-sensor.log` | The sensor's own log, rotated per the `logging` settings |
| `C:\Program Files (x86)\EnigmaSensor\captures\` | Captures and Zeek output |
| `C:\Program Files (x86)\EnigmaSensor\zeek-windows\` | Extracted Zeek runtime |

## Zeek runtime

`zeek-runtime-win64.zip` is built by the [Enigma-Zeek](https://github.com/EnigmaNetz/Enigma-Zeek)
repository from a pinned Zeek release and published as a GitHub release named
`zeek-runtime-win64-<tag>-r<revision>`. It is Zeek 8.0.10, the same version as the Linux packages in
`installer/linux/zeek/`, and its `BUILD-INFO.txt` records the versions and commits it was built from.

To update it, publish a new runtime from Enigma-Zeek (its README), then replace the file here with
the release asset and check it against the release's SHA-256:

```sh
gh release download zeek-runtime-win64-<tag>-r<revision> --repo EnigmaNetz/Enigma-Zeek --dir /tmp/zeek-win
(cd /tmp/zeek-win && sha256sum -c zeek-runtime-win64.zip.sha256)
cp /tmp/zeek-win/zeek-runtime-win64.zip /tmp/zeek-win/zeek-runtime-win64.zip.sha256 installer/windows/
```

`zeek-runtime-win64.zip.sha256` is committed next to the zip, so the repository records which
release the zip came from; check it with `sha256sum -c` in this directory.

The sensor extracts the zip over `zeek-windows\` on start without clearing it first, so files a
previous runtime shipped and a new one dropped stay on upgraded hosts. Nothing loads them.

## Npcap

The sensor chooses its capturer once, at service start: Npcap if
`%WINDIR%\System32\Npcap\wpcap.dll` exists or Npcap lists devices, otherwise `pktmon`. The log says
which:

- `[capture] Using Npcap capturer (promiscuous mode enabled)`
- `[capture] Npcap not available, using pktmon capturer (limited to host traffic)`

If Npcap is installed after the sensor, restart the service:

```powershell
Restart-Service EnigmaSensor
```

Npcap is licensed separately by its authors; see the [Npcap license](https://npcap.com/oem/). The
installer downloads it from npcap.com rather than redistributing it. The free license covers up to
five installs, and the installer's Npcap page says so.

## Version

`AppVersion` in the `.iss` is set by `scripts/bump-version.sh`; see
[DEVELOPMENT.md](../../DEVELOPMENT.md).
