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
| `zeek-runtime-win64.zip` | This directory, committed. The sensor extracts it to `zeek-windows\` on every start |
| `config.example.json` | Repository root. Used only to create the config, not installed |

Npcap is not packaged. The installer downloads it at install time if the user asks for it.

## What the installer does

It needs administrator rights and installs to `C:\Program Files\EnigmaSensor`. After the directory
page it shows up to two pages of its own, Npcap first (both are inserted after the directory page,
and Inno Setup places the later-created page first).

1. **Npcap page** (skipped when `{sys}\Npcap\wpcap.dll` exists): an "Install Npcap (Recommended)"
   checkbox, unchecked by default. Npcap captures everything the network card receives; without it
   the sensor uses `pktmon`, which only sees this computer's own traffic.
2. **Configuration page** (only when `C:\ProgramData\EnigmaSensor\config.json` does not exist): asks
   for the API key and Network ID. Both are required, and the Network ID is checked against the same
   rules as the sensor (1 to 64 characters; letters, numbers, spaces, hyphens and underscores;
   starting and ending with a letter or number).
3. **Before installing**: if Npcap was chosen, downloads `https://npcap.com/dist/npcap-1.79.exe`.
   If the download fails it shows a message and carries on without Npcap.
4. **Installing**: stops an existing `EnigmaSensor` service, copies the files, and on a fresh install
   writes `C:\ProgramData\EnigmaSensor\config.json` from `config.example.json` with the API key and
   Network ID filled in. An existing config is never touched.
5. **After installing**:
   - launches the Npcap installer if it was downloaded; the user clicks through it and setup waits;
   - registers the service with NSSM: runs as LocalSystem, starts automatically, working directory
     `C:\Program Files\EnigmaSensor`, console output to
     `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log`;
   - starts the service.

Running a newer installer over an existing install upgrades it in place and keeps the config.

Uninstalling stops and removes the service. The config in `C:\ProgramData\EnigmaSensor` stays.

### Resulting files

| Path | Contents |
| --- | --- |
| `C:\ProgramData\EnigmaSensor\config.json` | Config, including the API key |
| `C:\ProgramData\EnigmaSensor\logs\enigma-sensor.log` | Service console output. NSSM is not configured to rotate it |
| `C:\Program Files\EnigmaSensor\logs\enigma-sensor.log` | The sensor's own log, rotated per the `logging` settings |
| `C:\Program Files\EnigmaSensor\captures\` | Captures and Zeek output |
| `C:\Program Files\EnigmaSensor\zeek-windows\` | Extracted Zeek runtime |

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
installer downloads it from npcap.com rather than redistributing it.

## Version

`AppVersion` in the `.iss` is set by `scripts/bump-version.sh`; see
[DEVELOPMENT.md](../../DEVELOPMENT.md).
