# Windows Installer Setup

## Overview

The Enigma Sensor Windows installer uses [Inno Setup](https://jrsoftware.org/isinfo.php) and optionally bundles Npcap for enhanced network capture capabilities.

## Prerequisites

1. **Inno Setup** - Download and install from https://jrsoftware.org/isdl.php
2. **Npcap Installer** (optional but recommended) - See instructions below
3. **Compiled sensor binary** - Run build from project root
4. **NSSM binary** - Should be in `bin/nssm.exe`

## Building the Installer

### Quick Build (Without Npcap)

```bash
# From project root
cd installer/windows

# Compile with Inno Setup
iscc enigma-sensor-installer.iss
```

This creates `Output/enigma-sensor-installer.exe` without Npcap bundled. The sensor will fall back to pktmon.

### Full Build (With Npcap)

To include optional Npcap installation:

1. **Download Npcap Installer**:
   ```powershell
   # Download to installer/windows/ directory
   cd installer/windows
   Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.79.exe" -OutFile "npcap-installer.exe"
   ```

2. **Verify File Placement**:
   ```
   installer/windows/
   ├── enigma-sensor-installer.iss
   ├── npcap-installer.exe         ← Downloaded Npcap installer
   ├── zeek-runtime-win64.zip
   └── README.md
   ```

3. **Build Installer**:
   ```bash
   iscc enigma-sensor-installer.iss
   ```

   The output `enigma-sensor-installer.exe` will include Npcap as an optional component.

## Installer Features

### Npcap Integration

The installer provides an **optional Npcap installation step** with:

1. **Automatic Detection** - Checks if Npcap is already installed
2. **User Choice** - Checkbox to install Npcap (checked by default if not installed)
3. **Silent Installation** - Runs Npcap installer with `/S` flag
4. **Graceful Fallback** - Sensor works with or without Npcap

### Installation Flow

```
1. Welcome Screen
2. License Agreement
3. Select Destination Directory
4. Enter API Key (if fresh install)
5. Npcap Option Page          ← NEW
   - "Install Npcap (Recommended)"
   - Explains benefits vs pktmon
   - Auto-checked if Npcap not installed
   - Skipped if already installed
6. Ready to Install
7. Installing Files
8. Installing Npcap (if selected)  ← NEW
9. Configuring Service
10. Finish
```

### Npcap Benefits Explained to User

The installer shows this message on the Npcap page:

> **Install Npcap for improved packet capture**
>
> Npcap enables full network visibility with promiscuous mode, capturing 5-20x more traffic than the built-in pktmon tool. This is recommended for comprehensive network monitoring.
>
> Without Npcap, the sensor will use pktmon, which captures only traffic processed by this computer.
>
> Would you like to install Npcap?

## Testing the Installer

### Test Without Npcap

1. Build installer without `npcap-installer.exe` in directory
2. Run installer
3. Npcap page should not appear
4. Sensor should use pktmon (check logs)

### Test With Npcap Option

1. Place `npcap-installer.exe` in `installer/windows/`
2. Build installer
3. Run installer
4. Npcap page should appear with checkbox
5. Select/deselect and verify behavior

### Test With Npcap Already Installed

1. Install Npcap manually or via Wireshark
2. Run installer
3. Npcap page should show but with note about existing installation
4. Installation should skip Npcap step

## Npcap Licensing Considerations

### Important License Information

- **Npcap License**: Review at https://npcap.com/oem/redist.html
- **Free Use**: Npcap is free for non-commercial use
- **Commercial Use**: May require Npcap OEM license for redistribution
- **Wireshark Exception**: If users already have Wireshark, they have Npcap

### Recommended Approach

1. **Bundle Npcap installer** but make it optional
2. **User consent** - Checkbox gives explicit user choice
3. **License compliance** - User accepts Npcap license during installation
4. **Alternative**: Provide separate download link instead of bundling

### For Commercial Deployments

If distributing to commercial customers:

1. Contact Npcap team about OEM licensing
2. Or provide download instructions instead of bundling
3. Or rely on customers with Wireshark already having Npcap

## File Sizes

- Enigma Sensor binary: ~20MB
- NSSM: ~350KB
- Zeek runtime: ~75MB
- Npcap installer: ~3MB
- **Total installer size**: ~100MB (with all components)

## Troubleshooting

### Npcap Installation Fails

**Symptom**: Installer completes but sensor uses pktmon

**Solutions**:
1. Check if Npcap installer was included in build
2. Verify Npcap installer is not corrupted
3. Try manual Npcap installation
4. Check Windows Event Log for Npcap installation errors

### Silent Installation Not Working

**Symptom**: Npcap shows UI during installation

**Solutions**:
1. Ensure `/S` parameter is used (already in script)
2. Check Npcap installer version supports silent mode
3. Run installer as Administrator

### Sensor Doesn't Use Npcap After Installation

**Symptom**: Logs show "using pktmon capturer" even with Npcap installed

**Solutions**:
1. Verify Npcap DLL exists: `C:\Windows\System32\Npcap\wpcap.dll`
2. Check Npcap service is running: `Get-Service npcap`
3. Restart sensor service: `Restart-Service EnigmaSensor`
4. Check sensor logs for Npcap detection messages

## Build Script Example

For automated builds, use this PowerShell script:

```powershell
# build-installer.ps1
param(
    [switch]$IncludeNpcap = $true
)

# Navigate to installer directory
cd installer/windows

# Download Npcap if requested and not present
if ($IncludeNpcap -and -not (Test-Path "npcap-installer.exe")) {
    Write-Host "Downloading Npcap installer..."
    Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.79.exe" -OutFile "npcap-installer.exe"
}

# Build installer
Write-Host "Building installer with Inno Setup..."
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" enigma-sensor-installer.iss

Write-Host "Installer created: Output/enigma-sensor-installer.exe"
```

## Version Management

Update the version number in `enigma-sensor-installer.iss`:

```ini
[Setup]
AppVersion=x.y.z    ← Update this
```

## References

- **Inno Setup Documentation**: https://jrsoftware.org/ishelp/
- **Npcap Website**: https://npcap.com/
- **Npcap License**: https://github.com/nmap/npcap/blob/master/LICENSE
- **NSSM Documentation**: https://nssm.cc/usage
