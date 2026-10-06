# Install test for the Windows installer. Runs the built installer silently on a
# Windows host (CI runner) and checks the config it writes:
#
#   1. Fresh install: config.json is valid JSON holding exactly the API key and
#      Network ID supplied (the key contains a quote and backslashes), and only
#      SYSTEM and Administrators can access it.
#   2. Upgrade: a config an earlier installer left readable by every user is
#      locked down, and its content is left unchanged.
#
# Needs an administrator shell and Go (to check the config with Go's own JSON
# decoder, which is stricter than PowerShell's). It installs the sensor service
# and leaves an api.enigmaai.net entry in the hosts file, so run it on a
# disposable machine only.
#
# Usage: pwsh scripts/test-windows-install.ps1 [-Installer <path to installer .exe>]
param(
    [string] $Installer = 'installer/windows/Output/enigma-sensor-installer.exe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ConfigPath = 'C:\ProgramData\EnigmaSensor\config.json'
$AllowedSids = @('S-1-5-18', 'S-1-5-32-544') # SYSTEM, Administrators
$Failures = 0

function Pass([string] $Name) { Write-Host "PASS: $Name" }
function Fail([string] $Name, [string] $Detail) {
    Write-Host "FAIL: $Name"
    if ($Detail) { Write-Host "      $Detail" }
    $script:Failures++
}

function Invoke-Installer([string] $Name) {
    $log = Join-Path ([IO.Path]::GetTempPath()) "enigma-install-$Name.log"
    $proc = Start-Process -FilePath (Resolve-Path $Installer) -Wait -PassThru `
        -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$log`""
    if ($proc.ExitCode -eq 0) {
        Pass "$($Name): installer exit code is 0"
    } else {
        Fail "$($Name): installer exit code is 0" "got $($proc.ExitCode); log follows"
        Get-Content $log | Write-Host
    }
}

function Get-ConfigSids {
    (Get-Acl $ConfigPath).Access |
        ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } |
        Sort-Object -Unique
}

function Assert-ConfigLockedDown([string] $Name) {
    $acl = Get-Acl $ConfigPath
    $owner = ([Security.Principal.NTAccount] $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($owner -eq 'S-1-5-32-544') {
        Pass "$($Name): config.json is owned by Administrators"
    } else {
        Fail "$($Name): config.json is owned by Administrators" "owner is $($acl.Owner)"
    }
    if ($acl.AreAccessRulesProtected) {
        Pass "$($Name): config.json does not inherit permissions"
    } else {
        Fail "$($Name): config.json does not inherit permissions" 'inheritance is still enabled'
    }
    $sids = @(Get-ConfigSids)
    $extra = @($sids | Where-Object { $AllowedSids -notcontains $_ })
    if ($extra.Count -eq 0 -and $sids.Count -gt 0) {
        Pass "$($Name): only SYSTEM and Administrators can access config.json"
    } else {
        Fail "$($Name): only SYSTEM and Administrators can access config.json" "access granted to: $($sids -join ', ')"
    }
}

function Stop-Sensor {
    $svc = Get-Service EnigmaSensor -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service EnigmaSensor -Force }
}

if (-not (Test-Path $Installer)) { throw "No installer at $Installer; build it with ISCC first" }

# The installer starts the service, and config.example.json points at the
# production API. Send that name nowhere for the length of the test.
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "`r`n127.0.0.1 api.enigmaai.net"

# --- 1. Fresh install ---------------------------------------------------------
Write-Host '=== Fresh install ==='
Stop-Sensor
Remove-Item -Force $ConfigPath -ErrorAction SilentlyContinue
# A quote, backslashes and a tab: each must be escaped for the sensor to load it.
$apiKey = "ci-key-`"quoted`"-back\slash\`ttab"

$networkId = 'ci-test-network'
$env:ENIGMA_API_KEY = $apiKey
$env:ENIGMA_NETWORK_ID = $networkId
Invoke-Installer 'fresh'
Remove-Item Env:ENIGMA_API_KEY, Env:ENIGMA_NETWORK_ID

# Decode with Go's encoding/json, as the sensor does: PowerShell's parser accepts
# raw control characters that Go rejects. The file is readable only by SYSTEM and
# Administrators, which this elevated shell is.
$decoder = Join-Path ([IO.Path]::GetTempPath()) 'enigma-config-decode'
New-Item -ItemType Directory -Force -Path $decoder | Out-Null
Set-Content -Path (Join-Path $decoder 'main.go') -Value @'
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var c struct {
		NetworkID string `json:"network_id"`
		EnigmaAPI struct {
			APIKey string `json:"api_key"`
		} `json:"enigma_api"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, _ := json.Marshal(map[string]string{"api_key": c.EnigmaAPI.APIKey, "network_id": c.NetworkID})
	fmt.Print(string(out))
}
'@
$decoded = & go run (Join-Path $decoder 'main.go') $ConfigPath 2>&1
if ($LASTEXITCODE -eq 0) {
    Pass 'fresh: config.json decodes with Go encoding/json'
    $config = ($decoded -join '') | ConvertFrom-Json
    if ($config.api_key -ceq $apiKey) {
        Pass 'fresh: api_key round-trips with its quote, backslashes and tab'
    } else {
        Fail 'fresh: api_key round-trips with its quote, backslashes and tab' 'the decoded key differs from the one supplied'
    }
    if ($config.network_id -ceq $networkId) {
        Pass 'fresh: network_id is the one supplied'
    } else {
        Fail 'fresh: network_id is the one supplied' "got '$($config.network_id)'"
    }
} else {
    Fail 'fresh: config.json decodes with Go encoding/json' ($decoded -join ' ')
}
Assert-ConfigLockedDown 'fresh'

# --- 2. Upgrade over a config an earlier installer left readable ---------------
Write-Host '=== Upgrade over an inherited-permission config ==='
Stop-Sensor
# As an earlier installer might have left it: inherited permissions (readable by
# Users) and owned by Users, so the installer has to fix both.
& icacls.exe $ConfigPath /reset | Out-Null
& icacls.exe $ConfigPath /setowner '*S-1-5-32-545' | Out-Null
$ownerBefore = ([Security.Principal.NTAccount] (Get-Acl $ConfigPath).Owner).Translate([Security.Principal.SecurityIdentifier]).Value
if ((Get-ConfigSids) -contains 'S-1-5-32-545' -and $ownerBefore -eq 'S-1-5-32-545') {
    Pass 'upgrade: setup leaves config.json readable by and owned by Users'
} else {
    Fail 'upgrade: setup leaves config.json readable by and owned by Users' "owner $ownerBefore, access: $((Get-ConfigSids) -join ', ')"
}
$before = Get-Content -Raw $ConfigPath
Invoke-Installer 'upgrade'
if ((Get-Content -Raw $ConfigPath) -ceq $before) {
    Pass 'upgrade: config.json content is unchanged'
} else {
    Fail 'upgrade: config.json content is unchanged' 'the installer rewrote an existing config'
}
Assert-ConfigLockedDown 'upgrade'

Stop-Sensor

Write-Host '=== Summary ==='
if ($Failures -ne 0) {
    Write-Host "$Failures check(s) failed."
    exit 1
}
Write-Host 'All checks passed.'
