# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
<#
.SYNOPSIS
  Windows proxy for the sandbox CLI.

.DESCRIPTION
  Forwards 'sandbox <args>' from PowerShell into the sandbox-vm WSL2
  distro provisioned by ../setup.ps1. PowerShell auto-resolves a bare
  'sandbox' invocation to this script when bin\ is on $env:Path,
  because $env:PATHEXT includes .PS1.

  Args after this script's name are passed through verbatim to the
  bash CLI inside the distro.
#>

$ErrorActionPreference = "Stop"

$DistroName = if ($env:SANDBOX_DISTRO) { $env:SANDBOX_DISTRO } else { "sandbox-vm" }
$BinDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $BinDir

function ConvertTo-WslPath($winPath) {
    $resolved = (Resolve-Path -LiteralPath $winPath).Path
    $drive = $resolved.Substring(0, 1).ToLower()
    $tail  = $resolved.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$tail"
}

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: wsl.exe not found. Install WSL2 and run setup.ps1 first." -ForegroundColor Red
    exit 1
}

$wslRepoRoot = ConvertTo-WslPath $RepoRoot

# --cd sets the working directory inside WSL so the agent CLI's relative
# lib/ sourcing (lib/platform.sh, lib/lima.sh, etc.) resolves the same way
# it does for native Linux/macOS users.
& wsl.exe -d $DistroName --user root --cd $wslRepoRoot -- ./bin/sandbox @args
exit $LASTEXITCODE
