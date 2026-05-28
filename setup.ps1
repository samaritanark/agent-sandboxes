#Requires -Version 5.1
<#
.SYNOPSIS
  Agent Sandbox setup for Windows hosts.

.DESCRIPTION
  Provisions a dedicated WSL2 distro named 'sandbox-vm' (cloned from a
  Microsoft-Store Ubuntu-24.04 install) and runs setup.sh inside it.
  The dedicated distro mirrors the role Lima plays on macOS: it isolates
  the sandbox's k3s, Cilium, and gVisor state from any other Linux
  distro the user already has installed.

.PARAMETER PodCidr
  Forwarded to setup.sh as --pod-cidr.

.PARAMETER ServiceCidr
  Forwarded to setup.sh as --service-cidr.

.PARAMETER ApiserverPort
  Forwarded to setup.sh as --apiserver-port. Defaults to 6443.

.PARAMETER Dns
  Forwarded to setup.sh as --dns. Comma- or space-separated upstream DNS
  resolver IP(s) for CoreDNS to forward to. REQUIRED on WSL2: its host DNS
  resolver is a tunnel sentinel unreachable from pod network namespaces, so
  without a pod-reachable resolver agents cannot resolve their APIs. Use a
  public resolver (e.g. 1.1.1.1,8.8.8.8) or an internal DNS IP pods can reach.

.PARAMETER SourceDistro
  Existing WSL distro to clone as the sandbox base. Default: Ubuntu-24.04.
  The source distro is read once (wsl --export) and is otherwise untouched.

.PARAMETER DistroName
  Name to give the new dedicated distro. Default: sandbox-vm.

.PARAMETER InstallDir
  Directory where the sandbox distro's VHDX will live. Default:
  $env:LOCALAPPDATA\sandbox-vm (per-user, no admin required).
#>

[CmdletBinding()]
param(
    [string]$PodCidr,
    [string]$ServiceCidr,
    [int]$ApiserverPort = 6443,
    [string]$Dns,
    [string]$SourceDistro = "Ubuntu-24.04",
    [string]$DistroName = "sandbox-vm",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "sandbox-vm")
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Header($msg) { Write-Host "=== $msg ===" -ForegroundColor Cyan }
function Write-Step($msg)   { Write-Host "==> $msg" -ForegroundColor Green }
function Write-Info($msg)   { Write-Host "    $msg" }
function Fail($msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# Soft nudge toward PowerShell 7. The script supports Windows PowerShell 5.1
# (the default shell on every Windows install) but PS 7+ is more capable and
# reads source files as UTF-8 by default -- safer if non-ASCII characters
# ever creep back into this script. Informational only; the script continues.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host ("INFO: Running on Windows PowerShell {0}. PowerShell 7+ is recommended" -f $PSVersionTable.PSVersion) -ForegroundColor Yellow
    Write-Host "      (install with: winget install Microsoft.PowerShell). Continuing..." -ForegroundColor Yellow
    Write-Host ""
}

function Test-WslAvailable {
    return $null -ne (Get-Command wsl.exe -ErrorAction SilentlyContinue)
}

# wsl.exe emits UTF-16LE with embedded NULs; strip them and any blank lines.
function Get-WslDistros {
    $raw = & wsl.exe --list --quiet 2>$null
    if ($LASTEXITCODE -ne 0) { return @() }
    return $raw |
        ForEach-Object { ($_ -replace "`0", "").Trim() } |
        Where-Object { $_ -ne "" }
}

# C:\Users\you\proj -> /mnt/c/Users/you/proj
function ConvertTo-WslPath($winPath) {
    $resolved = (Resolve-Path -LiteralPath $winPath).Path
    $drive = $resolved.Substring(0, 1).ToLower()
    $tail  = $resolved.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$tail"
}

# Repair-UnixLineEndings — strip CR from any Unix script under $Root that
# was checked out with CRLF endings. Git on Windows defaults
# core.autocrlf=true, which rewrites .sh files to CRLF. Bash inside WSL
# then parses '#!/usr/bin/env bash\r' as an interpreter literally named
# 'bash\r' and fails with "No such file or directory". .gitattributes
# prevents this on fresh clones; this rescues checkouts that pre-date
# that commit. Returns the number of files repaired.
function Repair-UnixLineEndings {
    param([string]$Root)

    # Mirror the .gitattributes LF list — files sourced or executed
    # inside WSL2/Lima/Linux.
    $candidates = New-Object System.Collections.Generic.HashSet[string]
    foreach ($explicit in @('setup.sh', 'uninstall.sh', 'bin\sandbox')) {
        $full = Join-Path $Root $explicit
        if (Test-Path -LiteralPath $full) { [void]$candidates.Add($full) }
    }
    foreach ($pat in @('*.sh','*.bash','*.yaml','*.yml','*.md','*.toml','*.tmpl','Dockerfile*')) {
        Get-ChildItem -Path $Root -Filter $pat -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\\.git\\' } |
            ForEach-Object { [void]$candidates.Add($_.FullName) }
    }

    $fixed = 0
    foreach ($f in $candidates) {
        $content = [System.IO.File]::ReadAllText($f)
        if ($content.Contains("`r`n")) {
            [System.IO.File]::WriteAllText($f, ($content -replace "`r`n", "`n"))
            $fixed++
        }
    }
    return $fixed
}

Write-Header "AI Agent Sandbox Setup (Windows)"
Write-Info "Distro:          $DistroName"
Write-Info "Install dir:     $InstallDir"
Write-Info "Source distro:   $SourceDistro"
Write-Info "Pod CIDR:        $(if ($PodCidr)     { $PodCidr }     else { '(default)' })"
Write-Info "Service CIDR:    $(if ($ServiceCidr) { $ServiceCidr } else { '(default)' })"
Write-Info "API server port: $ApiserverPort"
Write-Info "DNS resolver:    $(if ($Dns) { $Dns } else { '(required on WSL2 — pass -Dns)' })"
Write-Host ""

# 1. WSL2 + a recent-enough build (systemd support requires 0.67.6+).
Write-Step "Checking WSL prerequisites"
if (-not (Test-WslAvailable)) {
    Fail @"
WSL is not installed. Open an elevated PowerShell and run:
    wsl --install
Reboot when prompted, then re-run this script.
"@
}

$wslVerOutput = & wsl.exe --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail @"
'wsl --version' failed. This usually means an older WSL build without
systemd support. Update WSL with:
    wsl --update
then re-run this script.
"@
}
Write-Info ($wslVerOutput | Select-Object -First 1)

# 2. Provision (or re-use) the dedicated sandbox distro.
$distros = Get-WslDistros
if ($distros -contains $DistroName) {
    Write-Step "Distro '$DistroName' already exists -- re-using it"
} else {
    if ($distros -notcontains $SourceDistro) {
        Fail @"
Source distro '$SourceDistro' is not installed. From PowerShell run:
    wsl --install -d $SourceDistro
Complete the first-launch prompts (UNIX username/password), then re-run
this script. The source distro is only read once to seed '$DistroName';
afterwards you can keep or remove it independently.
"@
    }

    Write-Step "Cloning '$SourceDistro' into '$DistroName'"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    $tarball = Join-Path $env:TEMP "$DistroName-rootfs-$(Get-Date -Format yyyyMMddHHmmss).tar"
    try {
        Write-Info "Exporting $SourceDistro to $tarball"
        & wsl.exe --export $SourceDistro $tarball
        if ($LASTEXITCODE -ne 0) { Fail "wsl --export failed (exit $LASTEXITCODE)" }

        Write-Info "Importing as $DistroName into $InstallDir"
        & wsl.exe --import $DistroName $InstallDir $tarball --version 2
        if ($LASTEXITCODE -ne 0) { Fail "wsl --import failed (exit $LASTEXITCODE)" }
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $tarball
    }

    # k3s requires systemd as PID 1. The default-user line ensures the bash
    # CLI sees /root/.sandbox/ consistently regardless of which user the
    # source distro shipped with.
    Write-Step "Enabling systemd in '$DistroName'"
    $wslConfContent = @"
[boot]
systemd=true

[user]
default=root
"@
    $tmpConf = New-TemporaryFile
    try {
        Set-Content -LiteralPath $tmpConf -Value $wslConfContent -Encoding ascii -NoNewline
        $tmpConfWsl = ConvertTo-WslPath $tmpConf.FullName
        & wsl.exe -d $DistroName --user root -- bash -c "cp '$tmpConfWsl' /etc/wsl.conf && chmod 644 /etc/wsl.conf"
        if ($LASTEXITCODE -ne 0) { Fail "Failed to write /etc/wsl.conf inside $DistroName" }
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $tmpConf
    }

    Write-Info "Terminating '$DistroName' so systemd starts on next launch"
    & wsl.exe --terminate $DistroName | Out-Null
}

# 3. systemd must be PID 1 before setup.sh runs (k3s won't otherwise start).
Write-Step "Verifying systemd is running in '$DistroName'"
$pid1 = (& wsl.exe -d $DistroName --user root -- bash -c "ps -p 1 -o comm= 2>/dev/null").Trim()
if ($pid1 -ne "systemd") {
    Fail @"
PID 1 inside '$DistroName' is '$pid1', not systemd. Try:
    wsl --update
    wsl --shutdown
then re-run this script. If it persists, the WSL host build is too old for
systemd support (need 0.67.6+).
"@
}
Write-Info "systemd OK"

# 4. Strip CR from any Unix script in $RepoRoot. No-op on a fresh clone
#    that picked up the repo's .gitattributes (which pins LF for files
#    WSL touches), but rescues older checkouts whose .sh files came down
#    CRLF under the Windows-default git config.autocrlf=true and would
#    fail bash's shebang parser inside WSL.
Write-Step "Checking Unix script line endings"
$fixedCount = Repair-UnixLineEndings -Root $RepoRoot
if ($fixedCount -gt 0) {
    Write-Info "Stripped CR from $fixedCount file(s) — existing checkout had CRLF endings."
    Write-Info "To prevent this on re-clone:  git config --global core.autocrlf false"
} else {
    Write-Info "All Unix scripts already LF-clean."
}

# 5. Hand off to setup.sh inside the distro.
Write-Step "Running setup.sh inside '$DistroName'"
$wslRepoRoot = ConvertTo-WslPath $RepoRoot

$setupArgs = @()
if ($PodCidr)     { $setupArgs += @("--pod-cidr",     $PodCidr) }
if ($ServiceCidr) { $setupArgs += @("--service-cidr", $ServiceCidr) }
if ($PSBoundParameters.ContainsKey("ApiserverPort")) {
    $setupArgs += @("--apiserver-port", "$ApiserverPort")
}
if ($Dns) { $setupArgs += @("--dns", $Dns) }

& wsl.exe -d $DistroName --user root --cd $wslRepoRoot -- ./setup.sh @setupArgs
if ($LASTEXITCODE -ne 0) { Fail "setup.sh inside $DistroName failed (exit $LASTEXITCODE)" }

Write-Host ""
Write-Header "Setup complete"
Write-Host ""
Write-Info "Add the CLI to PATH for this PowerShell session:"
Write-Info "    `$env:Path = `"$RepoRoot\bin;`$env:Path`""
Write-Info ""
Write-Info "Run a Tier 1 session:"
Write-Info "    sandbox run --agent claude --tier 1"
Write-Info ""
Write-Info "For Tier 2/3, clone repos INSIDE the sandbox distro (not on C:\):"
Write-Info "    wsl -d $DistroName -- bash -c 'git clone <url> ~/repos/<name>'"
Write-Info "    sandbox run --agent claude --tier 2 --repo ~/repos/<name>"
