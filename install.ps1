# scholar-access one-click installer (Windows).
# This file is intentionally ASCII-only: Windows PowerShell 5.1 mis-decodes
# UTF-8 without BOM and would break on Chinese text.
#
# Usage:  right-click -> Run with PowerShell, or double-click install.cmd
# Options: -Port 5380 -Upstream https://doh.scholar.work/dns-query -SkipCA -NoStart

param(
    [int]$Port = 0,
    [string]$Upstream = "",
    [switch]$SkipCA,
    [switch]$NoStart,
    [switch]$NoAutostart
)

$ErrorActionPreference = "Stop"
try { chcp 65001 > $null } catch {}
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path (Join-Path $root "scholar_access\cli.py"))) {
    Write-Host "[X] Cannot find scholar_access\cli.py next to this script." -ForegroundColor Red
    Write-Host "    Run install.ps1 from inside the cloned repository." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Set-Location $root

function Find-Python {
    $candidates = @(
        @{ Exe = "py"; Args = @("-3") },
        @{ Exe = "python"; Args = @() },
        @{ Exe = "python3"; Args = @() }
    )
    foreach ($cand in $candidates) {
        $cmd = Get-Command $cand.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $probe = @($cand.Args) + @("-c", "import sys;print(sys.executable);print('%d.%d' % sys.version_info[:2])")
            $out = & $cmd.Source @probe 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $out) { continue }
            $exe = $out[0]
            $ver = $out[1]
            if ($ver -match "^(\d+)\.(\d+)$") {
                $major = [int]$Matches[1]; $minor = [int]$Matches[2]
                if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 9)) {
                    return @{ Exe = $exe; Version = $ver }
                }
            }
        } catch { }
    }
    return $null
}

Write-Host ""
Write-Host "  scholar-access installer" -ForegroundColor Cyan
Write-Host "  ------------------------" -ForegroundColor Cyan
Write-Host ""

$python = Find-Python
if (-not $python) {
    Write-Host "[X] Python 3.9+ not found." -ForegroundColor Red
    Write-Host "    Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH')," -ForegroundColor Yellow
    Write-Host "    then run this script again." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[*] Python $($python.Version): $($python.Exe)"

$cliArgs = @("-m", "scholar_access", "install")
if ($Port -gt 0) { $cliArgs += @("--port", "$Port") }
if ($Upstream) { $cliArgs += @("--upstream", $Upstream) }
if ($SkipCA) { $cliArgs += "--skip-ca" }
if ($NoStart) { $cliArgs += "--no-start" }
if ($NoAutostart) { $cliArgs += "--no-autostart" }

$env:PYTHONPATH = $root + ";" + $env:PYTHONPATH
& $python.Exe @cliArgs
$code = $LASTEXITCODE

Write-Host ""
if ($code -eq 0) {
    Write-Host "[OK] Installed." -ForegroundColor Green
} else {
    Write-Host "[X] Installer exited with code $code." -ForegroundColor Red
    Write-Host "    Log file: $env:LOCALAPPDATA\scholar-access\router.log" -ForegroundColor Yellow
}
Write-Host ""
Read-Host "Press Enter to close"
