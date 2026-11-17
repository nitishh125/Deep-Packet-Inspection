<#
.SYNOPSIS
    DPI Launcher for Windows PowerShell
.EXAMPLE
    .\dpi.ps1 test_dpi.pcap output.pcap
    .\dpi.ps1 test_dpi.pcap output.pcap --block-app YouTube
    .\dpi.ps1 test_dpi.pcap output.pcap --rules rules.example.txt
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnginePath = Join-Path $ScriptDir "dpi_engine.py"

# Try Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if ($pythonCmd) {
    & $pythonCmd.Source $EnginePath @args
    exit $LASTEXITCODE
} else {
    Write-Host "[ERROR] Python 3 is not found in your PATH." -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/ or run 'winget install Python.Python.3.12'" -ForegroundColor Yellow
    exit 1
}
