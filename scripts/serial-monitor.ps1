param([Parameter(Mandatory = $true)][string]$Port, [string]$Python = "python")
& (Join-Path $PSScriptRoot "../tools/serial_monitor.ps1") -Port $Port -Python $Python
exit $LASTEXITCODE
