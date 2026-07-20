param([Parameter(Mandatory = $true)][string]$Port, [string]$Environment = "esp32-s3-release", [string]$Python = "python")
& (Join-Path $PSScriptRoot "../tools/flash.ps1") -Port $Port -Environment $Environment -Python $Python
exit $LASTEXITCODE
