param([string]$Python = "python", [switch]$SkipWeb)
& (Join-Path $PSScriptRoot "../tools/build.ps1") -Python $Python -SkipWeb:$SkipWeb
exit $LASTEXITCODE
