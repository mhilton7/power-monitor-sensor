param([Parameter(Mandatory = $true)][string]$Port, [string]$Python = "python")
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$env:PLATFORMIO_CORE_DIR = Join-Path $Root ".pio-core"
Push-Location $Root
try { & $Python -m platformio device monitor --port $Port --baud 115200 } finally { Pop-Location }
