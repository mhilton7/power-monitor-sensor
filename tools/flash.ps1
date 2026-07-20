param([Parameter(Mandatory = $true)][string]$Port, [string]$Environment = "esp32-s3-release", [string]$Python = "python")
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$env:PLATFORMIO_CORE_DIR = Join-Path $Root ".pio-core"
$env:PLATFORMIO_SETTING_ENABLE_TELEMETRY = "No"
& $Python -m platformio run -d $Root -e $Environment -t upload --upload-port $Port
