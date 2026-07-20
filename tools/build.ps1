param([string]$Python = "python", [switch]$SkipWeb)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $Root
try {
  if (-not $SkipWeb) {
    Push-Location (Join-Path $Root "web")
    try { npm ci; npm test -- --run; npm run build } finally { Pop-Location }
    & $Python tools/build_web.py --skip-build
  }
  & $Python -m unittest discover -s test -p "test_*.py" -v
  $env:PLATFORMIO_CORE_DIR = Join-Path $Root ".pio-core"
  $env:PLATFORMIO_SETTING_ENABLE_TELEMETRY = "No"
  & $Python -m platformio run -e native-tests
  & (Join-Path $Root ".pio/build/native-tests/program.exe")
  & $Python -m platformio run -e esp32-s3-release -e esp32-s3-debug -e esp32-s3-simulated-meter
  & $Python tools/check_repo.py
} finally { Pop-Location }
