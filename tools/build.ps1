param([string]$Python = "python", [switch]$SkipWeb)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $Root
try {
  if (-not $SkipWeb) {
    Push-Location (Join-Path $Root "web")
    try {
      npm ci
      if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
      npm test -- --run
      if ($LASTEXITCODE -ne 0) { throw "frontend tests failed" }
      npm run build
      if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }
    } finally { Pop-Location }
    & $Python tools/build_web.py --skip-build
    if ($LASTEXITCODE -ne 0) { throw "UI embedding failed" }
  }
  & $Python -m unittest discover -s test -p "test_*.py" -v
  if ($LASTEXITCODE -ne 0) { throw "Python tests failed" }
  $env:PLATFORMIO_CORE_DIR = Join-Path $Root ".pio-core"
  $env:PLATFORMIO_SETTING_ENABLE_TELEMETRY = "No"
  & $Python -m platformio run -e native-tests
  if ($LASTEXITCODE -ne 0) { throw "native test build failed" }
  $PreviousPath = $env:Path
  try {
    $NativeRuntime = Join-Path $env:PLATFORMIO_CORE_DIR "packages/toolchain-gccmingw32/bin"
    $env:Path = $NativeRuntime + ";" + $env:Path
    & (Join-Path $Root ".pio/build/native-tests/program.exe")
    if ($LASTEXITCODE -ne 0) { throw "native test executable failed" }
  } finally {
    $env:Path = $PreviousPath
  }
  & $Python -m platformio run -e esp32-s3-release -e esp32-s3-debug -e esp32-s3-simulated-meter
  if ($LASTEXITCODE -ne 0) { throw "firmware build matrix failed" }
  & $Python tools/check_repo.py
  if ($LASTEXITCODE -ne 0) { throw "repository checks failed" }
} finally { Pop-Location }
