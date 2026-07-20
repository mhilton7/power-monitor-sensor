#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
cd "$ROOT"
(cd web && npm ci && npm test -- --run && npm run build)
"$PYTHON" tools/build_web.py --skip-build
"$PYTHON" -m unittest discover -s test -p 'test_*.py' -v
PLATFORMIO_CORE_DIR="$ROOT/.pio-core" PLATFORMIO_SETTING_ENABLE_TELEMETRY=No "$PYTHON" -m platformio run -e native-tests
"$ROOT/.pio/build/native-tests/program"
PLATFORMIO_CORE_DIR="$ROOT/.pio-core" PLATFORMIO_SETTING_ENABLE_TELEMETRY=No "$PYTHON" -m platformio run -e esp32-s3-release -e esp32-s3-debug -e esp32-s3-simulated-meter
"$PYTHON" tools/check_repo.py
