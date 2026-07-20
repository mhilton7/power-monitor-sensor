#!/usr/bin/env sh
set -eu
if [ "$#" -lt 1 ]; then echo "usage: tools/flash.sh PORT [ENVIRONMENT]" >&2; exit 2; fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
ENVIRONMENT=${2:-esp32-s3-release}
PLATFORMIO_CORE_DIR="$ROOT/.pio-core" PLATFORMIO_SETTING_ENABLE_TELEMETRY=No "$PYTHON" -m platformio run -d "$ROOT" -e "$ENVIRONMENT" -t upload --upload-port "$1"
