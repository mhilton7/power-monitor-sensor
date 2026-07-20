#!/usr/bin/env sh
set -eu
if [ "$#" -ne 1 ]; then echo "usage: tools/serial_monitor.sh PORT" >&2; exit 2; fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
cd "$ROOT"
PLATFORMIO_CORE_DIR="$ROOT/.pio-core" "$PYTHON" -m platformio device monitor --port "$1" --baud 115200
