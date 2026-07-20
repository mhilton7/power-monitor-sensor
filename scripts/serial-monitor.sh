#!/usr/bin/env sh
set -eu
exec sh "$(dirname -- "$0")/../tools/serial_monitor.sh" "$@"
