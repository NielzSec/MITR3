#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(dirname "$(readlink -f "$0")")/mitr3-arsenal.py" "$@"
