#!/usr/bin/env bash
# Canonical MITR3 Gopherus base. No backup/alternate checkout is selected.
set -euo pipefail
cd "$HOME/Tools/gopherus"
exec python3 gopherus.py "$@"
