#!/usr/bin/env bash
# Usage: mitr3-ad.sh --check | --install | TOOL [arguments]
set -euo pipefail
base=$(dirname "$(readlink -f "$0")")
case "${1:---check}" in
  --check) exec "$base/mitr3-arsenal.sh" check phase2 ;;
  --install) exec "$base/mitr3-arsenal.sh" install phase2 ;;
  impacket|bloodhound-python|kerbrute|responder) exec "$base/mitr3-arsenal.sh" run "$@" ;;
  *) echo 'Usage: mitr3-ad.sh --check | --install | {impacket|bloodhound-python|kerbrute|responder} [arguments]' >&2; exit 2 ;;
esac
