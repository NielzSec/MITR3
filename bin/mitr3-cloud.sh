#!/usr/bin/env bash
# Usage: mitr3-cloud.sh --check | --install | TOOL [arguments]
set -euo pipefail
base=$(dirname "$(readlink -f "$0")")
case "${1:---check}" in
  --check) exec "$base/mitr3-arsenal.sh" check phase3 ;;
  --install) exec "$base/mitr3-arsenal.sh" install phase3 ;;
  aws|gcloud|az|prowler|scoutsuite|cloudfox|pacu|trufflehog) exec "$base/mitr3-arsenal.sh" run "$@" ;;
  *) echo 'Usage: mitr3-cloud.sh --check | --install | {aws|gcloud|az|prowler|scoutsuite|cloudfox|pacu|trufflehog} [arguments]' >&2; exit 2 ;;
esac
