#!/usr/bin/env bash
# Clone the external reverse-engineering toolkit used by the lab.
#
# Shallow clones, recorded commits, idempotent. Everything lands in vendor/
# and is never executed by this script.
#
#   bash scripts/bootstrap_repos.sh            # light set
#   bash scripts/bootstrap_repos.sh --all      # includes heavy projects
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$HERE/vendor"
LOCK="$VENDOR/REPOS.lock"
mkdir -p "$VENDOR"

WITH_ALL=0
[ "${1:-}" = "--all" ] && WITH_ALL=1

clone() {
    local url="$1" name="$2"
    local dest="$VENDOR/$name"
    if [ -d "$dest/.git" ]; then
        echo "  keep   $name ($(git -C "$dest" rev-parse --short HEAD))"
        return
    fi
    echo "  clone  $name <- $url"
    if ! git clone --depth 1 --single-branch "$url" "$dest" >/dev/null 2>&1; then
        echo "  FAIL   $name (repository unavailable or renamed)"
        rm -rf "$dest"
        return 0
    fi
}

LIGHT=(
    "https://github.com/onekey-sec/unblob|unblob"
    "https://github.com/hugsy/gef|gef"
    "https://github.com/al3xtjames/ghidra-firmware-utils|ghidra-firmware-utils"
    "https://github.com/ReFirmLabs/binwalk|binwalk"
    "https://github.com/rampageX/firmware-mod-kit|firmware-mod-kit"
)

HEAVY=(
    "https://github.com/e-m-b-a/emba|emba"
    "https://github.com/intel/cve-bin-tool|cve-bin-tool"
    "https://github.com/attify/firmware-analysis-toolkit|firmware-analysis-toolkit"
    "https://github.com/NationalSecurityAgency/ghidra|ghidra-source"
)

echo "== cloning into $VENDOR"
for spec in "${LIGHT[@]}"; do
    clone "${spec%%|*}" "${spec##*|}"
done

if [ "$WITH_ALL" -eq 1 ]; then
    for spec in "${HEAVY[@]}"; do
        clone "${spec%%|*}" "${spec##*|}"
    done
fi

echo "== inventory"
du -sh "$VENDOR"/* 2>/dev/null | sort -h | tail -8

# Rebuild the lock from what is actually on disk, so it can never drift.
{
    for dir in "$VENDOR"/*/; do
        [ -d "$dir/.git" ] || continue
        name="$(basename "$dir")"
        url="$(git -C "$dir" remote get-url origin 2>/dev/null || echo unknown)"
        sha="$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '%s\t%s\t%s\n' "$name" "$url" "$sha"
    done
} > "$LOCK.tmp"
mv "$LOCK.tmp" "$LOCK"
echo "lock: $LOCK"
