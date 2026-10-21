#!/usr/bin/env bash
# Install the OT firmware lab into ~/MITR3/labs/ot-firmware without root.
#
# Verifies the host toolchain, creates the working dirs, links the CLI into
# ~/.local/bin and runs `fwlab doctor`. It never installs packages and never
# touches system directories.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HOME/.local/bin"
STATE="$HOME/MITR3/labs/ot-firmware/workspaces"
mkdir -p "$BIN" "$STATE/ghidra-projects"

echo "== lab root: $HERE"

fail=0
check() {
    local name="$1" hint="$2"
    if command -v "$name" >/dev/null 2>&1; then
        printf '  ok    %-12s %s\n' "$name" "$(command -v "$name")"
    else
        printf '  miss  %-12s %s\n' "$name" "$hint"
        fail=1
    fi
}

echo "== host tools"
check python3 "pacman -S python"
check gcc "pacman -S gcc"
check r2 "pacman -S radare2"
check jadx "pacman -S jadx"
check apktool "pacman -S apktool"
check binwalk "pacman -S binwalk"
check readelf "pacman -S binutils"
check strings "pacman -S binutils"

if [ -x /opt/ghidra/support/analyzeHeadless ]; then
    printf '  ok    %-12s %s\n' ghidra "/opt/ghidra/support/analyzeHeadless"
else
    printf '  miss  %-12s %s\n' ghidra "install Ghidra under /opt/ghidra"
    fail=1
fi

echo "== cli link"
chmod +x "$HERE/bin/fwlab"
ln -sf "$HERE/bin/fwlab" "$BIN/fwlab"
echo "  $BIN/fwlab -> $HERE/bin/fwlab"

case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "  note: add $BIN to PATH to call fwlab directly" ;;
esac

echo "== fixtures"
if [ ! -f "$HERE/fixtures/dist/fw-v1.tar.gz" ]; then
    bash "$HERE/fixtures/build_fixtures.sh" >/dev/null
    echo "  built synthetic firmware pair"
else
    echo "  fixtures already built"
fi

echo "== doctor"
"$HERE/bin/fwlab" doctor || true

echo
if [ "$fail" -eq 0 ]; then
    echo "lab ready. try: fwlab demo"
else
    echo "lab ready with missing optional tools (see 'miss' above)."
fi
