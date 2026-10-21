#!/usr/bin/env bash
# Build the synthetic firmware pair used by the lab tests.
# v1 = vulnerable (X-Lab-Admin backdoor), v2 = fixed (session token only).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$HERE/dist"
WORK="$HERE/build"
CC="${CC:-gcc}"

rm -rf "$WORK" "$DIST"
mkdir -p "$WORK" "$DIST"

build_tree() {
    local version="$1"
    local cflags="$2"
    local root="$WORK/fw-$version"
    mkdir -p "$root"/{etc/init.d,usr/sbin,www/cgi-bin,var/run,etc/lab}

    "$CC" -O2 -s $cflags -o "$root/www/cgi-bin/status.cgi" "$HERE/src/gateway.c"

    cat > "$root/etc/init.d/rcS" <<'EOF'
#!/bin/sh
mount -t proc none /proc
/usr/sbin/lighttpd -f /etc/lighttpd.conf
echo boot-ok
EOF
    chmod 755 "$root/etc/init.d/rcS"

    cat > "$root/etc/lighttpd.conf" <<'EOF'
server.document-root = "/www"
server.modules = ( "mod_cgi" )
cgi.assign = ( ".cgi" => "" )
server.port = 8080
EOF

    printf '<html><body><h1>Lab Gateway</h1><p>firmware %s</p></body></html>\n' "$version" > "$root/www/index.html"
    printf 'firmware=%s\nbuild=lab\n' "$version" > "$root/etc/lab/version"
    printf 'serial=LAB-0001\ntoken=lab-%s\n' "$version" > "$root/etc/lab/device.conf"
    printf 'this file is gzipped so the extractor has something nested to find\n' | gzip -9 > "$root/etc/lab/notes.txt.gz"
    chmod 600 "$root/etc/lab/device.conf"

    tar --sort=name --mtime='2026-01-01 00:00:00' --owner=0 --group=0 --numeric-owner \
        -C "$WORK" -czf "$DIST/fw-$version.tar.gz" "fw-$version"
}

build_tree v1 "-DLAB_V1"
build_tree v2 ""

( cd "$DIST" && sha256sum *.tar.gz > SHA256SUMS )
echo "built:"
ls -l "$DIST"
cat "$DIST/SHA256SUMS"
