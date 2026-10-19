#!/usr/bin/env python3
"""Move one exposed Robin/Google credential from the live MITR3 Maestri board into
an owner-only secret file. No credential or partial value is ever printed.
Non-destructive to the rest of the board. Refuse conflicting existing secrets.
"""
import os
from pathlib import Path
import re

board = Path("/home/nielz/.maestri/workspaces/e5b70c54-62eb-4d7e-b2f5-7b91fef5039b/notes/MITR3 OPS BOARD.md")
root = Path.home() / ".config/mitr3-secrets"
dst = root / "robin-google.token"
pat = re.compile(r"(?<![A-Za-z0-9_])AQ\.[A-Za-z0-9_-]{25,}")
replacement = "[CREDENCIAL PROTEGIDA: ~/.config/mitr3-secrets/robin-google.token — rotacionar a chave exposta]"
stat_before = board.stat()
content = board.read_text(encoding="utf-8")
matched = pat.findall(content)
if len(matched) != 1:
    print("NO_CHANGE count_of_matching_values=", len(matched))
    raise SystemExit(1 if matched else 0)
key = matched[0]
root.mkdir(mode=0o700, parents=True, exist_ok=True)
root.chmod(0o700)
if dst.exists():
    if dst.read_text().strip() != key:
        raise SystemExit("BLOCKED: private secret already exists with different content")
else:
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
dst.chmod(0o600)
# Do not overwrite a note which another agent changed while we were securing the token.
stat_now = board.stat()
if (stat_now.st_size, stat_now.st_mtime_ns) != (stat_before.st_size, stat_before.st_mtime_ns):
    raise SystemExit("BLOCKED: board was edited concurrently. Secret stored privately; retry board redaction.")
new = content.replace(key, replacement)
with board.open("w", encoding="utf-8") as f:
    f.write(new)
board.chmod(0o644)
assert pat.search(board.read_text(encoding="utf-8")) is None
print("OK: credential removed from shared board; owner-only secret present, permissions=0600")
print("ROTATION_RECOMMENDED: a credential previously appearing in a shared note should be revoked and replaced.")
