# MITR3 OT Firmware Lab

Reproducible, evidence-first firmware reverse engineering. Built to answer one
question for any package on the bench: **where is the trust boundary, and what
crosses it without being checked?**

The lab does not depend on a live device. It works on vendor packages you are
authorized to analyze, on your own fixtures, and on emulated targets with no
network. Every step is a file on disk with a hash, so a claim can be replayed by
someone who was not in the room.

## What it does

| Step | Command | Output |
|---|---|---|
| container ID | `fwlab inspect pkg.bin` | type, magic, size, entropy |
| bounded extraction | `fwlab extract pkg.bin -o work/` | files + nested containers, path-safe |
| inventory | `fwlab inventory work/tree -o inv.json` | sha256, ELF arch/endian/class, setuid, scripts, auth strings |
| triage ranking | `fwlab queue inv.json -o q.jsonl` | score + reasons per binary |
| version delta | `fwlab diff old.json new.json` | added / removed / modified |
| Ghidra handoff | `fwlab ghidra q.jsonl --tree work/tree --run` | headless import + auth-function decompilation |
| evidence | `fwlab report ... -o report.md` | markdown a reviewer can cite |

Everything is stdlib Python. Extraction never executes target code and refuses
path traversal, absolute paths, symlink escapes, and over-budget archives.

## Quick start

```bash
cd ~/MITR3/labs/ot-firmware
bash scripts/install_mitr3.sh      # checks host tools, links ~/.local/bin/fwlab
make demo                          # synthetic v1 vs v2, full pipeline
make test                          # 14 unit tests
bash scripts/bootstrap_repos.sh    # clone the external toolkit into vendor/
```

`make demo` prints something like:

```
workdir: /tmp/opencode/fwlab-demo
  extract: .../fw-v1
  inventory: 8
  queue: 1
  modified: 4
top of the queue:
  [ 65] www/cgi-bin/status.cgi  (x86_64, stripped)
```

Then `fwlab ghidra /tmp/opencode/fwlab-demo/v1.queue.jsonl --tree <root> --run`
decompiles the candidates and writes `<binary>.interesting.c`.

## Layout

```
fwlab/            package: formats, extract, inventory, diff, ghidra, report, cli
bin/fwlab         launcher (no install required)
fixtures/         synthetic vulnerable/fixed firmware pair + C source
tools/            AuthExport.java (Ghidra post-script, compiled on import)
scripts/          install_mitr3.sh, bootstrap_repos.sh
tests/            unit suite
docs/             METHOD.md, WALKTHROUGH.md
vendor/           cloned upstream projects (gitignored, recorded in REPOS.lock)
```

## Safety rules baked in

- Extraction writes data; nothing is chmod'd +x and run.
- Symlinks in archives are skipped; `..` and absolute members are rejected.
- File count, byte budget and recursion depth are capped.
- Unknown containers are reported as unknown, never guessed into an extractor.
- Real OT devices are out of scope for this lab. Validation happens on fixtures
  or emulation with networking disabled.

## Integration

- **REA** exposes `extract_firmware` (Unblob) for containers this lab hands off
  when the format is not zip/tar/gz/xz. Use it after `fwlab inspect` says the
  container is squashfs/cramfs/ubi.
- **Ghidra** 12.x at `/opt/ghidra`; `analyzeHeadless` is the only entry point
  used. Projects live in `workspaces/ghidra-projects` (Ghidra rejects project
  paths containing a dot-prefixed element such as `~/.local`).
- **MegaBrain** stores the evidence bundle: `report.md`, `inspect.json`,
  `inv.json`, `q.jsonl`, `delta.json` plus the package sha256.

## Evidence bundle

A claim is only as good as its bundle. Ship these five files together:

1. package sha256 and provenance (URL, version, date, authorization)
2. `inspect.json`
3. `inv.json`
4. `q.jsonl`
5. `report.md` + decompiled function excerpt with addresses

Anything missing from that list turns a finding into an anecdote.
