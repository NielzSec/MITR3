# Walkthrough — a synthetic auth bypass, end to end

This is the lab proving itself on its own fixture. Nothing here touches a vendor
device. The point is the shape of the evidence, not the bug: the same six
artifacts are what you would attach to a real package.

## Fixture

`fixtures/build_fixtures.sh` compiles one C CGI twice:

- **v1** — `-DLAB_V1`, includes a debug header check
- **v2** — same source without the check

```
e3b62c0c660d2491b297fa12cab6ba8c198ce9a3c58167a03058d1b370668550  fw-v1.tar.gz
fe2e89e5daa9874ef611d03b17b92d8682ffff8cc4e4f3b43e4959c5c9add0cc  fw-v2.tar.gz
```

## Run

```bash
make demo
# or
fwlab demo --fixture fixtures/dist/fw-v1.tar.gz \
            --against fixtures/dist/fw-v2.tar.gz \
            --workdir /tmp/opencode/fwlab-demo
```

Output:

```
workdir: /tmp/opencode/fwlab-demo
  extract: /tmp/opencode/fwlab-demo/v1/fw-v1.tar.extracted/fw-v1
  inventory: 8
  queue: 1
  modified: 4
  report: /tmp/opencode/fwlab-demo/report.md

top of the queue:
  [ 65] www/cgi-bin/status.cgi  (x86_64, stripped)
```

## Step 1 — container

`inspect.json`:

```json
{"type": "gzip", "confidence": "magic", "size": 3602, "entropy": 7.464,
 "note": "gzip stream"}
```

gzip wrapping a tar. The extractor unwraps both and records the nested result,
including the gzip inside `etc/lab/notes.txt.gz`.

## Step 2 — inventory

8 files, 1 ELF. The ELF is the CGI:

```
www/cgi-bin/status.cgi   sha256 72b82dfa…b2c8   x86_64   stripped   exec
```

`inventory` also flagged the strings that matter:

```
X-, admin, session, strcmp, strncmp
```

`strncmp` alone means nothing. It becomes a lead only in context.

## Step 3 — queue

```
[65] www/cgi-bin/status.cgi
     reasons: in_web_root, auth_strings:X-,admin,session,strcmp,strncmp, elf_exec
```

The score is auditable: 30 for the web root, 25 for auth strings, 10 for an
executable ELF. A reviewer can disagree with the weights; nobody has to guess
why the binary is first.

## Step 4 — decompile the boundary

```bash
fwlab ghidra /tmp/opencode/fwlab-demo/v1.queue.jsonl \
            --tree /tmp/opencode/fwlab-demo/v1/fw-v1.tar.extracted/fw-v1 --run
```

The post-script selects functions by name and by referenced strings, then dumps
decompiled bodies. In `FUN_001010f0` (the CGI main):

```c
pcVar4 = strstr(local_1028,"X-Lab-Admin: 1");
if (pcVar4 == (char *)0x0) {
  iVar2 = strncmp((char *)&local_1128,"/admin",6);
  if (iVar2 != 0) goto LAB_00101246;
  pcVar4 = strstr(local_1028,"X-Session: ");
  if (pcVar4 != (char *)0x0) {
    ...
    __stream = fopen("/var/run/lab-session","r");
```

Read the control flow, not the strings:

- `local_1028` is the raw request buffer, filled by `fread(stdin, …, 0xfff)`.
- The client controls every byte of it, including the header line.
- A match on `X-Lab-Admin: 1` skips the `/admin` session check entirely.
- Only if the header is absent does the code reach `fopen("/var/run/lab-session")`.

The trust boundary is the header line. The crossing is `strstr` returning
non-NULL before the session comparison. Two addresses, one sentence — that is
the finding format.

## Step 5 — delta against the fix

`fwlab diff` reports 4 modified files. Three are version strings; the fourth is
the CGI. Its hash changes from `72b82dfa…` to `98dec6a8…`.

`strings` on the two builds:

```
v1: X-Lab-Admin: 1
v2: (absent)
both: X-Session:  /var/run/lab-session
```

The fixed build keeps the session check and removes the header path. A
one-function delta at exactly the trust boundary is the vendor agreeing with
your read, in binary.

## What the lab does not claim

- The fixture is synthetic; it is not a Danfoss device and does not reproduce
  CVE-2025-41450.
- Static reachability is not runtime exploitability. The lab shows the crossing;
  proving impact needs the harness step (emulation, no network).
- A header named `X-Lab-Admin` is a teaching label. Real targets use plausible
  names and the same shape.

## Reproduce the bundle

```bash
cd ~/MITR3/labs/ot-firmware
make clean && make fixtures && make demo
ls /tmp/opencode/fwlab-demo
# inspect.json  v1.extract.json  v1.inv.json  v1.queue.jsonl  delta.json  report.md
```
