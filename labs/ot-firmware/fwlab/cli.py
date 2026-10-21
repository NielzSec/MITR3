"""fwlab CLI.

    fwlab doctor
    fwlab inspect FIRMWARE
    fwlab extract FIRMWARE -o OUTDIR
    fwlab inventory TREE -o inv.json
    fwlab queue inv.json -o queue.jsonl
    fwlab diff old.json new.json
    fwlab report --inspect ... --inventory ... --queue ... --diff ...
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

from . import __version__, diff as diffmod, extract as extractmod, formats, ghidra, inventory as invmod, report as reportmod

TOOLS = ["ghidra", "r2", "rabin2", "jadx", "apktool", "binwalk", "strings", "readelf", "objdump", "file"]


def _json_out(data, path):
    text = json.dumps(data, indent=2, sort_keys=True)
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text + "\n")
        print(f"written {path}")
    else:
        print(text)


def cmd_doctor(args):
    print(f"fwlab {__version__}")
    print(f"python {sys.version.split()[0]}")
    missing = []
    for tool in TOOLS:
        found = shutil.which(tool)
        print(f"  {tool:10s} {found or '-'}")
        if not found:
            missing.append(tool)
    ghidra_headless = shutil.which("analyzeHeadless") or ("/opt/ghidra/support/analyzeHeadless" if os.path.exists("/opt/ghidra/support/analyzeHeadless") else None)
    print(f"  {'analyzeHeadless':10s} {ghidra_headless or '-'}")
    if missing:
        print("missing:", ", ".join(missing))
    return 0


def cmd_inspect(args):
    info = formats.detect(args.firmware)
    _json_out(info, args.out)
    return 0


def cmd_extract(args):
    res = extractmod.extract(args.firmware, args.outdir)
    res["tree_roots"] = extractmod.tree_roots(res)
    res["effective_roots"] = [extractmod.effective_root(r) for r in res["tree_roots"]]
    res["root"] = extractmod.primary_root(res)
    _json_out(res, args.json)
    return 0 if not res.get("error") else 2


def cmd_inventory(args):
    inv = invmod.inventory(args.tree)
    _json_out(inv, args.out)
    return 0


def cmd_queue(args):
    with open(args.inventory_json) as fh:
        inv = json.load(fh)
    q = ghidra.build_queue(inv, min_score=args.min_score)
    path = ghidra.write_queue(q, args.out)
    print(f"{len(q)} binaries queued -> {path}")
    return 0


def cmd_diff(args):
    with open(args.old) as fh:
        old = json.load(fh)
    with open(args.new) as fh:
        new = json.load(fh)
    d = diffmod.diff(old, new)
    _json_out(d, args.out)
    return 0


def cmd_report(args):
    inspect = json.load(open(args.inspect)) if args.inspect else None
    inv = json.load(open(args.inventory)) if args.inventory else None
    queue = [json.loads(line) for line in open(args.queue)] if args.queue else None
    delta = json.load(open(args.diff)) if args.diff else None
    md = reportmod.build(args.title, inspect, inv, queue, delta)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w").write(md)
        print(f"written {args.out}")
    else:
        print(md)
    return 0


def cmd_ghidra(args):
    queue = [json.loads(line) for line in open(args.queue)]
    if not queue:
        print("empty queue")
        return 1
    item = queue[args.index]
    binary = os.path.join(args.tree, item["path"])
    if not os.path.exists(binary):
        print(f"missing binary: {binary}")
        return 2
    project_dir = os.path.abspath(args.projects)
    os.makedirs(project_dir, exist_ok=True)
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "AuthExport.java")
    cmd = ghidra.headless_command(project_dir, args.project, binary, script, out_dir)
    print(" ".join(cmd))
    if args.run:
        import subprocess
        return subprocess.call(cmd, timeout=args.timeout)
    print("dry run (pass --run to execute)")
    return 0


def cmd_demo(args):
    work = os.path.abspath(args.workdir)
    os.makedirs(work, exist_ok=True)
    fixture = os.path.abspath(args.fixture)
    steps = {}

    inspect = formats.detect(fixture)
    _write_json(os.path.join(work, "inspect.json"), inspect)

    ex = extractmod.extract(fixture, os.path.join(work, "v1"))
    ex["tree_roots"] = extractmod.tree_roots(ex)
    ex["root"] = extractmod.primary_root(ex)
    _write_json(os.path.join(work, "v1.extract.json"), ex)
    steps["extract"] = ex.get("root")

    inv = invmod.inventory(ex["root"])
    _write_json(os.path.join(work, "v1.inv.json"), inv)
    steps["inventory"] = inv["files"]

    queue = ghidra.build_queue(inv)
    ghidra.write_queue(queue, os.path.join(work, "v1.queue.jsonl"))
    steps["queue"] = len(queue)

    if args.against:
        ex2 = extractmod.extract(os.path.abspath(args.against), os.path.join(work, "v2"))
        ex2["root"] = extractmod.primary_root(ex2)
        inv2 = invmod.inventory(ex2["root"])
        _write_json(os.path.join(work, "v2.inv.json"), inv2)
        delta = diffmod.diff(inv, inv2)
        _write_json(os.path.join(work, "delta.json"), delta)
        steps["modified"] = delta["counts"]["modified"]
    else:
        delta = None

    md = reportmod.build(
        "fwlab demo — " + os.path.basename(fixture),
        inspect, inv, queue, delta,
    )
    report_path = os.path.join(work, "report.md")
    open(report_path, "w").write(md)

    print(f"workdir: {work}")
    for k, v in steps.items():
        print(f"  {k}: {v}")
    print(f"  report: {report_path}")
    if queue:
        print("\ntop of the queue:")
        for item in queue[:5]:
            print(f"  [{item['score']:3d}] {item['path']}  ({item['arch']}, {'stripped' if item['stripped'] else 'symbols'})")
    return 0


def _write_json(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(json.dumps(data, indent=2, sort_keys=True) + "\n")


def build_parser():
    p = argparse.ArgumentParser(prog="fwlab", description="OT firmware lab: inspect, extract, inventory, queue, diff")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("doctor", help="check local tooling")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("inspect", help="detect container format")
    s.add_argument("firmware")
    s.add_argument("-o", "--out")
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("extract", help="bounded, safe extraction")
    s.add_argument("firmware")
    s.add_argument("-o", "--outdir", required=True)
    s.add_argument("--json")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser("inventory", help="hash and describe every file")
    s.add_argument("tree")
    s.add_argument("-o", "--out")
    s.set_defaults(func=cmd_inventory)

    s = sub.add_parser("queue", help="rank binaries for Ghidra")
    s.add_argument("inventory_json")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--min-score", type=int, default=20)
    s.set_defaults(func=cmd_queue)

    s = sub.add_parser("diff", help="compare two inventories")
    s.add_argument("old")
    s.add_argument("new")
    s.add_argument("-o", "--out")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("report", help="render markdown evidence")
    s.add_argument("--title", default="Firmware analysis")
    s.add_argument("--inspect")
    s.add_argument("--inventory")
    s.add_argument("--queue")
    s.add_argument("--diff")
    s.add_argument("-o", "--out")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("ghidra", help="build (or run) the headless command for a queued binary")
    s.add_argument("queue")
    s.add_argument("--tree", required=True, help="extracted firmware root")
    s.add_argument("--index", type=int, default=0)
    s.add_argument("--projects", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "workspaces", "ghidra-projects"))
    s.add_argument("--project", default="ot-lab")
    s.add_argument("--out", default="ghidra-out")
    s.add_argument("--timeout", type=int, default=900)
    s.add_argument("--run", action="store_true")
    s.set_defaults(func=cmd_ghidra)

    s = sub.add_parser("demo", help="run the full pipeline on the synthetic fixture")
    s.add_argument("--fixture", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "dist", "fw-v1.tar.gz"))
    s.add_argument("--against", help="second firmware package for the delta")
    s.add_argument("--workdir", default="/tmp/opencode/fwlab-demo")
    s.set_defaults(func=cmd_demo)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
