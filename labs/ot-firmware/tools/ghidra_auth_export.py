# Ghidra post-script (reference only): dump auth/exec relevant functions.
#
# NOTE: Ghidra 12 refuses .py scripts unless the analyzer is started through
# PyGhidra. The lab ships tools/AuthExport.java instead and uses it by default.
# This file is kept as a reference for teams that run pyghidraRun.
#
# Runs on Ghidra's Jython. Invoked by fwlab's headless wrapper:
#   analyzeHeadless <proj> <name> -import <bin> -postScript ghidra_auth_export.py <outdir>
#
# Writes:
#   <outdir>/<binary>.functions.txt   function list with addresses
#   <outdir>/<binary>.interesting.c   decompiled bodies of candidate functions
#   <outdir>/<binary>.calls.txt       caller -> callee edges for those bodies
from __future__ import print_function

import os
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

KEYWORDS = [
    "auth", "session", "token", "admin", "password", "strcmp", "strncmp",
    "system", "popen", "exec", "header", "cookie", "permission", "role",
    "login", "debug", "upgrade", "firmware",
]

MAX_FUNCS = 120


def safe_name(program):
    name = program.getName()
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def main():
    args = getScriptArgs()
    if len(args) < 1:
        printerr("usage: ghidra_auth_export.py <outdir>")
        return
    outdir = args[0]
    if not os.path.isdir(outdir):
        os.makedirs(outdir)

    program = currentProgram
    base = safe_name(program)

    fm = program.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    listing = []

    with open(os.path.join(outdir, base + ".functions.txt"), "w") as fh:
        for f in funcs:
            fh.write("0x%s\t%s\t%s\n" % (f.getEntryPoint(), f.getName(), f.getSignature()))

    # Candidate selection: name match or string reference match.
    candidates = []
    seen = set()
    for f in funcs:
        lname = f.getName().lower()
        hit = any(k in lname for k in KEYWORDS)
        if not hit:
            body = f.getBody()
            it = body.getAddresses(True)
            refs = 0
            while it.hasNext() and refs < 400:
                addr = it.next()
                for ref in getReferencesFrom(addr):
                    to = ref.getToAddress()
                    data = getDataAt(to)
                    if data is not None and data.hasStringValue():
                        s = str(data.getValue()).lower()
                        if any(k in s for k in KEYWORDS):
                            hit = True
                            break
                    refs += 1
                if hit:
                    break
        if hit and f.getEntryPoint() not in seen:
            seen.add(f.getEntryPoint())
            candidates.append(f)
        if len(candidates) >= MAX_FUNCS:
            break

    decomp = DecompInterface()
    decomp.openProgram(program)
    monitor = ConsoleTaskMonitor()

    callers = {}
    with open(os.path.join(outdir, base + ".interesting.c"), "w") as fh:
        fh.write("// candidate functions selected by name/string heuristics\n")
        fh.write("// binary: %s\n\n" % program.getName())
        for f in candidates:
            fh.write("/* ---- 0x%s %s ---- */\n" % (f.getEntryPoint(), f.getSignature()))
            res = decomp.decompileFunction(f, 60, monitor)
            if res and res.decompileCompleted():
                fh.write(res.getDecompiledFunction().getC())
            else:
                fh.write("// decompilation failed\n")
            fh.write("\n\n")
            for caller in f.getCallingFunctions(monitor):
                callers.setdefault(caller.getName(), set()).add(f.getName())

    with open(os.path.join(outdir, base + ".calls.txt"), "w") as fh:
        for caller in sorted(callers):
            for callee in sorted(callers[caller]):
                fh.write("%s -> %s\n" % (caller, callee))

    println("ghidra_auth_export: %d functions, %d candidates -> %s" % (len(funcs), len(candidates), outdir))


main()
