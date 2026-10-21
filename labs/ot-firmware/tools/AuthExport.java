// Ghidra post-script: dump auth/exec relevant functions and their callers.
//
// Java on purpose: Ghidra 12 only runs .py scripts when started through
// PyGhidra. This compiles on the fly in analyzeHeadless.
//
// Candidate selection has two legs:
//   1. function name contains an auth/exec keyword
//   2. a function instruction references bytes that look like a keyword string
//
// Leg 2 avoids the Data API on purpose: the headless script compiler has been
// unreliable about ghidra.program.model.data on this install, so we map the
// string bytes ourselves and test reference targets against that set.
//
// Usage (from fwlab):
//   analyzeHeadless <proj> <name> -import <bin> -scriptPath tools \
//       -postScript AuthExport.java <outdir>
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;

public class AuthExport extends GhidraScript {

    private static final String[] KEYS = {
        "auth", "session", "token", "admin", "password", "strcmp", "strncmp",
        "system", "popen", "exec", "header", "cookie", "permission", "role",
        "login", "debug", "upgrade", "firmware"
    };
    private static final int MAX_FUNCS = 120;
    private static final int MAX_BLOCK_SCAN = 8 * 1024 * 1024;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: AuthExport.java <outdir>");
            return;
        }
        File outDir = new File(args[0]);
        if (!outDir.isDirectory() && !outDir.mkdirs()) {
            printerr("cannot create " + outDir);
            return;
        }
        String base = currentProgram.getName().replaceAll("[^A-Za-z0-9_.-]", "_");

        Set<Long> keywordBytes = mapKeywordBytes();

        List<Function> funcs = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            funcs.add(f);
        }

        try (PrintWriter fw = new PrintWriter(new File(outDir, base + ".functions.txt"))) {
            for (Function f : funcs) {
                fw.printf("0x%s\t%s\t%s%n", f.getEntryPoint(), f.getName(), f.getSignature());
            }
        }

        List<Function> candidates = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Function f : funcs) {
            if (candidates.size() >= MAX_FUNCS) {
                break;
            }
            if (isCandidate(f, keywordBytes) && seen.add(f.getEntryPoint().toString())) {
                candidates.add(f);
            }
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        List<String> calls = new ArrayList<>();
        try (PrintWriter cw = new PrintWriter(new File(outDir, base + ".interesting.c"))) {
            cw.println("// candidate functions selected by name and keyword-string references");
            cw.println("// binary: " + currentProgram.getName());
            cw.println();
            for (Function f : candidates) {
                cw.printf("/* ---- 0x%s %s ---- */%n", f.getEntryPoint(), f.getSignature());
                DecompileResults res = decomp.decompileFunction(f, 90, monitor);
                if (res != null && res.decompileCompleted()) {
                    cw.print(res.getDecompiledFunction().getC());
                } else {
                    cw.println("// decompilation failed");
                }
                cw.println();
                cw.println();
                for (Function caller : f.getCallingFunctions(monitor)) {
                    calls.add(caller.getName() + " -> " + f.getName());
                }
            }
        }

        try (PrintWriter xw = new PrintWriter(new File(outDir, base + ".calls.txt"))) {
            for (String line : calls) {
                xw.println(line);
            }
        }

        println("AuthExport: " + funcs.size() + " functions, " + candidates.size()
                + " candidates, " + keywordBytes.size() + " keyword bytes -> "
                + outDir.getAbsolutePath());
    }

    /** Addresses of bytes that belong to printable runs containing a keyword. */
    private Set<Long> mapKeywordBytes() {
        Set<Long> hits = new HashSet<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() || block.isExecute()) {
                continue;
            }
            long size = Math.min(block.getSize(), MAX_BLOCK_SCAN);
            byte[] buf = new byte[(int) size];
            try {
                currentProgram.getMemory().getBytes(block.getStart(), buf);
            } catch (Exception e) {
                continue;
            }
            int i = 0;
            while (i < buf.length) {
                if (buf[i] < 32 || buf[i] > 126) {
                    i++;
                    continue;
                }
                int start = i;
                while (i < buf.length && buf[i] >= 32 && buf[i] <= 126) {
                    i++;
                }
                if (i - start < 5) {
                    continue;
                }
                String run = new String(buf, start, i - start, StandardCharsets.ISO_8859_1)
                        .toLowerCase();
                boolean keyed = false;
                for (String k : KEYS) {
                    if (run.contains(k)) {
                        keyed = true;
                        break;
                    }
                }
                if (keyed) {
                    long base = block.getStart().getOffset() + start;
                    for (int j = 0; j < (i - start); j++) {
                        hits.add(base + j);
                    }
                }
            }
        }
        return hits;
    }

    private boolean isCandidate(Function f, Set<Long> keywordBytes) {
        String lname = f.getName().toLowerCase();
        for (String k : KEYS) {
            if (lname.contains(k)) {
                return true;
            }
        }
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        int seen = 0;
        while (it.hasNext() && seen < 2000) {
            Instruction ins = it.next();
            seen++;
            for (Reference ref : ins.getReferencesFrom()) {
                if (keywordBytes.contains(ref.getToAddress().getOffset())) {
                    return true;
                }
            }
        }
        return false;
    }
}
