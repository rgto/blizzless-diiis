// Ghidra script to extract ALL opcodes from D3 2.8.0
// Based on discovery: opcode-indexed pointer array at 0x1414051F8
// Each entry is an 8-byte pointer to a descriptor struct where:
//   [+0] = vtable pointer (may vary per message type)
//   [+8] = name string pointer
// Reads ALL non-null entries without filtering by vtable.
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.io.*;

public class ExtractOpcodes3 extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\opcodes_280.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Memory mem = currentProgram.getMemory();

        // Known array base from ExtractOpcodes2 calibration:
        // VersionsMessage descriptor at 0x141408910, at array index 20
        // Array entry for opcode 20 at 0x141405298
        // Array base = 0x141405298 - 20*8 = 0x1414051F8
        long arrayBase = 0x1414051F8L;

        println("=== Extracting opcodes from array at 0x" + Long.toHexString(arrayBase) + " ===");
        out.println("# D3 2.8.0 (build 99920) Opcode Table");
        out.println("# Extracted from Diablo III64.exe via Ghidra");
        out.println("# Array base: 0x" + Long.toHexString(arrayBase));
        out.println("# Format: OPCODE <id> = <name> [vtable=<hex>] [size=<bytes>]");
        out.println();

        int found = 0;
        int nullEntries = 0;
        int maxOpcode = 700; // scan beyond 2.7.4's max of ~553

        // Also check index 0
        for (int opc = 0; opc <= maxOpcode; opc++) {
            if (monitor.isCancelled()) break;
            try {
                Address entryAddr = toAddr(arrayBase + (long) opc * 8);
                long descPtr = mem.getLong(entryAddr);

                if (descPtr == 0) {
                    nullEntries++;
                    continue;
                }

                // Validate pointer is in a reasonable range (image base 0x140000000)
                if (descPtr < 0x140000000L || descPtr > 0x142000000L) {
                    // Probably past end of array
                    if (nullEntries > 20) {
                        // Many consecutive nulls + out-of-range = end of array
                        out.println("# End of array detected at opcode " + opc);
                        break;
                    }
                    continue;
                }

                Address descAddr = toAddr(descPtr);

                // Read vtable pointer at +0
                long vtable = 0;
                try {
                    vtable = mem.getLong(descAddr);
                } catch (Exception e) {
                    continue;
                }

                // Read name pointer at +8
                long namePtr = 0;
                try {
                    namePtr = mem.getLong(descAddr.add(8));
                } catch (Exception e) {
                    continue;
                }

                if (namePtr < 0x140000000L || namePtr > 0x142000000L) {
                    // Not a valid string pointer, but still log
                    out.println(String.format("# OPCODE %d -> desc 0x%X, vtable=0x%X, namePtr=0x%X (INVALID)",
                            opc, descPtr, vtable, namePtr));
                    continue;
                }

                String name = readString(mem, toAddr(namePtr));
                if (name == null || name.isEmpty()) {
                    out.println(String.format("# OPCODE %d -> desc 0x%X, vtable=0x%X (no name)",
                            opc, descPtr, vtable));
                    continue;
                }

                // Try to read message size from the descriptor struct
                // In D3, the size field is typically at some offset in the struct
                // Let's read several int32 fields and report non-zero ones
                StringBuilder extra = new StringBuilder();
                // Check +16 through +48 for small integers that could be sizes
                for (int off = 16; off <= 48; off += 4) {
                    try {
                        int val = mem.getInt(descAddr.add(off));
                        if (val > 0 && val < 100000) {
                            extra.append(String.format(" [+%d]=%d", off, val));
                        }
                    } catch (Exception e) {}
                }

                out.println(String.format("OPCODE %d = %s  vtable=0x%X%s",
                        opc, name, vtable, extra.toString()));
                found++;
                nullEntries = 0; // reset consecutive null counter

            } catch (Exception e) {
                // skip
            }
        }

        out.println();
        out.println("# Total opcodes found: " + found);
        out.println("# Array scanned: 0-" + maxOpcode);

        // Also scan BACKWARDS from base to check for index 0 or negative indices
        out.println();
        out.println("# --- Checking before array base ---");
        for (int i = -5; i < 0; i++) {
            try {
                Address entryAddr = toAddr(arrayBase + (long) i * 8);
                long descPtr = mem.getLong(entryAddr);
                if (descPtr != 0 && descPtr >= 0x140000000L && descPtr <= 0x142000000L) {
                    Address descAddr = toAddr(descPtr);
                    long namePtr = mem.getLong(descAddr.add(8));
                    if (namePtr >= 0x140000000L && namePtr <= 0x142000000L) {
                        String name = readString(mem, toAddr(namePtr));
                        if (name != null) {
                            out.println(String.format("# INDEX %d = %s (before array base!)", i, name));
                        }
                    }
                }
            } catch (Exception e) {}
        }

        // Verify calibration: check VersionsMessage at opcode 20
        out.println();
        out.println("# --- Calibration check ---");
        try {
            Address entry20 = toAddr(arrayBase + 20L * 8);
            long desc20 = mem.getLong(entry20);
            Address descAddr20 = toAddr(desc20);
            long namePtr20 = mem.getLong(descAddr20.add(8));
            String name20 = readString(mem, toAddr(namePtr20));
            out.println("# Opcode 20 = " + name20 + " (expected: VersionsMessage) -> " +
                    ("VersionsMessage".equals(name20) ? "OK" : "MISMATCH!"));
        } catch (Exception e) {
            out.println("# Calibration check failed: " + e.getMessage());
        }

        out.flush();
        out.close();
        println("Found " + found + " opcodes. Output: " + outputPath);
    }

    private String readString(Memory mem, Address addr) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 300; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0) break;
                if (b < 32 || b > 126) return null;
                sb.append((char) b);
            }
            return sb.length() > 0 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
