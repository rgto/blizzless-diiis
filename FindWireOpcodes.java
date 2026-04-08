// Ghidra script to find the WIRE OPCODE dispatch table in D3 2.8.0
// Strategy: Search for arrays of pointers where:
//   - Multiple entries point to the SAME descriptor (e.g., SimpleMessage used by many opcodes)
//   - The array has 500+ entries
//   - Known: VersionsMessage descriptor = 0x141408910, type index 20
// The wire opcode table should be a separate, larger array.
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.io.*;

public class FindWireOpcodes extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\wire_opcodes.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Memory mem = currentProgram.getMemory();

        long vtablePtr = 0x140FCE828L;

        // Known descriptors from the type table at 0x1414051F8
        long typeTableBase = 0x1414051F8L;
        
        // Collect all descriptor addresses from the type table
        Set<Long> knownDescPtrs = new HashSet<>();
        Map<Long, String> descToName = new HashMap<>();
        
        for (int i = 0; i < 155; i++) {
            try {
                long descPtr = mem.getLong(toAddr(typeTableBase + (long) i * 8));
                if (descPtr >= 0x140000000L && descPtr <= 0x142000000L) {
                    knownDescPtrs.add(descPtr);
                    // Read name
                    long namePtr = mem.getLong(toAddr(descPtr + 8));
                    if (namePtr >= 0x140000000L && namePtr <= 0x142000000L) {
                        String name = readString(mem, toAddr(namePtr));
                        if (name != null) {
                            descToName.put(descPtr, name);
                        }
                    }
                }
            } catch (Exception e) {}
        }

        println("Known descriptors: " + knownDescPtrs.size());
        out.println("# Known type descriptors: " + knownDescPtrs.size());

        // APPROACH 1: Search for pointer to VersionsMessage descriptor (0x141408910)
        // The type table has it at index 20. But the wire opcode table should 
        // ALSO have a reference to it. Find ALL pointers to 0x141408910.
        long versionsDesc = 0x141408910L;
        byte[] verBytes = longToBytes(versionsDesc);
        
        println("=== Searching for ALL pointers to VersionsMessage desc (0x141408910) ===");
        out.println("\n# All pointers to VersionsMessage descriptor:");
        
        List<Long> versionsRefs = new ArrayList<>();
        Address search = mem.getMinAddress();
        while (search != null && !monitor.isCancelled()) {
            search = mem.findBytes(search, verBytes, null, true, monitor);
            if (search != null) {
                versionsRefs.add(search.getOffset());
                out.println(String.format("  0x%X", search.getOffset()));
                search = search.add(1);
            }
        }
        println("Found " + versionsRefs.size() + " pointers to VersionsMessage desc");

        // Check each pointer location: is it part of a larger array?
        for (long ptrAddr : versionsRefs) {
            // The type table has this at index 20 (offset 160 = 0xA0)
            // Skip the type table entry
            if (ptrAddr == typeTableBase + 20 * 8) {
                out.println(String.format("  0x%X = type table entry (skipping)", ptrAddr));
                continue;
            }
            
            out.println(String.format("\n# Investigating pointer at 0x%X:", ptrAddr));
            
            // Check if this could be an opcode-indexed array
            // Walk backwards to find array start, walk forward to find end
            // Look for entries that point to known descriptors
            
            // Try different possible offsets for VersionsMessage's opcode
            // In 2.7.4 it's opcode 20. In 2.8.0, it might be different.
            // Try 20 first, then scan around.
            
            for (int assumedOpcode : new int[]{20, 19, 21, 15, 25, 30}) {
                long possibleBase = ptrAddr - (long) assumedOpcode * 8;
                
                // Validate: check how many entries in 0..600 point to known descriptors
                int validCount = 0;
                int totalNonNull = 0;
                Map<Long, Integer> descRefCounts = new HashMap<>();
                
                for (int opc = 0; opc <= 600; opc++) {
                    try {
                        long entryVal = mem.getLong(toAddr(possibleBase + (long) opc * 8));
                        if (entryVal == 0) continue;
                        if (entryVal < 0x140000000L || entryVal > 0x142000000L) continue;
                        totalNonNull++;
                        if (knownDescPtrs.contains(entryVal)) {
                            validCount++;
                            descRefCounts.merge(entryVal, 1, Integer::sum);
                        }
                    } catch (Exception e) {}
                }
                
                if (validCount >= 50) {
                    out.println(String.format("  *** CANDIDATE TABLE at base 0x%X (assuming opcode %d):", 
                        possibleBase, assumedOpcode));
                    out.println(String.format("      Valid desc refs: %d, Total non-null: %d", validCount, totalNonNull));
                    
                    // Check for repeated descriptors (key indicator of wire opcode table)
                    int repeated = 0;
                    for (Map.Entry<Long, Integer> e : descRefCounts.entrySet()) {
                        if (e.getValue() > 1) {
                            String dName = descToName.getOrDefault(e.getKey(), "?");
                            out.println(String.format("      %s appears %d times", dName, e.getValue()));
                            repeated++;
                        }
                    }
                    
                    if (repeated > 0) {
                        out.println("      << MULTIPLE DESCRIPTORS REPEATED - THIS IS LIKELY THE WIRE OPCODE TABLE >>");
                        
                        // DUMP FULL TABLE
                        out.println("\n# === WIRE OPCODE TABLE ===");
                        int lastValid = 0;
                        for (int opc = 0; opc <= 700; opc++) {
                            try {
                                long entryVal = mem.getLong(toAddr(possibleBase + (long) opc * 8));
                                if (entryVal == 0) continue;
                                if (entryVal < 0x140000000L || entryVal > 0x142000000L) {
                                    if (opc - lastValid > 50) break; // end of table
                                    continue;
                                }
                                lastValid = opc;
                                
                                String name = descToName.getOrDefault(entryVal, null);
                                if (name == null) {
                                    // Try to read directly
                                    try {
                                        long namePtr = mem.getLong(toAddr(entryVal + 8));
                                        if (namePtr >= 0x140000000L && namePtr <= 0x142000000L) {
                                            name = readString(mem, toAddr(namePtr));
                                        }
                                    } catch (Exception ex) {}
                                }
                                
                                // Try to read size info: check bytes at descriptor offset +16, +20, +24
                                int size = -1;
                                try {
                                    // Some D3 versions store serialized size at various offsets
                                    for (int soff = 16; soff <= 40; soff += 4) {
                                        int v = mem.getInt(toAddr(entryVal + soff));
                                        if (v > 0 && v < 65536) {
                                            size = v;
                                            break;
                                        }
                                    }
                                } catch (Exception ex) {}
                                
                                String sizeStr = size > 0 ? " SIZE=" + size : "";
                                out.println(String.format("OPCODE %d = %s%s", opc, 
                                    name != null ? name : String.format("? (desc=0x%X)", entryVal), sizeStr));
                                    
                            } catch (Exception e) {}
                        }
                    }
                }
            }
        }

        // APPROACH 2: Search for any array with 400+ entries pointing to known descriptors
        // Scan the .rdata section for dense arrays of descriptor pointers
        out.println("\n# === APPROACH 2: Scanning for dense pointer arrays ===");
        println("=== Approach 2: Scanning for dense pointer arrays ===");
        
        // Take a distinct known descriptor and search for all pointers to it
        // SimpleMessage (idx 51) should appear MANY times in the wire table
        long simpleDesc = 0;
        try {
            simpleDesc = mem.getLong(toAddr(typeTableBase + 51L * 8));
        } catch (Exception e) {}
        
        if (simpleDesc != 0) {
            out.println(String.format("# SimpleMessage descriptor: 0x%X", simpleDesc));
            byte[] simpleBytes = longToBytes(simpleDesc);
            
            List<Long> simpleRefs = new ArrayList<>();
            search = mem.getMinAddress();
            while (search != null && !monitor.isCancelled()) {
                search = mem.findBytes(search, simpleBytes, null, true, monitor);
                if (search != null) {
                    simpleRefs.add(search.getOffset());
                    search = search.add(1);
                }
            }
            out.println("# Pointers to SimpleMessage desc: " + simpleRefs.size());
            
            if (simpleRefs.size() > 5) {
                // Check if these refs are clustered (part of the same array)
                Collections.sort(simpleRefs);
                for (int i = 0; i < simpleRefs.size(); i++) {
                    out.println(String.format("  [%d] 0x%X (delta from prev: %d bytes)", 
                        i, simpleRefs.get(i),
                        i > 0 ? (simpleRefs.get(i) - simpleRefs.get(i-1)) : 0));
                }
                
                // If refs are 8-byte aligned and in the same region, it's an array
                if (simpleRefs.size() >= 2) {
                    long first = simpleRefs.get(0);
                    long last = simpleRefs.get(simpleRefs.size() - 1);
                    long span = last - first;
                    out.println(String.format("# Span: 0x%X (%d bytes, ~%d entries if stride=8)", 
                        span, span, span / 8));
                }
            }
        }

        out.flush();
        out.close();
        println("Output written to: " + outputPath);
    }

    private byte[] longToBytes(long val) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) ((val >> (i * 8)) & 0xFF);
        }
        return bytes;
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
