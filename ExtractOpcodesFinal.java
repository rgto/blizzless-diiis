// Ghidra script to extract ALL opcodes with sizes using byte-pattern scanning
// Works WITHOUT analysis pass since we scan raw bytes
// Accessor function pattern:
//   48 8B 05 xx xx xx xx    MOV RAX, [rip+xx]     (load type entry)  
//   48 89 02                MOV [RDX], RAX         
//   48 8D 05 xx xx xx xx    LEA RAX, [rip+xx]     
//   41 C7 00 SS SS SS SS    MOV dword ptr [R8], size
//   49 89 01                MOV [R9], RAX          
//   B8 01 00 00 00          MOV EAX, 1             
//   C3                      RET                    
// Total = 7+3+7+7+3+5+1 = 33 bytes per accessor
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.io.*;

public class ExtractOpcodesFinal extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\opcodes_280_final.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Memory mem = currentProgram.getMemory();

        long typeTableBase = 0x1414051F8L;

        // Build opcode->name map from type table
        Map<Integer, String> opcodeNames = new TreeMap<>();
        for (int i = 0; i < 155; i++) {
            try {
                long descPtr = mem.getLong(toAddr(typeTableBase + (long) i * 8));
                if (descPtr >= 0x140000000L && descPtr <= 0x142000000L) {
                    long namePtr = mem.getLong(toAddr(descPtr + 8));
                    if (namePtr >= 0x140000000L && namePtr <= 0x142000000L) {
                        String name = readString(mem, toAddr(namePtr));
                        if (name != null) opcodeNames.put(i, name);
                    }
                }
            } catch (Exception e) {}
        }
        println("Loaded " + opcodeNames.size() + " opcode names");

        // PATTERN 1: Full inline accessor
        // Bytes: 48 89 02  48 8D 05  xx xx xx xx  41 C7 00
        // The constant middle part is: 48 89 02 48 8D 05 (6 bytes)
        // After the LEA's 4-byte offset comes: 41 C7 00 SS SS SS SS
        
        // Search for "48 89 02 48 8D 05" in code region
        byte[] middlePattern = new byte[]{0x48, (byte)0x89, 0x02, 0x48, (byte)0x8D, 0x05};
        
        // Scan region: 0x1408A0000 to 0x1408C0000 (accessor functions area)
        long scanStart = 0x1408A0000L;
        long scanEnd = 0x1408C0000L;
        
        Map<Integer, Integer> opcodeSizes = new TreeMap<>();
        Map<Integer, Long> opcodeAddrs = new TreeMap<>();
        Map<Long, int[]> descAddrToOpcodeSize = new TreeMap<>();
        
        // Also collect all non-type-table descriptor addresses
        Set<Long> typeTableEntryAddrs = new HashSet<>();
        for (int i = 0; i < 155; i++) {
            typeTableEntryAddrs.add(typeTableBase + (long)i * 8);
        }
        
        // Collect all known descriptor pointer values
        Map<Long, Integer> descPtrToTypeIdx = new HashMap<>();
        for (int i = 0; i < 155; i++) {
            try {
                long descPtr = mem.getLong(toAddr(typeTableBase + (long) i * 8));
                descPtrToTypeIdx.put(descPtr, i);
            } catch (Exception e) {}
        }
        
        println("Scanning code region for accessor functions...");
        
        Address search = toAddr(scanStart);
        int patternHits = 0;
        
        while (search != null && search.getOffset() < scanEnd && !monitor.isCancelled()) {
            search = mem.findBytes(search, middlePattern, null, true, monitor);
            if (search == null || search.getOffset() >= scanEnd) break;
            
            long hitAddr = search.getOffset();
            patternHits++;
            
            // The "48 89 02 48 8D 05" is at hitAddr
            // Before this (at hitAddr-7), there should be: 48 8B 05 xx xx xx xx (MOV RAX,[rip+xx])
            // After 48 8D 05 xx xx xx xx comes: 41 C7 00 SS SS SS SS
            
            try {
                // Check for MOV RAX,[rip+xx] at hitAddr-7
                byte b0 = mem.getByte(toAddr(hitAddr - 7));
                byte b1 = mem.getByte(toAddr(hitAddr - 6));
                byte b2 = mem.getByte(toAddr(hitAddr - 5));
                
                if (b0 == 0x48 && b1 == (byte)0x8B && b2 == 0x05) {
                    // Read the RIP-relative offset for the type table load
                    int ripOffset = mem.getInt(toAddr(hitAddr - 4));
                    // RIP-relative: address = instruction_end + offset
                    // Instruction is at hitAddr-7, length 7, so RIP = hitAddr
                    long typeEntryAddr = hitAddr + ripOffset;
                    
                    // Read the LEA offset (4 bytes after 48 8D 05)
                    // LEA is at hitAddr+3, with format 48 8D 05 xx xx xx xx (7 bytes)
                    // So the size MOV starts at hitAddr + 3 + 7 = hitAddr + 10
                    
                    // Check for 41 C7 00 at hitAddr+10
                    byte s0 = mem.getByte(toAddr(hitAddr + 10));
                    byte s1 = mem.getByte(toAddr(hitAddr + 11));
                    byte s2 = mem.getByte(toAddr(hitAddr + 12));
                    
                    if (s0 == 0x41 && s1 == (byte)0xC7 && s2 == 0x00) {
                        // Read 4-byte size
                        int size = mem.getInt(toAddr(hitAddr + 13));
                        
                        // Determine opcode from type table entry address
                        long offset = typeEntryAddr - typeTableBase;
                        if (offset >= 0 && offset % 8 == 0) {
                            int opcode = (int) (offset / 8);
                            if (opcode < 155) {
                                opcodeSizes.put(opcode, size);
                                opcodeAddrs.put(opcode, hitAddr - 7);
                            }
                        }
                        
                        // Also try: maybe the loaded address is a descriptor directly
                        // (not from the type table but from another location)
                        try {
                            long descPtrVal = mem.getLong(toAddr(typeEntryAddr));
                            if (descPtrToTypeIdx.containsKey(descPtrVal)) {
                                int opcode = descPtrToTypeIdx.get(descPtrVal);
                                // This might be a SECOND accessor for the same type
                                // (i.e., a different wire opcode using the same message type)
                                // Check if typeEntryAddr is NOT in the type table
                                if (!typeTableEntryAddrs.contains(typeEntryAddr)) {
                                    descAddrToOpcodeSize.put(hitAddr - 7, new int[]{opcode, size});
                                }
                            }
                        } catch (Exception e) {}
                    }
                }
            } catch (Exception e) {}
            
            search = search.add(1);
        }
        
        println("Pattern hits: " + patternHits);
        println("Opcodes with sizes from type table: " + opcodeSizes.size());
        println("Additional accessors (outside type table): " + descAddrToOpcodeSize.size());
        
        // PATTERN 2: JMP-based accessor (shorter form)
        // MOV RAX, [rip+xx]; JMP common_epilogue
        // Bytes: 48 8B 05 xx xx xx xx E9 xx xx xx xx
        // Here we can just collect the type entry address but not the size directly
        // The size would be at the JMP target
        
        println("\nLooking for JMP-based accessors...");
        // Pattern: 48 8B 05 (any 4 bytes) E9
        byte[] jmpPattern = new byte[]{0x48, (byte)0x8B, 0x05};
        
        Map<Integer, Long> jmpAccessors = new TreeMap<>();
        search = toAddr(scanStart);
        
        while (search != null && search.getOffset() < scanEnd && !monitor.isCancelled()) {
            search = mem.findBytes(search, jmpPattern, null, true, monitor);
            if (search == null || search.getOffset() >= scanEnd) break;
            
            long hitAddr = search.getOffset();
            try {
                // Check if followed by JMP (E9) at hitAddr+7
                byte afterInsn = mem.getByte(toAddr(hitAddr + 7));
                if (afterInsn == (byte)0xE9) {
                    // Read RIP offset
                    int ripOffset = mem.getInt(toAddr(hitAddr + 3));
                    long typeEntryAddr = hitAddr + 7 + ripOffset;
                    
                    long offset = typeEntryAddr - typeTableBase;
                    if (offset >= 0 && offset % 8 == 0) {
                        int opcode = (int)(offset / 8);
                        if (opcode < 155 && !opcodeSizes.containsKey(opcode)) {
                            jmpAccessors.put(opcode, hitAddr);
                            
                            // Try to get size from JMP target
                            int jmpOffset = mem.getInt(toAddr(hitAddr + 8));
                            long jmpTarget = hitAddr + 12 + jmpOffset;
                            // At JMP target, look for the common epilogue pattern
                            // which should have MOV dword ptr [R8], or similar
                        }
                    }
                    
                    // Also check via descriptor value
                    try {
                        long descPtrVal = mem.getLong(toAddr(typeEntryAddr));
                        if (descPtrToTypeIdx.containsKey(descPtrVal)) {
                            int opcode = descPtrToTypeIdx.get(descPtrVal);
                            if (!opcodeSizes.containsKey(opcode)) {
                                jmpAccessors.put(opcode, hitAddr);
                            }
                        }
                    } catch (Exception e) {}
                }
            } catch (Exception e) {}
            
            search = search.add(1);
        }
        
        println("JMP-based accessors found: " + jmpAccessors.size());
        
        // Now look at ALL accessor addresses to find if they're in a function pointer table
        // Collect all accessor function start addresses
        TreeMap<Long, Integer> accessorStartToOpcode = new TreeMap<>();
        for (Map.Entry<Integer, Long> e : opcodeAddrs.entrySet()) {
            accessorStartToOpcode.put(e.getValue(), e.getKey());
        }
        for (Map.Entry<Integer, Long> e : jmpAccessors.entrySet()) {
            accessorStartToOpcode.put(e.getValue(), e.getKey());
        }
        
        if (!accessorStartToOpcode.isEmpty()) {
            out.println("# Accessor function addresses (for finding dispatch table):");
            long prevAddr = 0;
            for (Map.Entry<Long, Integer> e : accessorStartToOpcode.entrySet()) {
                long delta = prevAddr > 0 ? e.getKey() - prevAddr : 0;
                out.println(String.format("#   opcode %3d -> 0x%X (delta=%d)", e.getValue(), e.getKey(), delta));
                prevAddr = e.getKey();
            }
        }
        
        // OUTPUT FINAL TABLE
        out.println();
        out.println("# =============================================");
        out.println("# D3 2.8.0 (build 99920) OPCODE TABLE");
        out.println("# 155 opcodes (0-154), confirmed by CMP EDX,0x9B");
        out.println("# =============================================");
        out.println();
        
        int sizesFound = 0;
        for (int opc = 0; opc < 155; opc++) {
            String name = opcodeNames.getOrDefault(opc, "UNKNOWN_" + opc);
            Integer size = opcodeSizes.get(opc);
            
            String sizeStr = size != null ? String.format("//SIZE %d", size) : "//SIZE ?";
            if (size != null) sizesFound++;
            
            out.println(String.format("        %s = %d, %s", name, opc, sizeStr));
        }
        
        out.println();
        out.println("# Sizes found: " + sizesFound + " / 155");
        
        // List missing
        StringBuilder missing = new StringBuilder("# Missing sizes: ");
        for (int opc = 0; opc < 155; opc++) {
            if (!opcodeSizes.containsKey(opc)) {
                missing.append(opc).append("(").append(opcodeNames.getOrDefault(opc, "?")).append(") ");
            }
        }
        out.println(missing.toString());
        
        // List additional (non-type-table) accessors
        if (!descAddrToOpcodeSize.isEmpty()) {
            out.println();
            out.println("# Additional accessors pointing to descriptors outside type table:");
            for (Map.Entry<Long, int[]> e : descAddrToOpcodeSize.entrySet()) {
                out.println(String.format("#   at 0x%X -> type %d (%s), size %d", 
                    e.getKey(), e.getValue()[0], opcodeNames.getOrDefault(e.getValue()[0], "?"), e.getValue()[1]));
            }
        }
        
        out.flush();
        out.close();
        println("\nFinal output written to: " + outputPath);
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
