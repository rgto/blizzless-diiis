// Ghidra script to dump the common epilogue at 0x1408a8874
// and also try to extract sizes for JMP-based accessors
//@category D3

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.io.*;

public class DumpEpilogue extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\epilogue_dump.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Memory mem = currentProgram.getMemory();

        // Dump raw bytes at the common JMP target 0x1408a8874
        long epilogueAddr = 0x1408A8874L;
        out.println("=== Raw bytes at common epilogue 0x1408A8874 ===");
        for (int i = 0; i < 64; i++) {
            byte b = mem.getByte(toAddr(epilogueAddr + i));
            if (i % 16 == 0) {
                if (i > 0) out.println();
                out.printf("0x%X: ", epilogueAddr + i);
            }
            out.printf("%02X ", b & 0xFF);
        }
        out.println();

        // Try to manually decode common x86-64 from these bytes
        // Expected: MOV [RDX],RAX; LEA RAX,[rip+xx]; MOV dword [R8],<size>; MOV [R9],RAX; MOV EAX,1; RET
        
        // 48 89 02           = MOV [RDX], RAX
        // 48 8D 05 xx xx xx xx = LEA RAX, [rip+xx]
        // 41 C7 00 xx xx xx xx = MOV dword [R8], imm32
        // 49 89 01           = MOV [R9], RAX
        // B8 01 00 00 00     = MOV EAX, 1
        // C3                 = RET
        
        out.println("\n=== Manual decode ===");
        int off = 0;
        byte[] raw = new byte[64];
        for (int i = 0; i < 64; i++) {
            raw[i] = mem.getByte(toAddr(epilogueAddr + i));
        }
        
        // Check for MOV [RDX], RAX at offset 0
        if (raw[0] == 0x48 && raw[1] == (byte)0x89 && raw[2] == 0x02) {
            out.println("  +0: MOV [RDX], RAX");
            off = 3;
        }
        // Check for LEA RAX, [rip+xx]
        if (off < 60 && raw[off] == 0x48 && raw[off+1] == (byte)0x8D && raw[off+2] == 0x05) {
            int ripOff = (raw[off+3]&0xFF) | ((raw[off+4]&0xFF)<<8) | ((raw[off+5]&0xFF)<<16) | ((raw[off+6]&0xFF)<<24);
            long leaTarget = epilogueAddr + off + 7 + ripOff;
            out.printf("  +%d: LEA RAX, [rip+0x%X] -> 0x%X%n", off, ripOff, leaTarget);
            off += 7;
        }
        // Check for MOV dword [R8], imm32
        if (off < 60 && raw[off] == 0x41 && raw[off+1] == (byte)0xC7 && raw[off+2] == 0x00) {
            int size = (raw[off+3]&0xFF) | ((raw[off+4]&0xFF)<<8) | ((raw[off+5]&0xFF)<<16) | ((raw[off+6]&0xFF)<<24);
            out.printf("  +%d: MOV dword [R8], 0x%X (%d) <-- DEFAULT SIZE%n", off, size, size);
            off += 7;
        }
        
        out.println("\n=== Now trying different approach: check ALL JMP targets ===");
        
        // The JMP-based accessors might JMP to DIFFERENT targets, not all to 0x1408a8874
        // Let me scan all JMP accessors and group by target
        
        long typeTableBase = 0x1414051F8L;
        long scanStart = 0x1408A0000L;
        long scanEnd = 0x1408C0000L;
        
        // Collect all known descriptor pointers
        Map<Long, Integer> descPtrToTypeIdx = new HashMap<>();
        Map<Integer, String> opcodeNames = new TreeMap<>();
        for (int i = 0; i < 155; i++) {
            try {
                long descPtr = mem.getLong(toAddr(typeTableBase + (long) i * 8));
                descPtrToTypeIdx.put(descPtr, i);
                long namePtr = mem.getLong(toAddr(descPtr + 8));
                if (namePtr >= 0x140000000L && namePtr <= 0x142000000L) {
                    String name = readString(mem, toAddr(namePtr));
                    if (name != null) opcodeNames.put(i, name);
                }
            } catch (Exception e) {}
        }
        
        // Find all JMP-based accessors: pattern "48 8B 05 xx xx xx xx E9 xx xx xx xx"
        byte[] movRaxPattern = new byte[]{0x48, (byte)0x8B, 0x05};
        Address search = toAddr(scanStart);
        
        Map<Long, List<int[]>> targetToAccessors = new TreeMap<>(); // jmp_target -> list of [opcode, accessor_addr]
        
        while (search != null && search.getOffset() < scanEnd && !monitor.isCancelled()) {
            search = mem.findBytes(search, movRaxPattern, null, true, monitor);
            if (search == null || search.getOffset() >= scanEnd) break;
            long hitAddr = search.getOffset();
            
            try {
                byte afterByte = mem.getByte(toAddr(hitAddr + 7));
                if (afterByte == (byte)0xE9) {
                    // JMP-based accessor
                    int ripOffset = mem.getInt(toAddr(hitAddr + 3));
                    long typeEntryAddr = hitAddr + 7 + ripOffset;
                    
                    int jmpOffset = mem.getInt(toAddr(hitAddr + 8));
                    long jmpTarget = hitAddr + 12 + jmpOffset;
                    
                    int opcode = -1;
                    // Direct type table reference
                    long tblOff = typeEntryAddr - typeTableBase;
                    if (tblOff >= 0 && tblOff % 8 == 0 && tblOff / 8 < 155) {
                        opcode = (int)(tblOff / 8);
                    }
                    // Indirect via descriptor pointer
                    if (opcode < 0) {
                        try {
                            long descVal = mem.getLong(toAddr(typeEntryAddr));
                            if (descPtrToTypeIdx.containsKey(descVal)) {
                                opcode = descPtrToTypeIdx.get(descVal);
                            }
                        } catch (Exception e) {}
                    }
                    
                    if (opcode >= 0) {
                        targetToAccessors.computeIfAbsent(jmpTarget, k -> new ArrayList<>())
                            .add(new int[]{opcode, (int)(hitAddr & 0xFFFFFFFFL)});
                    }
                }
            } catch (Exception e) {}
            
            search = search.add(1);
        }
        
        out.println("JMP targets found: " + targetToAccessors.size());
        for (Map.Entry<Long, List<int[]>> entry : targetToAccessors.entrySet()) {
            long target = entry.getKey();
            List<int[]> accessors = entry.getValue();
            
            out.printf("\nJMP target 0x%X (%d accessors):%n", target, accessors.size());
            
            // Read the size from the target
            // Expected pattern at target: MOV [RDX],RAX; LEA; MOV [R8],size; ...
            int size = -1;
            try {
                // Check bytes at target
                for (int checkOff = 0; checkOff < 30; checkOff++) {
                    byte b0 = mem.getByte(toAddr(target + checkOff));
                    byte b1 = mem.getByte(toAddr(target + checkOff + 1));
                    byte b2 = mem.getByte(toAddr(target + checkOff + 2));
                    if (b0 == 0x41 && b1 == (byte)0xC7 && b2 == 0x00) {
                        size = mem.getInt(toAddr(target + checkOff + 3));
                        out.printf("  SIZE = %d (0x%X) at target+%d%n", size, size, checkOff);
                        break;
                    }
                }
            } catch (Exception e) {}
            
            for (int[] acc : accessors) {
                String name = opcodeNames.getOrDefault(acc[0], "?");
                out.printf("  opcode %3d = %s%n", acc[0], name);
            }
        }
        
        out.flush();
        out.close();
        println("Output written to: " + outputPath);
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
        } catch (Exception e) { return null; }
    }
}
