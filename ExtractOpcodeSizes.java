// Ghidra script to extract opcode sizes from accessor functions in D3 2.8.0
// Known: accessor functions are in region ~0x1408A6000-0x1408A9000
// Pattern: MOV RAX, [type_table_entry]; MOV [RDX], RAX; ...; MOV dword ptr [R8], <size>
// The type table entry address reveals which opcode it is (index = opcode)
// The immediate value for R8 gives the message size
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.util.*;
import java.io.*;

public class ExtractOpcodeSizes extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\opcodes_280_final.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        long typeTableBase = 0x1414051F8L;
        
        // First, build opcode->name map from type table
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

        // Scan the accessor function region for patterns
        // We know accessor functions for specific opcodes are at:
        //   0x1408A8072 → entry 1 = 0x141405200
        //   0x1408A6F4A → entry 20 = 0x141405298
        //   0x1408A869F → entry 51 = 0x141405390
        //   0x1408A6E78 → entry 75 = 0x141405450
        // Scan a wider region: 0x1408A5000 to 0x1408B0000
        
        long scanStart = 0x1408A5000L;
        long scanEnd = 0x1408B0000L;
        
        Map<Integer, Integer> opcodeSizes = new TreeMap<>();
        Map<Integer, Long> opcodeAccessorAddrs = new TreeMap<>();
        
        // Strategy: iterate through all instructions in the region
        // Look for MOV dword ptr [R8], <imm32> instructions
        // Then backtrack to find which type table entry was loaded
        
        out.println("# D3 2.8.0 (build 99920) Opcode Table with Sizes");
        out.println("# Extracted from Diablo III64.exe accessor functions");
        out.println();
        
        Instruction insn = listing.getInstructionAt(toAddr(scanStart));
        if (insn == null) {
            insn = listing.getInstructionAfter(toAddr(scanStart));
        }
        
        int accessorCount = 0;
        
        while (insn != null && insn.getAddress().getOffset() < scanEnd) {
            if (monitor.isCancelled()) break;
            
            String mnemonic = insn.getMnemonicString();
            String insnStr = insn.toString();
            
            // Look for MOV dword ptr [R8],<imm>  or  MOV dword ptr [R8 + ...], <imm>
            // The pattern for size assignment
            if (mnemonic.equals("MOV") && insnStr.contains("[R8]") && insnStr.contains(",0x")) {
                // Found a size assignment - extract the immediate value
                // Pattern: "MOV dword ptr [R8],0x30"
                int sizeVal = -1;
                try {
                    String hexStr = insnStr.substring(insnStr.lastIndexOf("0x") + 2);
                    sizeVal = Integer.parseInt(hexStr.trim(), 16);
                } catch (Exception e) {
                    try {
                        // Also try decimal
                        Object[] opObjects = insn.getOpObjects(1);
                        if (opObjects.length > 0) {
                            sizeVal = ((Number) opObjects[0]).intValue();
                        }
                    } catch (Exception e2) {}
                }
                
                if (sizeVal > 0 && sizeVal < 100000) {
                    // Backtrack to find the type table entry load
                    // Look for MOV RAX, qword ptr [0x14140xxxx] within ~20 instructions before
                    int opcode = -1;
                    Instruction prevInsn = insn;
                    for (int back = 0; back < 30; back++) {
                        prevInsn = listing.getInstructionBefore(prevInsn.getAddress());
                        if (prevInsn == null) break;
                        
                        String prevStr = prevInsn.toString();
                        if (prevStr.contains("qword ptr [0x14140")) {
                            // Extract the address
                            try {
                                int idx = prevStr.indexOf("0x14140");
                                String addrStr = prevStr.substring(idx + 2, idx + 2 + 11);
                                long tableAddr = Long.parseLong(addrStr, 16);
                                
                                // Calculate opcode index
                                long offset = tableAddr - typeTableBase;
                                if (offset >= 0 && offset % 8 == 0 && offset / 8 < 155) {
                                    opcode = (int) (offset / 8);
                                    break;
                                }
                            } catch (Exception e) {}
                        }
                    }
                    
                    if (opcode >= 0) {
                        opcodeSizes.put(opcode, sizeVal);
                        opcodeAccessorAddrs.put(opcode, insn.getAddress().getOffset());
                        accessorCount++;
                    }
                }
            }
            
            insn = listing.getInstructionAfter(insn.getAddress());
        }
        
        println("Found " + accessorCount + " accessor functions with sizes");
        
        // Also scan for functions that use MOV dword ptr [R8 + 0], <size> (different encoding)
        // And for functions outside the initial scan range
        // Let me also check the broader range 0x14008xxxx - 0x1400Fxxxx
        
        if (accessorCount < 100) {
            println("Expanding search to broader code region...");
            long scanStart2 = 0x1400F0000L;
            long scanEnd2 = 0x1400FFFFFL;
            
            insn = listing.getInstructionAt(toAddr(scanStart2));
            if (insn == null) insn = listing.getInstructionAfter(toAddr(scanStart2));
            
            while (insn != null && insn.getAddress().getOffset() < scanEnd2) {
                if (monitor.isCancelled()) break;
                String insnStr = insn.toString();
                
                if (insn.getMnemonicString().equals("MOV") && insnStr.contains("[R8]") && insnStr.contains(",0x")) {
                    int sizeVal = -1;
                    try {
                        String hexStr = insnStr.substring(insnStr.lastIndexOf("0x") + 2);
                        sizeVal = Integer.parseInt(hexStr.trim(), 16);
                    } catch (Exception e) {}
                    
                    if (sizeVal > 0 && sizeVal < 100000) {
                        Instruction prevInsn = insn;
                        for (int back = 0; back < 30; back++) {
                            prevInsn = listing.getInstructionBefore(prevInsn.getAddress());
                            if (prevInsn == null) break;
                            String prevStr = prevInsn.toString();
                            if (prevStr.contains("qword ptr [0x14140")) {
                                try {
                                    int idx = prevStr.indexOf("0x14140");
                                    String addrStr = prevStr.substring(idx + 2, idx + 2 + 11);
                                    long tableAddr = Long.parseLong(addrStr, 16);
                                    long offset = tableAddr - typeTableBase;
                                    if (offset >= 0 && offset % 8 == 0 && offset / 8 < 155) {
                                        int opc = (int) (offset / 8);
                                        if (!opcodeSizes.containsKey(opc)) {
                                            opcodeSizes.put(opc, sizeVal);
                                            opcodeAccessorAddrs.put(opc, insn.getAddress().getOffset());
                                            accessorCount++;
                                        }
                                        break;
                                    }
                                } catch (Exception e) {}
                            }
                        }
                    }
                }
                insn = listing.getInstructionAfter(insn.getAddress());
            }
        }
        
        println("Total accessor functions found: " + accessorCount);
        
        // Output the final table
        out.println("# FINAL OPCODE TABLE - D3 2.8.0 (build 99920)");
        out.println("# Opcodes: 0 to 154 (155 total, confirmed by CMP EDX,0x9B bounds check)");
        out.println("# VersionsMessage at opcode 20, size 48 (matches 2.7.4)");
        out.println();
        
        for (int opc = 0; opc < 155; opc++) {
            String name = opcodeNames.getOrDefault(opc, "UNKNOWN_" + opc);
            Integer size = opcodeSizes.get(opc);
            
            String sizeStr = size != null ? String.format(" //SIZE %d", size) : "";
            Long accAddr = opcodeAccessorAddrs.get(opc);
            String addrStr = accAddr != null ? String.format(" @0x%X", accAddr) : "";
            
            out.println(String.format("%s = %d,%s%s", name, opc, sizeStr, addrStr));
        }
        
        out.println();
        out.println("# Sizes found: " + opcodeSizes.size() + " / 155");
        out.println("# Missing sizes: ");
        for (int opc = 0; opc < 155; opc++) {
            if (!opcodeSizes.containsKey(opc)) {
                out.print(opc + "(" + opcodeNames.getOrDefault(opc, "?") + ") ");
            }
        }
        out.println();
        
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
        } catch (Exception e) {
            return null;
        }
    }
}
