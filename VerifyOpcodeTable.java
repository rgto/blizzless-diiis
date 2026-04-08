// Ghidra script to verify: is the type table index = wire opcode?
// Find code xrefs to the type table base address (0x1414051F8)
// and check how the index is computed and used.
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.io.*;

public class VerifyOpcodeTable extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\verify_opcodes.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        // The type table starts at 0x1414051F8
        // Each entry is 8 bytes (pointer to descriptor)
        // If this is the opcode table, code should reference this base address
        // typically like: LEA reg, [0x1414051F8] or MOV reg, [0x1414051F8 + index*8]
        
        long tableBase = 0x1414051F8L;
        
        // Search for the table base in code (as part of LEA/MOV instructions)
        // The address might appear as RIP-relative or absolute
        out.println("=== Looking for code references to type table base 0x" + Long.toHexString(tableBase) + " ===");
        
        // Approach: Search for the bytes of the address in the code section
        // Also search for addresses within the table (base to base+155*8)
        
        // First, find xrefs in Ghidra's reference database
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Address tableAddr = toAddr(tableBase);
        
        out.println("\n# Ghidra xrefs TO table base:");
        ReferenceIterator refIter = refMgr.getReferencesTo(tableAddr);
        int refCount = 0;
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Address fromAddr = ref.getFromAddress();
            out.println(String.format("  FROM 0x%X type=%s", fromAddr.getOffset(), ref.getReferenceType()));
            
            // Dump instructions around this reference
            for (int i = -5; i <= 5; i++) {
                Instruction insn = listing.getInstructionAt(fromAddr.add(i * 4)); // approximate
                if (insn == null) {
                    // Try actual listing
                    CodeUnit cu = listing.getCodeUnitContaining(fromAddr.add(i * 4));
                    if (cu instanceof Instruction) insn = (Instruction) cu;
                }
                if (insn != null) {
                    String mark = insn.getAddress().equals(fromAddr) ? " <<<" : "";
                    out.println(String.format("    0x%X: %s%s", insn.getAddress().getOffset(), insn.toString(), mark));
                }
            }
            refCount++;
        }
        out.println("Total refs to table base: " + refCount);
        
        // Also check xrefs to nearby addresses (entry 0, entry 1, VersionsMessage entry)
        long[] checkAddrs = new long[]{
            tableBase,          // base
            tableBase + 8,      // entry 1
            tableBase + 20*8,   // entry 20 (VersionsMessage) 
            tableBase + 51*8,   // entry 51 (SimpleMessage)
            tableBase + 75*8,   // entry 75 (QuitGameMessage)
        };
        
        for (long addr : checkAddrs) {
            out.println(String.format("\n# Xrefs to 0x%X:", addr));
            ReferenceIterator iter = refMgr.getReferencesTo(toAddr(addr));
            while (iter.hasNext()) {
                Reference ref = iter.next();
                out.println(String.format("  FROM 0x%X type=%s", ref.getFromAddress().getOffset(), ref.getReferenceType()));
            }
        }
        
        // Approach 2: Find the message PARSING function
        // In client code, there should be a function like:
        //   int opcode = readBits(buffer, 10);
        //   descriptor* desc = typeTable[opcode];
        //   msg = desc->vtable->create();
        // Look for instructions that load from [tableBase + reg*8]
        
        out.println("\n\n=== Looking for the message factory/parser function ===");
        
        // Search for instructions near the type table that do indexed loads
        // The pattern would be: LEA rax, [rip+offset_to_table]; MOV rax, [rax+rcx*8]
        // or similar
        
        // Let me search for LEA instructions that reference the table
        // by checking all instructions in the code section
        
        // Alternative: look at the function that SETS UP the type table
        // The descriptors at 0x141408xxx must be referenced by initialization code
        
        // Check first descriptor at 0x1414080D0 (entry 1 = EncounterInviteStateMessage)
        out.println("\n# Xrefs to first descriptor (0x1414080D0):");
        ReferenceIterator iter = refMgr.getReferencesTo(toAddr(0x1414080D0L));
        while (iter.hasNext()) {
            Reference ref = iter.next();
            out.println(String.format("  FROM 0x%X type=%s", ref.getFromAddress().getOffset(), ref.getReferenceType()));
        }
        
        // Check VersionsMessage descriptor (0x141408910)
        out.println("\n# Xrefs to VersionsMessage descriptor (0x141408910):");
        iter = refMgr.getReferencesTo(toAddr(0x141408910L));
        while (iter.hasNext()) {
            Reference ref = iter.next();
            Address fromAddr = ref.getFromAddress();
            out.println(String.format("  FROM 0x%X type=%s", fromAddr.getOffset(), ref.getReferenceType()));
            // Dump surrounding instructions
            for (int i = -3; i <= 3; i++) {
                Instruction insn = listing.getInstructionContaining(fromAddr.add(i * 4));
                if (insn != null) {
                    out.println(String.format("    0x%X: %s", insn.getAddress().getOffset(), insn.toString()));
                }
            }
        }
        
        // APPROACH 3: The most direct way - look for the number 155 or 0x9B near the table
        out.println("\n\n=== Searching for bounds check (value 155/0x9B) near type table references ===");
        
        // Search for CMP reg, 155 in code
        // CMP EAX, 0x9B = 3D 9B 00 00 00
        // CMP ECX, 0x9B = 81 F9 9B 00 00 00
        // CMP EDX, 0x9B = 81 FA 9B 00 00 00  
        byte[][] cmpPatterns = {
            {0x3D, (byte)0x9B, 0x00, 0x00, 0x00},  // CMP EAX, 155
            {(byte)0x81, (byte)0xF9, (byte)0x9B, 0x00, 0x00, 0x00},  // CMP ECX, 155
            {(byte)0x81, (byte)0xFA, (byte)0x9B, 0x00, 0x00, 0x00},  // CMP EDX, 155
            {(byte)0x83, (byte)0xF8, (byte)0x9B},  // CMP EAX, 0x9B (sign-extended)
            {(byte)0x83, (byte)0xF9, (byte)0x9B},  // CMP ECX, 0x9B
            {(byte)0x83, (byte)0xFA, (byte)0x9B},  // CMP EDX, 0x9B
        };
        
        for (byte[] pattern : cmpPatterns) {
            Address found = mem.getMinAddress();
            while (found != null && !monitor.isCancelled()) {
                found = mem.findBytes(found, pattern, null, true, monitor);
                if (found != null) {
                    // Check if this is in code section (roughly 0x140001000 to 0x140F00000)
                    long fOff = found.getOffset();
                    if (fOff >= 0x140001000L && fOff <= 0x140F00000L) {
                        Instruction insn = listing.getInstructionContaining(found);
                        if (insn != null) {
                            out.println(String.format("  CMP at 0x%X: %s", fOff, insn.toString()));
                            // Dump surrounding context
                            Address ctx = insn.getAddress();
                            for (int i = -3; i <= 3; i++) {
                                Instruction nearby = listing.getInstructionContaining(ctx.add(i * 4));
                                if (nearby != null && !nearby.getAddress().equals(insn.getAddress())) {
                                    out.println(String.format("    0x%X: %s", nearby.getAddress().getOffset(), nearby.toString()));
                                }
                            }
                        }
                    }
                    found = found.add(1);
                }
            }
        }
        
        out.flush();
        out.close();
        println("Output written to: " + outputPath);
    }
}
