// Debug script to see actual instruction format for known accessor functions
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class DebugInsn extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\debug_insn.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Listing listing = currentProgram.getListing();
        
        // Dump instructions around the known VersionsMessage accessor at 0x1408A6F4A
        out.println("=== Instructions around 0x1408A6F4A (VersionsMessage accessor) ===");
        long addr = 0x1408A6F30L;
        Instruction insn = listing.getInstructionAt(toAddr(addr));
        if (insn == null) insn = listing.getInstructionAfter(toAddr(addr));
        
        for (int i = 0; i < 30 && insn != null; i++) {
            out.println(String.format("  0x%X: mnemonic='%s' toString='%s' numOps=%d",
                insn.getAddress().getOffset(),
                insn.getMnemonicString(),
                insn.toString(),
                insn.getNumOperands()));
            
            // Show operand details
            for (int op = 0; op < insn.getNumOperands(); op++) {
                Object[] opObjs = insn.getOpObjects(op);
                StringBuilder sb = new StringBuilder();
                for (Object o : opObjs) {
                    sb.append(String.format(" [%s:%s]", o.getClass().getSimpleName(), o.toString()));
                }
                out.println(String.format("    op%d: repr='%s' objects=%s", op, insn.getDefaultOperandRepresentation(op), sb.toString()));
            }
            
            insn = insn.getNext();
        }
        
        // Also check the entry 1 accessor at 0x1408A8072
        out.println("\n=== Instructions around 0x1408A8072 (entry 1 accessor) ===");
        insn = listing.getInstructionAt(toAddr(0x1408A8060L));
        if (insn == null) insn = listing.getInstructionAfter(toAddr(0x1408A8060L));
        for (int i = 0; i < 20 && insn != null; i++) {
            out.println(String.format("  0x%X: mnemonic='%s' toString='%s'",
                insn.getAddress().getOffset(),
                insn.getMnemonicString(),
                insn.toString()));
            insn = insn.getNext();
        }
        
        // Check the QuitGameMessage accessor at 0x1408A6E78
        out.println("\n=== Instructions around 0x1408A6E78 (entry 75 QuitGameMessage) ===");
        insn = listing.getInstructionAt(toAddr(0x1408A6E68L));
        if (insn == null) insn = listing.getInstructionAfter(toAddr(0x1408A6E68L));
        for (int i = 0; i < 20 && insn != null; i++) {
            out.println(String.format("  0x%X: mnemonic='%s' toString='%s'",
                insn.getAddress().getOffset(),
                insn.getMnemonicString(),
                insn.toString()));
            insn = insn.getNext();
        }
        
        out.flush();
        out.close();
        println("Debug output written to: " + outputPath);
    }
}
