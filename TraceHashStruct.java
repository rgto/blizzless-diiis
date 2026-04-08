// Trace the ProtocolHash structure initialization function 0x1408c22d0
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class TraceHashStruct extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outPath = "C:/Users/Beroli/Downloads/D32.8.9-extracted/hash_struct_trace.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        Listing listing = currentProgram.getListing();
        
        // 0x1408c22d0 is called right after the struct is allocated and pointer stored
        // It likely initializes the struct including writing the protocol hash at offset 0x24
        pw.println("=== Function 0x1408c22d0 (struct initializator) ===");
        dumpInstructions(pw, listing, 0x1408c22d0L, 200);
        
        // Also check 0x1404e4f00 which is called right after
        pw.println("\n=== Function 0x1404e4f00 (called after init) ===");
        dumpInstructions(pw, listing, 0x1404e4f00L, 100);
        
        pw.println("\n=== Done ===");
        pw.close();
        println("Written to: " + outPath);
    }
    
    private void dumpInstructions(PrintWriter pw, Listing listing, long addr, int maxCount) {
        Address startAddr = toAddr(addr);
        Instruction instr = listing.getInstructionAt(startAddr);
        if (instr == null) { pw.println("  No instruction at address"); return; }
        int retCount = 0;
        for (int i = 0; i < maxCount && instr != null; i++) {
            pw.println("  " + instr.getAddress() + ": " + instr);
            if (instr.getMnemonicString().equals("RET")) {
                retCount++;
                if (retCount >= 1) { pw.println("  --- END ---"); break; }
            }
            instr = instr.getNext();
        }
    }
}
