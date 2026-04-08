// Ghidra script to analyze the ProtocolHash and SNOPackHash computation functions
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.io.*;

public class AnalyzeHashFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outPath = "C:/Users/Beroli/Downloads/D32.8.9-extracted/hash_functions.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        Listing listing = currentProgram.getListing();
        
        // Function that returns ProtocolHash
        pw.println("=== ProtocolHash function at 0x1408a6050 ===");
        dumpInstructions(pw, listing, 0x1408a6050L, 100);
        
        pw.println("\n=== SNOPackHash function at 0x1406e0c70 ===");
        dumpInstructions(pw, listing, 0x1406e0c70L, 100);
        
        // Also check global variable at 0x1416ea120 where protocol hash is stored
        pw.println("\n=== Global at 0x1416ea120 (ProtocolHash storage) ===");
        Memory mem = currentProgram.getMemory();
        Address globalAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1416ea120L);
        try {
            int val = mem.getInt(globalAddr);
            pw.println("Value at 0x1416ea120: 0x" + Integer.toHexString(val) + " (" + val + ")");
        } catch (Exception e) {
            pw.println("Cannot read value: " + e.getMessage());
        }
        
        // Check what calls 0x1408a6050 elsewhere - maybe it's initialized
        pw.println("\n=== References to 0x1408a6050 ===");
        Address funcAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1408a6050L);
        var refs = getReferencesTo(funcAddr);
        for (var ref : refs) {
            pw.println("  Called from: " + ref.getFromAddress());
        }
        
        pw.println("\n=== Done ===");
        pw.close();
        println("Hash analysis written to: " + outPath);
    }
    
    private void dumpInstructions(PrintWriter pw, Listing listing, long addr, int count) {
        Address startAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
        Instruction instr = listing.getInstructionAt(startAddr);
        if (instr == null) {
            pw.println("No instruction at address");
            return;
        }
        for (int i = 0; i < count && instr != null; i++) {
            pw.println("  " + instr.getAddress() + ": " + instr);
            // If we hit a RET, we're done with this function
            String mnemonic = instr.getMnemonicString();
            if (mnemonic.equals("RET") && i > 0) {
                pw.println("  --- END OF FUNCTION ---");
                break;
            }
            instr = instr.getNext();
        }
    }
}
