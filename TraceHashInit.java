// Ghidra script to find where the ProtocolHash structure is populated
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class TraceHashInit extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outPath = "C:/Users/Beroli/Downloads/D32.8.9-extracted/hash_init_trace.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        Listing listing = currentProgram.getListing();
        
        // Find all references to global 0x1416f64d8 (ProtocolHash pointer)
        Address globalAddr = toAddr(0x1416f64d8L);
        pw.println("=== References to 0x1416f64d8 (ProtocolHash ptr) ===");
        Reference[] refs = getReferencesTo(globalAddr);
        pw.println("Total references: " + refs.length);
        for (Reference ref : refs) {
            Address from = ref.getFromAddress();
            Instruction instr = listing.getInstructionAt(from);
            String instrStr = instr != null ? instr.toString() : "N/A";
            pw.println("  " + from + ": " + instrStr + " [" + ref.getReferenceType() + "]");
        }
        
        // For each reference, dump context to see if it's a WRITE (MOV [ptr], ...)
        pw.println("\n=== Context for WRITE references ===");
        for (Reference ref : refs) {
            Address from = ref.getFromAddress();
            Instruction instr = listing.getInstructionAt(from);
            if (instr != null) {
                String instrStr = instr.toString();
                // Look for writes (MOV [xxx], ... patterns)
                if (instrStr.contains("MOV") && instrStr.contains("[0x1416f64d8]") && !instrStr.startsWith("MOV RAX,")) {
                    pw.println("\n  WRITE at " + from + ": " + instrStr);
                    // Dump context
                    Instruction cur = instr;
                    for (int i = 0; i < 20; i++) {
                        Instruction p = cur.getPrevious();
                        if (p == null) break;
                        cur = p;
                    }
                    for (int i = 0; i < 40 && cur != null; i++) {
                        String mark = cur.getAddress().equals(from) ? " <<< WRITE" : "";
                        pw.println("    " + cur.getAddress() + ": " + cur + mark);
                        cur = cur.getNext();
                    }
                }
            }
        }
        
        // Also check the ProtocolHash function callers more carefully
        // Look at 1407d4b21 - the first caller of 0x1408a6050
        pw.println("\n=== Caller at 0x1407d4b21 context (first caller of ProtocolHash func) ===");
        dumpContext(pw, listing, 0x1407d4b21L, 30, 30);
        
        // Check 1404e5f9b
        pw.println("\n=== Caller at 0x1404e5f9b context ===");
        dumpContext(pw, listing, 0x1404e5f9bL, 30, 30);
        
        pw.println("\n=== Done ===");
        pw.close();
        println("Trace written to: " + outPath);
    }
    
    private void dumpContext(PrintWriter pw, Listing listing, long addr, int before, int after) {
        Address targetAddr = toAddr(addr);
        Instruction instr = listing.getInstructionAt(targetAddr);
        if (instr == null) { pw.println("  No instruction"); return; }
        
        Instruction cur = instr;
        for (int i = 0; i < before; i++) {
            Instruction p = cur.getPrevious();
            if (p == null) break;
            cur = p;
        }
        for (int i = 0; i < before + after + 1 && cur != null; i++) {
            String mark = cur.getAddress().equals(targetAddr) ? " <<<" : "";
            pw.println("    " + cur.getAddress() + ": " + cur + mark);
            cur = cur.getNext();
        }
    }
}
