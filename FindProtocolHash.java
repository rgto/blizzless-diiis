// Ghidra script to find references to the "ProtocolHash" string  
// and examine nearby constants that could be the protocol hash value
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class FindProtocolHash extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outPath = "C:/Users/Beroli/Downloads/D32.8.9-extracted/ghidra_analysis.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        
        // Search for "Server ProtocolHash" string in memory
        byte[] pattern = "Server ProtocolHash".getBytes("ASCII");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), pattern, null, true, monitor);
        
        if (addr != null) {
            pw.println("Found 'Server ProtocolHash' string at: " + addr);
            
            // Find all references to this string address
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            Reference[] refs = getReferencesTo(addr);
            pw.println("References to this string: " + refs.length);
            
            for (Reference ref : refs) {
                Address fromAddr = ref.getFromAddress();
                pw.println("  Referenced from: " + fromAddr);
                
                // Print instructions around the reference
                Instruction instr = listing.getInstructionAt(fromAddr);
                if (instr != null) {
                    // Print 30 instructions before and after
                    Instruction prev = instr;
                    for (int i = 0; i < 30; i++) {
                        Instruction p = prev.getPrevious();
                        if (p == null) break;
                        prev = p;
                    }
                    // Now print from prev to 60 instr forward
                    Instruction cur = prev;
                    for (int i = 0; i < 60 && cur != null; i++) {
                        pw.println("    " + cur.getAddress() + ": " + cur);
                        cur = cur.getNext();
                    }
                }
            }
        } else {
            pw.println("'Server ProtocolHash' string NOT found");
        }
        
        pw.println("\n=== Searching for 'Client SNOPackHash' ===");
        byte[] pattern2 = "Client SNOPackHash".getBytes("ASCII");
        Address addr2 = mem.findBytes(currentProgram.getMinAddress(), pattern2, null, true, monitor);
        if (addr2 != null) {
            pw.println("Found 'Client SNOPackHash' at: " + addr2);
            Reference[] refs2 = getReferencesTo(addr2);
            pw.println("References: " + refs2.length);
            for (Reference ref : refs2) {
                Address fromAddr = ref.getFromAddress();
                pw.println("  Referenced from: " + fromAddr);
                Instruction instr = listing.getInstructionAt(fromAddr);
                if (instr != null) {
                    Instruction prev = instr;
                    for (int i = 0; i < 30; i++) {
                        Instruction p = prev.getPrevious();
                        if (p == null) break;
                        prev = p;
                    }
                    Instruction cur = prev;
                    for (int i = 0; i < 60 && cur != null; i++) {
                        pw.println("    " + cur.getAddress() + ": " + cur);
                        cur = cur.getNext();
                    }
                }
            }
        }
        
        // Also search for "ProtocolMismatchText" 
        pw.println("\n=== Searching for 'ProtocolMismatchText' ===");
        byte[] pattern3 = "ProtocolMismatchText".getBytes("ASCII");
        Address addr3 = mem.findBytes(currentProgram.getMinAddress(), pattern3, null, true, monitor);
        if (addr3 != null) {
            pw.println("Found 'ProtocolMismatchText' at: " + addr3);
        }
        
        pw.println("\n=== Done ===");
        pw.close();
        println("Analysis written to: " + outPath);
    }
}
