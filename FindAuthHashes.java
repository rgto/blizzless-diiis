// Ghidra script to find auth module hashes
// The auth handler sends module descriptor with a SHA256 hash
// The client has hardcoded accepted hashes
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class FindAuthHashes extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outPath = "C:/Users/Beroli/Downloads/D32.8.9-extracted/auth_hashes.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        
        // Current known hashes from the 2.7.4 server code (VersionInfo.cs):
        // Password: 8f52906a2c85b416a595702251570f96d3522f39237603115f2f1ab24962043c
        // SSO:      8e86fbdd1ee515315e9e3e1b479b7889de1eceda0703d9876f9441ce4d934576
        // Thumbprint: 36b27cd911b33c61730a8b82c8b2495fd16e8024fc3b2dde08861c77a852941c
        // Token:    bfa574bcff509b3c92f7c4b25b2dc2d1decb962209f8c9c8582ddf4f26aac176
        // Risk:     5e298e530698af905e1247e51ef0b109b352ac310ce7802a1f63613db980ed17
        // Agreement: 41686a009b345b9cbe622ded9c669373950a2969411012a12f7eaac7ea9826ed
        
        // Search for these known hash bytes in the binary to identify the auth hash table
        // Password hash first 4 bytes: 0x8f, 0x52, 0x90, 0x6a
        String[] hashNames = {"Password", "SSO", "Thumbprint", "Token", "RiskFingerprint", "Agreement"};
        String[] knownHashes = {
            "8f52906a2c85b416a595702251570f96d3522f39237603115f2f1ab24962043c",
            "8e86fbdd1ee515315e9e3e1b479b7889de1eceda0703d9876f9441ce4d934576",
            "36b27cd911b33c61730a8b82c8b2495fd16e8024fc3b2dde08861c77a852941c",
            "bfa574bcff509b3c92f7c4b25b2dc2d1decb962209f8c9c8582ddf4f26aac176",
            "5e298e530698af905e1247e51ef0b109b352ac310ce7802a1f63613db980ed17",
            "41686a009b345b9cbe622ded9c669373950a2969411012a12f7eaac7ea9826ed"
        };
        
        for (int h = 0; h < knownHashes.length; h++) {
            String hexHash = knownHashes[h];
            byte[] hashBytes = new byte[32];
            for (int i = 0; i < 32; i++) {
                hashBytes[i] = (byte) Integer.parseInt(hexHash.substring(i*2, i*2+2), 16);
            }
            
            pw.println("=== Searching for " + hashNames[h] + " hash: " + hexHash + " ===");
            
            // Search for the raw bytes in memory
            Address found = mem.findBytes(currentProgram.getMinAddress(), hashBytes, null, true, monitor);
            if (found != null) {
                pw.println("  FOUND at address: " + found);
                // Dump 256 bytes of context
                byte[] context = new byte[256];
                mem.getBytes(found, context);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 256; i++) {
                    sb.append(String.format("%02x", context[i] & 0xFF));
                    if (i % 32 == 31) sb.append("\n    ");
                }
                pw.println("  Context (256 bytes from found address):\n    " + sb.toString());
                
                // Also check what's 32 bytes before (in case there's a structure)
                Address before = found.subtract(64);
                byte[] beforeContext = new byte[64];
                try {
                    mem.getBytes(before, beforeContext);
                    StringBuilder sb2 = new StringBuilder();
                    for (int i = 0; i < 64; i++) {
                        sb2.append(String.format("%02x", beforeContext[i] & 0xFF));
                        if (i % 32 == 31) sb2.append("\n    ");
                    }
                    pw.println("  64 bytes BEFORE:\n    " + sb2.toString());
                } catch (Exception e) {}
                
                // Check for references
                Reference[] refs = getReferencesTo(found);
                pw.println("  References: " + refs.length);
                for (Reference ref : refs) {
                    pw.println("    From: " + ref.getFromAddress() + " [" + ref.getReferenceType() + "]");
                }
            } else {
                pw.println("  NOT FOUND - hash may have changed in 2.8.0");
            }
            pw.println();
        }
        
        // Also search for CAuthHandler string to find the auth framework
        pw.println("\n=== Searching for CAuthHandler references ===");
        byte[] authPattern = "CAuthHandler".getBytes("ASCII");
        Address authAddr = mem.findBytes(currentProgram.getMinAddress(), authPattern, null, true, monitor);
        while (authAddr != null) {
            pw.println("  Found 'CAuthHandler' at: " + authAddr);
            authAddr = mem.findBytes(authAddr.add(1), authPattern, null, true, monitor);
        }
        
        pw.println("\n=== Done ===");
        pw.close();
        println("Auth hash analysis written to: " + outPath);
    }
}
