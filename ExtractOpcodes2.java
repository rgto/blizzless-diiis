// Ghidra script to extract opcode table from Diablo III 2.8.0
// Based on discovery: message descriptors have a common vtable pointer at offset 0,
// name string pointer at offset +8, with stride of 0x60 (96) bytes.
// The vtable pointer 0x140FCE828 is shared by all message descriptors.
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.io.*;

public class ExtractOpcodes2 extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\opcodes_output2.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        Memory mem = currentProgram.getMemory();
        
        // Known vtable pointer from calibration
        long vtablePtr = 0x140FCE828L;
        byte[] vtableBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            vtableBytes[i] = (byte) ((vtablePtr >> (i * 8)) & 0xFF);
        }
        
        // Step 1: Find ALL occurrences of this vtable pointer in the binary
        println("=== Searching for vtable pointer 0x" + Long.toHexString(vtablePtr) + " ===");
        out.println("=== Searching for vtable pointer 0x" + Long.toHexString(vtablePtr) + " ===");
        
        List<Address> vtableHits = new ArrayList<>();
        Address searchAddr = mem.getMinAddress();
        while (searchAddr != null && !monitor.isCancelled()) {
            searchAddr = mem.findBytes(searchAddr, vtableBytes, null, true, monitor);
            if (searchAddr != null) {
                vtableHits.add(searchAddr);
                searchAddr = searchAddr.add(1);
            }
        }
        
        println("Found " + vtableHits.size() + " vtable pointer instances");
        out.println("Found " + vtableHits.size() + " vtable pointer instances");
        
        // Step 2: For each vtable hit, read the name pointer at +8 and all other struct fields
        int entryCount = 0;
        TreeMap<String, long[]> messageData = new TreeMap<>(); // name -> [addr, field values...]
        
        for (Address vtableAddr : vtableHits) {
            if (monitor.isCancelled()) break;
            try {
                // Read name pointer at +8
                long namePtr = mem.getLong(vtableAddr.add(8));
                Address nameAddr = vtableAddr.getNewAddress(namePtr);
                String name = readString(mem, nameAddr);
                
                if (name == null || name.isEmpty()) continue;
                if (!name.matches("[A-Z][A-Za-z0-9_]+")) continue;
                
                // Dump the full 96-byte struct
                StringBuilder info = new StringBuilder();
                info.append(String.format("0x%X: name='%s'", vtableAddr.getOffset(), name));
                
                long[] fieldValues = new long[12]; // 12 int32 fields at +16 to +92
                for (int off = 16; off < 96; off += 4) {
                    int val = mem.getInt(vtableAddr.add(off));
                    fieldValues[(off - 16) / 4] = val;
                    if (val != 0) {
                        info.append(String.format("  [+%d]=%d(0x%X)", off, val, val));
                    }
                }
                
                out.println(info.toString());
                messageData.put(name, fieldValues);
                entryCount++;
                
            } catch (Exception e) {
                // skip
            }
        }
        
        println("Found " + entryCount + " message descriptors");
        out.println("\nTotal message descriptors: " + entryCount);
        
        // Step 3: If first approach fails, try a broader search
        // Search for ALL strings ending in "Message" and find their referencing structures
        if (entryCount < 10) {
            println("\n=== Fallback: Broad string search ===");
            out.println("\n=== Fallback: Broad string search ===");
            
            // Scan for all "*Message" strings in the .rdata section
            byte[] msgSuffix = "Message\0".getBytes("ASCII");
            List<Address> msgStrings = new ArrayList<>();
            searchAddr = mem.getMinAddress();
            while (searchAddr != null && !monitor.isCancelled()) {
                searchAddr = mem.findBytes(searchAddr, msgSuffix, null, true, monitor);
                if (searchAddr != null) {
                    // Walk back to find start of string
                    Address strStart = findStringStart(mem, searchAddr);
                    if (strStart != null) {
                        String fullStr = readString(mem, strStart);
                        if (fullStr != null && fullStr.matches("[A-Z][A-Za-z0-9_]*Message")) {
                            msgStrings.add(strStart);
                            // Find pointer to this string in data sections
                            long strAddr = strStart.getOffset();
                            byte[] ptrBytes = new byte[8];
                            for (int i = 0; i < 8; i++) {
                                ptrBytes[i] = (byte) ((strAddr >> (i * 8)) & 0xFF);
                            }
                            
                            Address ptrSearch = mem.getMinAddress();
                            boolean foundPtr = false;
                            while (ptrSearch != null && !monitor.isCancelled()) {
                                ptrSearch = mem.findBytes(ptrSearch, ptrBytes, null, true, monitor);
                                if (ptrSearch != null) {
                                    // Dump surrounding context
                                    StringBuilder sb = new StringBuilder();
                                    sb.append(String.format("STR '%s' at 0x%X, ptr at 0x%X:", 
                                        fullStr, strStart.getOffset(), ptrSearch.getOffset()));
                                    
                                    // Read -16 to +96 around pointer
                                    for (int off = -16; off < 96; off += 8) {
                                        try {
                                            long val = mem.getLong(ptrSearch.add(off));
                                            if (val != 0) {
                                                int lo = mem.getInt(ptrSearch.add(off));
                                                int hi = mem.getInt(ptrSearch.add(off + 4));
                                                sb.append(String.format("\n    [%+d]: 0x%016X (i32: %d, %d)", off, val, lo, hi));
                                            }
                                        } catch (Exception e) {}
                                    }
                                    out.println(sb.toString());
                                    foundPtr = true;
                                    ptrSearch = ptrSearch.add(1);
                                }
                            }
                            if (!foundPtr) {
                                out.println(String.format("STR '%s' at 0x%X: NO POINTER FOUND", fullStr, strStart.getOffset()));
                            }
                        }
                    }
                    searchAddr = searchAddr.add(1);
                }
            }
            
            println("Found " + msgStrings.size() + " message strings in binary");
            out.println("\nTotal message strings found: " + msgStrings.size());
        }
        
        // Step 4: Alternative - look for the message registration function
        // In D3, messages are registered by calling a function with (opcode, name, size, createFunc)
        // Let's search for sequences of small integers followed by string pointers
        if (entryCount < 10) {
            println("\n=== Alternative: Scanning for opcode-indexed table ===");
            out.println("\n=== Alternative: Scanning for opcode-indexed table ===");
            
            // In some D3 versions, there's a pointer array indexed by opcode
            // Array of function pointers or descriptor pointers, where index = opcode
            // Let's find if VersionsMessage's descriptor pointer appears in such an array
            
            // We know "VersionsMessage" string is at 0x1410DA958
            // Its pointer is at 0x141408918
            // If VersionsMessage = opcode 20, look for an array where entry[20] points to 0x141408918
            // or to the vtable entry at 0x141408910
            
            long versionsDescAddr = 0x141408910L; // vtable entry for VersionsMessage
            byte[] descPtrBytes = new byte[8];
            for (int i = 0; i < 8; i++) {
                descPtrBytes[i] = (byte) ((versionsDescAddr >> (i * 8)) & 0xFF);
            }
            
            searchAddr = mem.getMinAddress();
            while (searchAddr != null && !monitor.isCancelled()) {
                searchAddr = mem.findBytes(searchAddr, descPtrBytes, null, true, monitor);
                if (searchAddr != null) {
                    out.println(String.format("Ptr to VersionsMessage descriptor found at 0x%X", searchAddr.getOffset()));
                    
                    // If this is an array indexed by opcode (20), then array start = this - 20*8
                    long arrayBase = searchAddr.getOffset() - 20 * 8;
                    out.println(String.format("  Potential array base (assuming opcode 20): 0x%X", arrayBase));
                    
                    // Check: do entries at other opcode positions point to valid descriptors?
                    int validCount = 0;
                    for (int opc = 1; opc <= 30; opc++) {
                        try {
                            Address entryAddr = searchAddr.getNewAddress(arrayBase + (long)opc * 8);
                            long entryVal = mem.getLong(entryAddr);
                            if (entryVal != 0) {
                                // Check if this points to a location with our vtable pointer
                                Address descAddr = searchAddr.getNewAddress(entryVal);
                                long possibleVtable = mem.getLong(descAddr);
                                if (possibleVtable == vtablePtr) {
                                    String nameAtDesc = readString(mem, searchAddr.getNewAddress(mem.getLong(descAddr.add(8))));
                                    out.println(String.format("  Opcode %d -> desc 0x%X -> name='%s'", opc, entryVal, nameAtDesc));
                                    validCount++;
                                }
                            }
                        } catch (Exception e) {}
                    }
                    
                    if (validCount >= 5) {
                        out.println("*** OPCODE-INDEXED ARRAY FOUND ***");
                        // Extract all entries
                        for (int opc = 1; opc <= 600; opc++) {
                            try {
                                Address entryAddr = searchAddr.getNewAddress(arrayBase + (long)opc * 8);
                                long entryVal = mem.getLong(entryAddr);
                                if (entryVal != 0) {
                                    Address descAddr = searchAddr.getNewAddress(entryVal);
                                    long possibleVtable = mem.getLong(descAddr);
                                    if (possibleVtable == vtablePtr) {
                                        String nameAtDesc = readString(mem, searchAddr.getNewAddress(mem.getLong(descAddr.add(8))));
                                        if (nameAtDesc != null) {
                                            out.println(String.format("OPCODE %d = %s", opc, nameAtDesc));
                                        }
                                    }
                                }
                            } catch (Exception e) {}
                        }
                    }
                    
                    searchAddr = searchAddr.add(1);
                }
            }
        }
        
        out.flush();
        out.close();
        println("\n=== Output written to " + outputPath + " ===");
    }
    
    private Address findStringStart(Memory mem, Address endAddr) {
        // Walk backwards from the "Message\0" match to find start of the full string
        try {
            for (int i = 0; i < 200; i++) {
                byte b = mem.getByte(endAddr.add(-i - 1));
                if (b == 0) {
                    return endAddr.add(-i);
                }
                if (b < 32 || b > 126) {
                    return endAddr.add(-i);
                }
            }
        } catch (Exception e) {}
        return null;
    }
    
    private String readString(Memory mem, Address addr) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 200; i++) {
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
