// Ghidra script to extract opcode table from Diablo III 2.8.0
// Approach: Find message name strings, trace xrefs to find the descriptor struct,
// then read opcode and size fields from the struct.
//@category D3
//@author Migration Tool

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.util.*;
import java.io.*;
import ghidra.program.model.symbol.ReferenceIterator;

public class ExtractOpcodes extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Phase 1: Find a known message string to discover the struct layout
        // "VersionsMessage" is opcode 20 in 2.7.4 - use it as calibration
        
        String outputPath = "C:\\Users\\Beroli\\Downloads\\D32.8.9-extracted\\opcodes_output.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        // Step 1: Find "VersionsMessage" string to calibrate struct layout
        println("=== Phase 1: Calibrating with VersionsMessage ===");
        out.println("=== Phase 1: Calibrating with VersionsMessage ===");
        
        Address calibrationStr = findStringAddress("VersionsMessage");
        if (calibrationStr == null) {
            println("ERROR: Could not find 'VersionsMessage' string");
            out.println("ERROR: Could not find 'VersionsMessage' string");
            out.close();
            return;
        }
        println("Found 'VersionsMessage' at " + calibrationStr);
        out.println("Found 'VersionsMessage' at " + calibrationStr);
        
        // Find all references to this string
        ReferenceIterator refIter = refMgr.getReferencesTo(calibrationStr);
        List<Reference> refList = new ArrayList<>();
        while (refIter.hasNext()) refList.add(refIter.next());
        println("References to VersionsMessage: " + refList.size());
        out.println("References to VersionsMessage: " + refList.size());
        
        // Also search for pointer to this string in data sections
        long strAddrLong = calibrationStr.getOffset();
        byte[] strAddrBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            strAddrBytes[i] = (byte) ((strAddrLong >> (i * 8)) & 0xFF);
        }
        
        println("Searching for pointer bytes to " + calibrationStr + " ...");
        out.println("Searching for pointer bytes to " + calibrationStr + " ...");
        
        // Search all memory for pointers to the string
        List<Address> ptrLocations = new ArrayList<>();
        Address searchAddr = mem.getMinAddress();
        while (searchAddr != null && !monitor.isCancelled()) {
            searchAddr = mem.findBytes(searchAddr, strAddrBytes, null, true, monitor);
            if (searchAddr != null) {
                ptrLocations.add(searchAddr);
                println("  Pointer to VersionsMessage at: " + searchAddr);
                out.println("  Pointer to VersionsMessage at: " + searchAddr);
                
                // Dump surrounding bytes to understand struct layout
                // Dump -64 to +128 bytes around this pointer
                long base = searchAddr.getOffset();
                out.println("  Hex dump around pointer (base=" + searchAddr + "):");
                for (int row = -8; row <= 16; row++) {
                    Address rowAddr = searchAddr.getNewAddress(base + row * 8);
                    StringBuilder sb = new StringBuilder();
                    sb.append(String.format("    %s [%+4d]: ", rowAddr, row * 8));
                    try {
                        long val = mem.getLong(rowAddr);
                        sb.append(String.format("0x%016X", val));
                        // Try to interpret as int32 pair
                        int lo = mem.getInt(rowAddr);
                        int hi = mem.getInt(rowAddr.add(4));
                        sb.append(String.format("  (int32: %d, %d)", lo, hi));
                    } catch (Exception e) {
                        sb.append("  <unreadable>");
                    }
                    out.println(sb.toString());
                }
                
                searchAddr = searchAddr.add(1);
            }
        }
        
        if (ptrLocations.isEmpty()) {
            println("No pointer references found. Trying Ghidra references...");
            out.println("No pointer references found. Trying Ghidra references...");
            for (Reference ref : refList) {
                Address fromAddr = ref.getFromAddress();
                println("  Ghidra ref from: " + fromAddr + " type: " + ref.getReferenceType());
                out.println("  Ghidra ref from: " + fromAddr + " type: " + ref.getReferenceType());
            }
        }
        
        // Step 2: Now search for ALL message name strings and their descriptors
        println("\n=== Phase 2: Finding all message descriptors ===");
        out.println("\n=== Phase 2: Finding all message descriptors ===");
        
        // Known message names from 2.7.4 opcodes - search for these as strings
        String[] knownMessages = {
            "QuitGameMessage",
            "VersionsMessage", 
            "ConnectionEstablishedMessage",
            "GameSetupMessage",
            "NewPlayerMessage",
            "EnterWorldMessage",
            "RevealSceneMessage",
            "RevealWorldMessage",
            "ACDEnterKnownMessage",
            "GameTickMessage",
            "EndOfTickMessage",
            "PingMessage",
            "PongMessage",
            "LoadCompleteMessage",
            "ChatMessage",
            "TryChatMessage",
            "PlayEffectMessage",
            "AttributeSetValueMessage",
            "AttributesSetValuesMessage",
            "TargetMessage",
            "ACDTranslateNormalMessage",
            "JoinBNetGameMessage",
            // New messages found in 2.8.0
            "WarningCountdownNotificationMessage",
            "BlizzconCVarsMessage",
            "PRTransformMessage",
            "RitualTetherEffectMessage",
        };
        
        // For each known message, find string and surrounding data
        Map<String, Address> messageStrAddrs = new LinkedHashMap<>();
        for (String msgName : knownMessages) {
            if (monitor.isCancelled()) break;
            Address addr = findStringAddress(msgName);
            if (addr != null) {
                messageStrAddrs.put(msgName, addr);
            }
        }
        
        println("Found " + messageStrAddrs.size() + "/" + knownMessages.length + " message strings");
        out.println("Found " + messageStrAddrs.size() + "/" + knownMessages.length + " message strings");
        
        // For each found string, find the descriptor pointer and try to read the opcode
        // We'll analyze the calibration result first to know the struct offset
        
        // Step 3: Exhaustive approach - scan .rdata for a table of message descriptors
        // Message descriptor tables in D3 are typically contiguous arrays of pointers
        println("\n=== Phase 3: Scanning for message descriptor table ===");
        out.println("\n=== Phase 3: Scanning for message descriptor table ===");
        
        // Find all strings that end with "Message" in the binary
        List<String[]> allMessages = new ArrayList<>(); // [name, strAddr, ptrAddr, context]
        
        // Scan for string pointers in .rdata / data sections
        // For the calibration addresses found, check if they're part of a table
        if (!ptrLocations.isEmpty()) {
            Address firstPtr = ptrLocations.get(0);
            println("Analyzing table around first pointer at " + firstPtr);
            out.println("Analyzing table around first pointer at " + firstPtr);
            
            // Try different struct sizes (common: 8, 16, 24, 32, 40, 48, 56, 64 bytes)
            for (int structSize = 8; structSize <= 128; structSize += 8) {
                // Check if there's a pattern: other message string pointers at regular intervals
                int foundCount = 0;
                long baseOffset = firstPtr.getOffset();
                
                for (int i = -20; i <= 20; i++) {
                    if (i == 0) continue;
                    try {
                        Address checkAddr = firstPtr.getNewAddress(baseOffset + (long)i * structSize);
                        long ptrValue = mem.getLong(checkAddr);
                        // Check if this pointer points to a valid string in the binary
                        Address targetAddr = firstPtr.getNewAddress(ptrValue);
                        if (isValidMessageString(mem, targetAddr)) {
                            foundCount++;
                        }
                    } catch (Exception e) {
                        // ignore
                    }
                }
                
                if (foundCount >= 5) {
                    println("*** LIKELY TABLE FOUND: structSize=" + structSize + ", found " + foundCount + " message strings nearby");
                    out.println("*** LIKELY TABLE FOUND: structSize=" + structSize + ", found " + foundCount + " message strings nearby");
                    
                    // Now extract the full table
                    extractTable(mem, firstPtr, structSize, out);
                    break;
                }
            }
        }
        
        out.flush();
        out.close();
        println("\n=== Output written to " + outputPath + " ===");
    }
    
    private void extractTable(Memory mem, Address knownEntry, int structSize, PrintWriter out) throws Exception {
        // Walk backwards to find the start of the table
        long base = knownEntry.getOffset();
        long tableStart = base;
        
        for (int i = 1; i < 600; i++) {
            Address checkAddr = knownEntry.getNewAddress(base - (long)i * structSize);
            try {
                long ptrValue = mem.getLong(checkAddr);
                Address targetAddr = knownEntry.getNewAddress(ptrValue);
                if (isValidMessageString(mem, targetAddr)) {
                    tableStart = checkAddr.getOffset();
                } else {
                    break;
                }
            } catch (Exception e) {
                break;
            }
        }
        
        // Walk forward from tableStart to extract all entries
        println("Table starts around: 0x" + Long.toHexString(tableStart));
        out.println("Table starts around: 0x" + Long.toHexString(tableStart));
        
        int count = 0;
        TreeMap<Integer, String> opcodeMap = new TreeMap<>();
        
        for (int i = 0; i < 700; i++) {
            if (monitor.isCancelled()) break;
            Address entryAddr = knownEntry.getNewAddress(tableStart + (long)i * structSize);
            try {
                long namePtr = mem.getLong(entryAddr);
                Address nameAddr = knownEntry.getNewAddress(namePtr);
                
                String name = readString(mem, nameAddr);
                if (name == null || name.isEmpty()) break;
                if (!name.matches("[A-Z][A-Za-z0-9_]+")) break;
                
                // Read potential opcode and size from other fields in the struct
                // Try several offsets
                StringBuilder info = new StringBuilder();
                info.append(String.format("Entry[%d] at 0x%X: name='%s'", i, entryAddr.getOffset(), name));
                
                // Dump all int32 values in the struct
                for (int off = 8; off < structSize; off += 4) {
                    try {
                        int val = mem.getInt(entryAddr.add(off));
                        info.append(String.format("  [+%d]=%d(0x%X)", off, val, val));
                    } catch (Exception e) {
                        break;
                    }
                }
                
                out.println(info.toString());
                count++;
                
            } catch (Exception e) {
                break;
            }
        }
        
        println("Extracted " + count + " table entries");
        out.println("Total entries: " + count);
    }
    
    private Address findStringAddress(String target) throws Exception {
        Memory mem = currentProgram.getMemory();
        byte[] targetBytes = target.getBytes("ASCII");
        
        Address addr = mem.getMinAddress();
        while (addr != null && !monitor.isCancelled()) {
            addr = mem.findBytes(addr, targetBytes, null, true, monitor);
            if (addr != null) {
                // Verify it's a null-terminated string (check byte before and after)
                try {
                    byte after = mem.getByte(addr.add(targetBytes.length));
                    if (after == 0) {
                        // Check byte before - should be 0 or start of section
                        try {
                            byte before = mem.getByte(addr.add(-1));
                            if (before == 0 || before == '\n') {
                                return addr;
                            }
                        } catch (Exception e) {
                            return addr; // at start of section, OK
                        }
                    }
                } catch (Exception e) {
                    // can't read after, skip
                }
                addr = addr.add(1);
            }
        }
        return null;
    }
    
    private boolean isValidMessageString(Memory mem, Address addr) {
        try {
            String s = readString(mem, addr);
            if (s == null) return false;
            // Message names typically: start with uppercase, contain "Message" or are CamelCase, length > 5
            return s.length() > 5 && s.length() < 100 && 
                   Character.isUpperCase(s.charAt(0)) &&
                   s.matches("[A-Z][A-Za-z0-9_]+");
        } catch (Exception e) {
            return false;
        }
    }
    
    private String readString(Memory mem, Address addr) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 200; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0) break;
                if (b < 32 || b > 126) return null; // not ASCII
                sb.append((char) b);
            }
            return sb.length() > 0 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
