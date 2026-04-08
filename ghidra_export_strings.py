# Extract key data from Diablo III64.exe using Ghidra headless
# Exports all strings to a file for analysis

import ghidra.program.model.listing.Data
import ghidra.program.model.data.StringDataType

output_file = "C:/Users/Beroli/projects/blizzless-diiis/ghidra_strings.txt"

f = open(output_file, "w")

# Get all defined strings
listing = currentProgram.getListing()
dataIterator = listing.getDefinedData(True)

count = 0
while dataIterator.hasNext() and count < 500000:
    data = dataIterator.next()
    dataType = data.getDataType()
    if "string" in dataType.getName().lower() or "unicode" in dataType.getName().lower():
        try:
            val = data.getValue()
            if val is not None:
                s = str(val)
                if len(s) > 5:
                    f.write("0x{:x}\t{}\n".format(data.getAddress().getOffset(), s))
        except:
            pass
    count += 1

f.close()
print("Exported strings to " + output_file)
