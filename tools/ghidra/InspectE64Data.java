// Print data, references, and symbols around exact Ghidra virtual addresses.
// This is deliberately read-only and is useful for resolving PIE/relocation
// ambiguity in literal pools without guessing from raw file offsets.
// Usage: -postScript InspectE64Data.java 0x002d4b24 0x00699600
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

public class InspectE64Data extends ghidra.app.script.GhidraScript {
    private void dumpAddress(Address address) {
        println("===== address " + address + " =====");
        println("bytes=" + bytesAt(address, 16));
        Data data = currentProgram.getListing().getDataContaining(address);
        if (data != null) {
            println("data=" + data + " value=" + data.getValue());
        }
        Instruction instruction = currentProgram.getListing().getInstructionAt(address);
        if (instruction != null) {
            println("instruction=" + instruction);
        }
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function != null) {
            println("function=" + function.getName() + " @ " + function.getEntryPoint());
        }
        SymbolTable symbols = currentProgram.getSymbolTable();
        Symbol[] symbolsAt = symbols.getSymbols(address);
        for (Symbol symbol : symbolsAt) {
            println("symbol=" + symbol.getName() + " source=" + symbol.getSource());
        }
        Reference[] refs = getReferencesTo(address);
        for (Reference ref : refs) {
            println("reference=" + ref.getFromAddress() + " type=" + ref.getReferenceType());
            Function from = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (from != null) {
                println("  fromFunction=" + from.getName() + " @ " + from.getEntryPoint());
            }
        }
    }

    private String bytesAt(Address address, int count) {
        try {
            byte[] bytes = new byte[count];
            currentProgram.getMemory().getBytes(address, bytes);
            StringBuilder result = new StringBuilder();
            for (byte value : bytes) {
                result.append(String.format("%02x", value & 0xff));
            }
            return result.toString();
        } catch (Exception exc) {
            return "<unreadable: " + exc.getMessage() + ">";
        }
    }

    @Override
    public void run() throws Exception {
        for (String argument : getScriptArgs()) {
            dumpAddress(toAddr(Long.decode(argument)));
        }
    }
}
