// Decompile one or more exact entry points from an imported ARM ELF.
// Usage: -postScript E64DumpAt.java 0x00272b34 0x0027482c
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

public class E64DumpAt extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String arg : getScriptArgs()) {
            long value = Long.decode(arg);
            Address address = toAddr(value);
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                println("===== " + arg + " (no function) =====");
                continue;
            }
            println("===== " + function.getName() + " @ " + address + " =====");
            DecompileResults result = decompiler.decompileFunction(function, 180, TaskMonitor.DUMMY);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("[decompilation failed: " + result.getErrorMessage() + "]");
            }
        }
        decompiler.dispose();
    }
}
