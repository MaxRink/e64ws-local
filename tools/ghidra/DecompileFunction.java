// Decompile one function by entry address (or name) and print the C.
// @category E64

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DecompileFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("DECOMPILE usage: DecompileFunction <address-or-name>");
            return;
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        Function target = null;
        Address addr = currentProgram.getAddressFactory().getAddress(args[0]);
        if (addr != null) {
            target = fm.getFunctionAt(addr);
        }
        if (target == null) {
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(args[0])) {
                    target = f;
                    break;
                }
            }
        }
        if (target == null) {
            println("DECOMPILE not-found " + args[0]);
            return;
        }
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        DecompileResults results = dec.decompileFunction(target, 60, monitor);
        println("DECOMPILE_BEGIN " + target.getName() + " @ " + target.getEntryPoint());
        println(results.getDecompiledFunction().getC());
        println("DECOMPILE_END " + target.getName());
    }
}
