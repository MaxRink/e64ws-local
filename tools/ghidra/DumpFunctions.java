// Dump named functions so coverage can be inspected from the console.
// @category E64

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DumpFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String filter = "";
        String[] args = getScriptArgs();
        if (args.length > 0) {
            filter = args[0].toLowerCase();
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        int printed = 0;
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            String name = f.getName();
            if (name.startsWith("FUN_")) {
                continue;
            }
            if (!filter.isEmpty() && !name.toLowerCase().contains(filter)) {
                continue;
            }
            println("FUNC " + f.getEntryPoint() + " " + name + " params=" + f.getParameterCount());
            printed++;
        }
        println("FUNC_TOTAL printed=" + printed);
    }
}
