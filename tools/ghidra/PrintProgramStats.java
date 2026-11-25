// Print a compact coverage line for the currently open program.
// @category E64

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class PrintProgramStats extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        int total = fm.getFunctionCount();
        int named = 0;
        int external = 0;
        int thunks = 0;
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal()) {
                external++;
                continue;
            }
            if (f.isThunk()) {
                thunks++;
            }
            String name = f.getName();
            if (!name.startsWith("FUN_") && f.getSymbol().getSource() != SourceType.DEFAULT) {
                named++;
            }
        }
        println("PROGRAM_STATS program=" + currentProgram.getName()
                + " lang=" + currentProgram.getLanguageID()
                + " total=" + total
                + " named=" + named
                + " external=" + external
                + " thunks=" + thunks);
    }
}
