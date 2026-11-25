// Diagnostic helper for an imported ELF or raw Xtensa image; this name avoids
// Ghidra's built-in ListFunctions script. The count is an inventory only:
// raw ESP binaries have no linked symbols or source-level names.
import ghidra.program.model.listing.Function;

public class E64ListFunctions extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String needle = getScriptArgs().length == 0 ? "" : getScriptArgs()[0];
        int count = 0;
        int shown = 0;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            count++;
            String name = function.getName();
            if (!needle.isEmpty() && !name.contains(needle)) {
                continue;
            }
            if (needle.isEmpty() && shown >= 100) {
                continue;
            }
            println(function.getEntryPoint() + " " + name);
            shown++;
        }
        println("FUNCTION_COUNT=" + count + " MATCH_COUNT=" + shown + " NEEDLE=" + needle);
    }
}
