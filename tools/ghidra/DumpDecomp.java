// Ghidra headless helper for this research repository.
// Usage: analyzeHeadless <project-dir> <project-name> -process <file>
//        -postScript DumpDecomp.java [substring ...]
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

public class DumpDecomp extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] wanted = getScriptArgs();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            String name = function.getName();
            // Headless Analyzer does not accept positional script arguments in
            // the distribution build, so the default is intentionally bounded
            // to the protocol dispatcher rather than every function.
            boolean selected = wanted.length == 0 &&
                ((name.contains("JsonConnector") &&
                  (name.contains("cmd") || name.contains("handleMessage") ||
                   name.contains("handleFoundMessage") || name.contains("validateToken") ||
                   name.contains("JsonConnectorC"))) ||
                 name.contains("WebSocketConnector"));
            for (String fragment : wanted) {
                if (name.contains(fragment)) {
                    selected = true;
                    break;
                }
            }
            if (!selected) {
                continue;
            }

            println("===== " + name + " @ " + function.getEntryPoint() + " =====");
            DecompileResults result = decompiler.decompileFunction(function, 120, TaskMonitor.DUMMY);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("[decompilation failed: " + result.getErrorMessage() + "]");
            }
        }
        decompiler.dispose();
    }
}
