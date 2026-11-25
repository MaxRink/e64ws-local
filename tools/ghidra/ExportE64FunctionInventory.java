// Exhaustive, reproducible inventory/decompilation pass for the supplied E64
// ELF programs. Raw decompiler output is written to an explicitly supplied
// ignored/temp directory; the checked-in repository should contain only the
// derived inventory and the script that produced it.
//
// Usage from analyzeHeadless:
//   -postScript ExportE64FunctionInventory.java \
//     output=/private/tmp/e64/libNgxUi.csv \
//     decomp=/private/tmp/e64/libNgxUi

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ExportE64FunctionInventory extends GhidraScript {
    private static final int DECOMP_TIMEOUT_SECONDS = 60;

    @Override
    public void run() throws Exception {
        String outputPath = null;
        String decompPath = null;
        boolean decompile = true;
        for (String arg : getScriptArgs()) {
            if (arg.startsWith("output=")) outputPath = arg.substring("output=".length());
            if (arg.startsWith("decomp=")) decompPath = arg.substring("decomp=".length());
            if (arg.equals("decompile=false")) decompile = false;
        }
        if (outputPath == null || outputPath.isEmpty()) {
            throw new IllegalArgumentException("output=PATH is required");
        }
        File output = new File(outputPath);
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();
        File decompDir = null;
        if (decompile && decompPath != null && !decompPath.isEmpty()) {
            decompDir = new File(decompPath);
            decompDir.mkdirs();
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        FunctionManager manager = currentProgram.getFunctionManager();
        int count = 0;
        int decompOk = 0;
        int decompFailed = 0;
        int locals = 0;
        int parameters = 0;

        try (BufferedWriter csv = new BufferedWriter(new FileWriter(output))) {
            csv.write("index,program,address,name,namespace,category,thunk,external,body_bytes,parameters,locals,decomp_status,decomp_file\n");
            for (Function function : manager.getFunctions(true)) {
                if (monitor.isCancelled()) break;
                count++;
                String name = function.getName();
                String namespace = function.getParentNamespace() == null
                    ? ""
                    : function.getParentNamespace().getName(true);
                int parameterCount = safeParameterCount(function);
                int localCount = safeLocalCount(function);
                parameters += parameterCount;
                locals += localCount;
                String category = classify(name);
                String status = "not_requested";
                String decompFile = "";

                if (decompDir != null && !function.isExternal()) {
                    String base = String.format(Locale.ROOT, "%06d_%s.c", count, safeFileName(name));
                    File file = new File(decompDir, base);
                    DecompileResults result = decompiler.decompileFunction(
                        function, DECOMP_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        status = "ok";
                        decompOk++;
                        try (BufferedWriter source = new BufferedWriter(new FileWriter(file))) {
                            source.write("/* program=" + safeComment(currentProgram.getName()) +
                                " address=" + function.getEntryPoint() +
                                " name=" + safeComment(name) +
                                " category=" + category + " */\n");
                            source.write(result.getDecompiledFunction().getC());
                        }
                        decompFile = file.getAbsolutePath();
                    } else {
                        status = "failed";
                        decompFailed++;
                        try (BufferedWriter source = new BufferedWriter(new FileWriter(file))) {
                            source.write("/* decompilation failed: " +
                                safeComment(result.getErrorMessage()) + " */\n");
                        }
                        decompFile = file.getAbsolutePath();
                    }
                }

                csv.write(csvRow(count, currentProgram.getName(), function.getEntryPoint(), name,
                    namespace, category, Boolean.toString(function.isThunk()),
                    Boolean.toString(function.isExternal()),
                    Long.toString(function.getBody().getNumAddresses()),
                    Integer.toString(parameterCount), Integer.toString(localCount),
                    status, decompFile));
            }
        } finally {
            decompiler.dispose();
        }

        println("E64_INVENTORY_PROGRAM=" + currentProgram.getName());
        println("E64_INVENTORY_FUNCTIONS=" + count);
        println("E64_INVENTORY_PARAMETERS=" + parameters);
        println("E64_INVENTORY_LOCALS=" + locals);
        println("E64_DECOMP_OK=" + decompOk);
        println("E64_DECOMP_FAILED=" + decompFailed);
        println("E64_INVENTORY_OUTPUT=" + output.getAbsolutePath());
        if (decompDir != null) println("E64_DECOMP_DIR=" + decompDir.getAbsolutePath());
    }

    private static int safeParameterCount(Function function) {
        try {
            Parameter[] parameters = function.getParameters();
            return parameters == null ? 0 : parameters.length;
        } catch (Exception ignored) {
            return -1;
        }
    }

    private static int safeLocalCount(Function function) {
        try {
            Variable[] variables = function.getLocalVariables();
            return variables == null ? 0 : variables.length;
        } catch (Exception ignored) {
            return -1;
        }
    }

    private static String classify(String rawName) {
        String name = rawName == null ? "" : rawName.toLowerCase(Locale.ROOT);
        if (containsAny(name, "websocket", "jsonconnector", "network", "socket", "http", "tls")) return "protocol-network";
        if (containsAny(name, "token", "login", "auth", "password", "role", "permission", "session")) return "auth-session";
        if (containsAny(name, "ota", "update", "swupdate", "flash", "firmware", "boot", "partition", "efuse")) return "update-boot";
        if (containsAny(name, "esp", "uart", "sdio", "ioctl", "heartbeat", "gpio", "reset")) return "esp-transport";
        if (containsAny(name, "sqlite", "sql", "database", "query", "insert", "select", "blob")) return "sqlite-storage";
        if (containsAny(name, "gbs", "grind", "agsa", "ddsensor", "brew", "calibrat", "fan", "motor")) return "grinder-runtime";
        if (containsAny(name, "qwidget", "qobject", "qml", "qt", "ui", "window", "dialog", "button", "label")) return "qt-ui";
        if (containsAny(name, "malloc", "free", "memcpy", "memset", "operator new", "operator delete", "alloc")) return "runtime-memory";
        if (containsAny(name, "log", "debug", "trace", "printf", "assert")) return "logging-diagnostics";
        if (name.startsWith("thunk_") || name.contains("thunk")) return "thunk-wrapper";
        return "other-unclassified";
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) if (value.contains(needle)) return true;
        return false;
    }

    private static String safeFileName(String value) {
        String name = value == null || value.isEmpty() ? "unnamed" : value;
        name = name.replaceAll("[^A-Za-z0-9._-]", "_");
        // macOS/APFS and other filesystems impose a component-length limit.
        // The monotonically increasing function index is already prepended by
        // the caller, so truncating the readable symbol is deterministic and
        // does not make two output files collide within one run.
        return name.length() <= 120 ? name : name.substring(0, 120);
    }

    private static String safeComment(String value) {
        if (value == null) return "";
        return value.replace("*/", "* /").replace("\n", " ").replace("\r", " ");
    }

    private static String csvRow(Object... values) {
        List<String> escaped = new ArrayList<>();
        for (Object value : values) {
            String text = value == null ? "" : value.toString();
            escaped.add("\"" + text.replace("\"", "\"\"") + "\"");
        }
        return String.join(",", escaped) + "\n";
    }
}
