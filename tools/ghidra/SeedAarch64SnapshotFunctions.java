// Seed conservative function starts in a stripped Dart AOT instruction
// snapshot. Ghidra's normal ELF analysis has no entry references for these
// packed instructions, so it otherwise reports zero functions. This pass is
// deliberately heuristic: names carry the address and confidence, never a
// guessed Dart method name.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class SeedAarch64SnapshotFunctions extends GhidraScript {
    private static final long STP_FRAME_MASK = 0xffc07fffL;
    private static final long STP_X29_X30_PREINDEX = 0xa98079fdL;

    @Override
    public void run() throws Exception {
        long seeded = 0;
        long existing = 0;
        long candidates = 0;
        long instructionPresent = 0;
        long creationFailures = 0;
        int diagnosticLines = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute()) continue;
            long size = block.getSize();
            if (size < 4 || size > Integer.MAX_VALUE) continue;
            byte[] bytes = new byte[(int) size];
            currentProgram.getMemory().getBytes(block.getStart(), bytes);
            for (int offset = 0; offset + 4 <= bytes.length; offset += 4) {
                long word = ((bytes[offset] & 0xffL))
                    | ((bytes[offset + 1] & 0xffL) << 8)
                    | ((bytes[offset + 2] & 0xffL) << 16)
                    | ((bytes[offset + 3] & 0xffL) << 24);
                if ((word & STP_FRAME_MASK) != STP_X29_X30_PREINDEX) continue;
                candidates++;
                Address address = block.getStart().add(offset);
                if (diagnosticLines == 0) {
                    println("DART_AOT_BLOCK=" + block.getName()
                        + " start=" + block.getStart()
                        + " initialized=" + block.isInitialized()
                        + " execute=" + block.isExecute()
                        + " address=" + address);
                    diagnosticLines++;
                }
                Function function = getFunctionAt(address);
                if (function != null) {
                    existing++;
                    continue;
                }
                if (getInstructionAt(address) != null) instructionPresent++;
                try {
                    clearListing(address, address.add(3));
                    disassemble(address);
                    function = createFunction(address, null);
                } catch (Exception error) {
                    function = null;
                    creationFailures++;
                    if (diagnosticLines++ < 6) {
                        println("DART_AOT_CREATE_EXCEPTION=" + address + " " + error);
                    }
                }
                if (function != null) {
                    function.setComment(
                        "Heuristic AArch64 frame-prologue seed in Dart AOT snapshot; "
                        + "address-based name is not a recovered Dart symbol.");
                    function.setName("dart_snapshot_fn_" + address, SourceType.ANALYSIS);
                    seeded++;
                } else if (diagnosticLines++ < 6) {
                    println("DART_AOT_CREATE_NULL=" + address
                        + " instruction=" + (getInstructionAt(address) != null));
                }
            }
        }
        println("DART_AOT_PROLOGUE_CANDIDATES=" + candidates);
        println("DART_AOT_EXISTING_FUNCTIONS=" + existing);
        println("DART_AOT_INSTRUCTIONS_PRESENT=" + instructionPresent);
        println("DART_AOT_CREATE_FAILURES=" + creationFailures);
        println("DART_AOT_SEEDED_FUNCTIONS=" + seeded);
    }
}
