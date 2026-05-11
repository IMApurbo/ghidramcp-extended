package ghidramcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.util.task.TaskMonitor;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.Executors;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidraMCPExtended",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhidraMCP Extended HTTP Server",
    description = "Full read+write MCP interface: patch, rename, export, xrefs, search"
)
public class GhidraMCPExtendedPlugin extends ProgramPlugin {

    private HttpServer server;
    private static final int PORT = 8080;

    public GhidraMCPExtendedPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    public void init() {
        super.init();
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", PORT), 0);
            server.setExecutor(Executors.newCachedThreadPool());
            registerHandlers();
            server.start();
            System.out.println("[GhidraMCPExtended] Listening on port " + PORT);
        } catch (IOException e) {
            System.err.println("[GhidraMCPExtended] Failed to start: " + e.getMessage());
        }
    }

    @Override
    public void cleanup() {
        if (server != null) server.stop(0);
        super.cleanup();
    }

    // ── Route registration ────────────────────────────────────────────────────

    private void registerHandlers() {
        // READ
        server.createContext("/list_methods",        ex -> safe(ex, this::handleListMethods));
        server.createContext("/list_classes",         ex -> safe(ex, this::handleListClasses));
        server.createContext("/list_imports",         ex -> safe(ex, this::handleListImports));
        server.createContext("/list_exports",         ex -> safe(ex, this::handleListExports));
        server.createContext("/list_segments",        ex -> safe(ex, this::handleListSegments));
        server.createContext("/list_strings",         ex -> safe(ex, this::handleListStrings));
        server.createContext("/decompile_function",   ex -> safe(ex, this::handleDecompile));
        server.createContext("/get_function_by_name", ex -> safe(ex, this::handleGetFunctionByName));
        server.createContext("/read_bytes",           ex -> safe(ex, this::handleReadBytes));
        server.createContext("/xrefs_to",             ex -> safe(ex, this::handleXrefsTo));
        server.createContext("/xrefs_from",           ex -> safe(ex, this::handleXrefsFrom));
        server.createContext("/search_bytes",         ex -> safe(ex, this::handleSearchBytes));
        server.createContext("/search_strings",       ex -> safe(ex, this::handleSearchStrings));
        // WRITE
        server.createContext("/rename_function",      ex -> safe(ex, this::handleRenameFunction));
        server.createContext("/rename_data",          ex -> safe(ex, this::handleRenameData));
        server.createContext("/rename_variable",      ex -> safe(ex, this::handleRenameVariable));
        server.createContext("/patch_bytes",          ex -> safe(ex, this::handlePatchBytes));
        server.createContext("/patch_instruction",    ex -> safe(ex, this::handlePatchInstruction));
        server.createContext("/nop_range",            ex -> safe(ex, this::handleNopRange));
        server.createContext("/set_comment",          ex -> safe(ex, this::handleSetComment));
        server.createContext("/set_bookmark",         ex -> safe(ex, this::handleSetBookmark));
        server.createContext("/set_data_type",        ex -> safe(ex, this::handleSetDataType));
        // FIX 1: these two were missing from registerHandlers entirely
        server.createContext("/set_function_signature", ex -> safe(ex, this::handleSetFunctionSignature));
        server.createContext("/run_analysis",           ex -> safe(ex, this::handleRunAnalysis));
        // EXPORT
        server.createContext("/export_binary",        ex -> safe(ex, this::handleExportBinary));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    @FunctionalInterface interface Handler { void handle(HttpExchange ex) throws Exception; }

    private void safe(HttpExchange ex, Handler h) {
        try { h.handle(ex); }
        catch (Exception e) {
            try {
                java.io.StringWriter sw = new java.io.StringWriter();
                e.printStackTrace(new java.io.PrintWriter(sw));
                sendResponse(ex, 500, "EXCEPTION: " + sw.toString());
            } catch (IOException ignored) {}
        }
    }

    private void sendResponse(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes("UTF-8");
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null || query.isEmpty()) return map;
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            try {
                if (kv.length == 2)
                    map.put(java.net.URLDecoder.decode(kv[0], "UTF-8"),
                            java.net.URLDecoder.decode(kv[1], "UTF-8"));
            } catch (Exception ignored) {}
        }
        return map;
    }

    private Map<String, String> parseBody(HttpExchange ex) throws IOException {
        return parseQuery(new String(ex.getRequestBody().readAllBytes(), "UTF-8"));
    }

    private boolean requirePost(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equalsIgnoreCase("POST")) {
            sendResponse(ex, 405, "POST required"); return false;
        }
        return true;
    }

    private Program prog() { return getCurrentProgram(); }

    private boolean checkProgram(HttpExchange ex) throws IOException {
        if (prog() == null) { sendResponse(ex, 503, "No program open in Ghidra"); return false; }
        return true;
    }

    /**
     * FIX 2: Robust address parser.
     * Accepts: "0x001011eb", "001011eb", "00401000", decimal strings.
     * Previously addr() called getAddress(String) which silently returned null
     * for plain hex strings without "0x", causing NullPointerException -> 500.
     */
    private Address parseAddr(String s) {
        if (s == null) return null;
        s = s.trim();
        try {
            // Try Ghidra's own parser first (handles "ram:001011eb" etc.)
            Address a = prog().getAddressFactory().getAddress(s);
            if (a != null) return a;
        } catch (Exception ignored) {}
        try {
            // Strip 0x prefix if present, parse as unsigned hex
            String hex = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
            long offset = Long.parseUnsignedLong(hex, 16);
            return prog().getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (Exception ignored) {}
        return null;
    }

    private String addrStr(Address a) { return a == null ? "?" : a.toString(); }

    // ── READ handlers ─────────────────────────────────────────────────────────

    private void handleListMethods(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        int offset = Integer.parseInt(q.getOrDefault("offset","0"));
        int limit  = Integer.parseInt(q.getOrDefault("limit","100"));
        StringBuilder sb = new StringBuilder();
        FunctionIterator it = prog().getFunctionManager().getFunctions(true);
        int i = 0, n = 0;
        while (it.hasNext()) {
            Function f = it.next();
            if (i++ < offset) continue;
            if (n++ >= limit) break;
            sb.append(f.getName()).append(" @ ").append(addrStr(f.getEntryPoint())).append("\n");
        }
        sendResponse(ex, 200, sb.toString());
    }

    private void handleListClasses(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        StringBuilder sb = new StringBuilder();
        SymbolIterator it = prog().getSymbolTable().getDefinedSymbols();
        Set<String> seen = new HashSet<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            Namespace ns = s.getParentNamespace();
            if (ns instanceof GhidraClass && seen.add(ns.getName(true)))
                sb.append(ns.getName(true)).append("\n");
        }
        sendResponse(ex, 200, sb.length() == 0 ? "(none)" : sb.toString());
    }

    private void handleListImports(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        StringBuilder sb = new StringBuilder();
        SymbolIterator it = prog().getSymbolTable().getExternalSymbols();
        while (it.hasNext()) {
            Symbol s = it.next();
            sb.append(s.getName(true)).append("\n");
        }
        sendResponse(ex, 200, sb.length() == 0 ? "(none)" : sb.toString());
    }

    private void handleListExports(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        StringBuilder sb = new StringBuilder();
        SymbolIterator it = prog().getSymbolTable().getDefinedSymbols();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint())
                sb.append(s.getName()).append(" @ ").append(addrStr(s.getAddress())).append("\n");
        }
        sendResponse(ex, 200, sb.length() == 0 ? "(none)" : sb.toString());
    }

    private void handleListSegments(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        StringBuilder sb = new StringBuilder();
        for (MemoryBlock mb : prog().getMemory().getBlocks()) {
            sb.append(String.format("%-20s start=%-12s end=%-12s size=%-8d %s%s%s%n",
                mb.getName(),
                addrStr(mb.getStart()), addrStr(mb.getEnd()),
                mb.getSize(),
                mb.isRead()    ? "r" : "-",
                mb.isWrite()   ? "w" : "-",
                mb.isExecute() ? "x" : "-"));
        }
        sendResponse(ex, 200, sb.toString());
    }

    private void handleListStrings(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        StringBuilder sb = new StringBuilder();
        for (Data d : prog().getListing().getDefinedData(true)) {
            String dtName = d.getDataType().getName().toLowerCase();
            if (dtName.contains("string") || dtName.contains("unicode")) {
                Object v = d.getValue();
                if (v != null)
                    sb.append(addrStr(d.getAddress())).append(": ").append(v).append("\n");
            }
        }
        sendResponse(ex, 200, sb.length() == 0 ? "(none)" : sb.toString());
    }

    private void handleDecompile(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { sendResponse(ex, 400, "?name= required"); return; }
        Function f = findFunctionByName(name);
        if (f == null) { sendResponse(ex, 404, "Function not found: " + name); return; }
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(prog());
            DecompileResults res = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
            if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                sendResponse(ex, 200, res.getDecompiledFunction().getC());
            } else {
                sendResponse(ex, 500, "Decompilation failed: " + res.getErrorMessage());
            }
        } finally {
            decomp.dispose();
        }
    }

    private void handleGetFunctionByName(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { sendResponse(ex, 400, "?name= required"); return; }
        Function f = findFunctionByName(name);
        if (f == null) { sendResponse(ex, 404, "Not found: " + name); return; }
        sendResponse(ex, 200,
            "name: "      + f.getName() + "\n" +
            "address: "   + addrStr(f.getEntryPoint()) + "\n" +
            "signature: " + f.getSignature().getPrototypeString() + "\n" +
            "size: "      + f.getBody().getNumAddresses() + " bytes");
    }

    private void handleReadBytes(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String addrParam = q.get("address");
        int length = Math.min(Integer.parseInt(q.getOrDefault("length","16")), 65536);
        if (addrParam == null) { sendResponse(ex, 400, "?address= required"); return; }
        Address a = parseAddr(addrParam);
        if (a == null) { sendResponse(ex, 400, "Invalid address: " + addrParam); return; }
        byte[] buf = new byte[length];
        prog().getMemory().getBytes(a, buf);
        StringBuilder sb = new StringBuilder();
        for (byte b : buf) sb.append(String.format("%02x ", b));
        sendResponse(ex, 200, sb.toString().trim());
    }

    private void handleXrefsTo(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String a = q.get("address");
        if (a == null) { sendResponse(ex, 400, "?address= required"); return; }
        Address addr = parseAddr(a);
        if (addr == null) { sendResponse(ex, 400, "Invalid address: " + a); return; }
        StringBuilder sb = new StringBuilder();
        for (Reference r : prog().getReferenceManager().getReferencesTo(addr))
            sb.append(addrStr(r.getFromAddress()))
              .append(" -> ").append(addrStr(r.getToAddress()))
              .append(" [").append(r.getReferenceType()).append("]\n");
        sendResponse(ex, 200, sb.length() == 0 ? "(no xrefs)" : sb.toString());
    }

    private void handleXrefsFrom(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String a = q.get("address");
        if (a == null) { sendResponse(ex, 400, "?address= required"); return; }
        Address addr = parseAddr(a);
        if (addr == null) { sendResponse(ex, 400, "Invalid address: " + a); return; }
        StringBuilder sb = new StringBuilder();
        for (Reference r : prog().getReferenceManager().getReferencesFrom(addr))
            sb.append(addrStr(r.getFromAddress()))
              .append(" -> ").append(addrStr(r.getToAddress()))
              .append(" [").append(r.getReferenceType()).append("]\n");
        sendResponse(ex, 200, sb.length() == 0 ? "(no xrefs)" : sb.toString());
    }

    private void handleSearchBytes(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String pattern = q.get("pattern");
        if (pattern == null) { sendResponse(ex, 400, "?pattern= required (hex, ?? = wildcard)"); return; }
        pattern = pattern.replaceAll("\\s","");
        if (pattern.length() % 2 != 0) { sendResponse(ex, 400, "pattern must be even-length hex string"); return; }
        int len = pattern.length() / 2;
        byte[] values = new byte[len], masks = new byte[len];
        for (int i = 0; i < len; i++) {
            String b = pattern.substring(i*2, i*2+2);
            if (b.contains("?")) { masks[i]=0; values[i]=0; }
            else { masks[i]=(byte)0xFF; values[i]=(byte)Integer.parseInt(b,16); }
        }
        StringBuilder sb = new StringBuilder();
        Address start = prog().getMinAddress();
        Address found;
        while ((found = prog().getMemory().findBytes(start, values, masks, true, TaskMonitor.DUMMY)) != null) {
            sb.append(addrStr(found)).append("\n");
            start = found.add(1);
        }
        sendResponse(ex, 200, sb.length() == 0 ? "(no matches)" : sb.toString());
    }

    private void handleSearchStrings(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String sub = q.getOrDefault("query","").toLowerCase();
        StringBuilder sb = new StringBuilder();
        for (Data d : prog().getListing().getDefinedData(true)) {
            if (d.getDataType().getName().toLowerCase().contains("string")) {
                Object v = d.getValue();
                if (v != null && v.toString().toLowerCase().contains(sub))
                    sb.append(addrStr(d.getAddress())).append(": ").append(v).append("\n");
            }
        }
        sendResponse(ex, 200, sb.length() == 0 ? "(no matches)" : sb.toString());
    }

    // ── WRITE handlers ────────────────────────────────────────────────────────

    private void handleRenameFunction(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String newName = b.get("new_name");
        if (newName == null) { sendResponse(ex, 400, "new_name required"); return; }
        Function f = null;
        if (b.containsKey("address")) {
            Address a = parseAddr(b.get("address"));
            if (a != null) f = prog().getFunctionManager().getFunctionAt(a);
        }
        if (f == null && b.containsKey("old_name"))
            f = findFunctionByName(b.get("old_name"));
        if (f == null) { sendResponse(ex, 404, "Function not found"); return; }
        int tx = prog().startTransaction("rename_function");
        try {
            f.setName(newName, SourceType.USER_DEFINED);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Renamed to " + newName);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleRenameData(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrParam = b.get("address"), newName = b.get("new_name");
        if (addrParam == null || newName == null) { sendResponse(ex, 400, "address and new_name required"); return; }
        Address a = parseAddr(addrParam);
        if (a == null) { sendResponse(ex, 400, "Invalid address: " + addrParam); return; }
        int tx = prog().startTransaction("rename_data");
        try {
            Symbol sym = prog().getSymbolTable().getPrimarySymbol(a);
            if (sym != null) sym.setName(newName, SourceType.USER_DEFINED);
            else prog().getSymbolTable().createLabel(a, newName, SourceType.USER_DEFINED);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Label set: " + newName + " @ " + addrParam);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleRenameVariable(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String funcName = b.get("function"), oldName = b.get("old_name"), newName = b.get("new_name");
        if (funcName == null || oldName == null || newName == null) {
            sendResponse(ex, 400, "function, old_name, new_name required"); return;
        }
        Function f = findFunctionByName(funcName);
        if (f == null) { sendResponse(ex, 404, "Function not found"); return; }

        DecompInterface decomp = new DecompInterface();
        DecompileResults res;
        try {
            decomp.openProgram(prog());
            res = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
        } finally {
            decomp.dispose();
        }
        if (!res.decompileCompleted()) { sendResponse(ex, 500, "Decompilation failed"); return; }

        HighFunction hf = res.getHighFunction();
        LocalSymbolMap lsm = hf.getLocalSymbolMap();
        HighSymbol target = null;
        Iterator<HighSymbol> it = lsm.getSymbols();
        while (it.hasNext()) {
            HighSymbol hs = it.next();
            if (hs.getName().equals(oldName)) { target = hs; break; }
        }
        if (target == null) { sendResponse(ex, 404, "Variable not found: " + oldName); return; }

        int tx = prog().startTransaction("rename_variable");
        try {
            HighFunctionDBUtil.updateDBVariable(target, newName, null, SourceType.USER_DEFINED);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Renamed: " + oldName + " -> " + newName);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    /**
     * FIX 2 applied: use parseAddr() instead of addr() everywhere in patch handlers.
     * FIX 3: make memory block writable before patching if it isn't already.
     */
    private void handlePatchBytes(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrParam = b.get("address"), hexBytes = b.get("bytes");
        if (addrParam == null || hexBytes == null) { sendResponse(ex, 400, "address and bytes required"); return; }
        hexBytes = hexBytes.replaceAll("\\s","");
        if (hexBytes.length() % 2 != 0) { sendResponse(ex, 400, "bytes must be even-length hex string"); return; }
        byte[] patch = new byte[hexBytes.length()/2];
        for (int i = 0; i < patch.length; i++)
            patch[i] = (byte) Integer.parseInt(hexBytes.substring(i*2, i*2+2), 16);

        Address a = parseAddr(addrParam);
        if (a == null) { sendResponse(ex, 400, "Invalid address: " + addrParam); return; }

        int tx = prog().startTransaction("patch_bytes");
        try {
            // Make the block writable if needed
            MemoryBlock block = prog().getMemory().getBlock(a);
            if (block != null && !block.isWrite()) block.setWrite(true);

            prog().getListing().clearCodeUnits(a, a.add(patch.length - 1), false);
            prog().getMemory().setBytes(a, patch);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Patched " + patch.length + " byte(s) @ " + addrParam);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handlePatchInstruction(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrParam = b.get("address"), asmText = b.get("asm");
        if (addrParam == null || asmText == null) { sendResponse(ex, 400, "address and asm required"); return; }

        Address a = parseAddr(addrParam);
        if (a == null) { sendResponse(ex, 400, "Invalid address: " + addrParam); return; }

        int tx = prog().startTransaction("patch_instruction");
        try {
            // Make the block writable if needed
            MemoryBlock block = prog().getMemory().getBlock(a);
            if (block != null && !block.isWrite()) block.setWrite(true);

            // Clear existing instruction(s) in a 15-byte window before assembling.
            // 15 bytes is the maximum length of a single x86-64 instruction.
            // This prevents MemoryAccessException: conflicts with instruction.
            prog().getListing().clearCodeUnits(a, a.add(15), false);

            Assembler asm = Assemblers.getAssembler(prog());
            try {
                // asm.assemble() writes bytes to memory; read them back to report
                asm.assemble(a, asmText);
                // Read back the assembled bytes to report length and hex
                Instruction insn = prog().getListing().getInstructionAt(a);
                int encodedLen = (insn != null) ? insn.getLength() : 1;
                byte[] encoded = new byte[encodedLen];
                prog().getMemory().getBytes(a, encoded);
                prog().endTransaction(tx, true);
                sendResponse(ex, 200,
                    "Assembled [" + asmText + "] @ " + addrParam
                    + " (" + encodedLen + " byte(s): " + bytesToHex(encoded) + ")");
            } catch (AssemblySemanticException | AssemblySyntaxException asmEx) {
                prog().endTransaction(tx, false);
                String tip = "Assembly failed for [" + asmText + "]: " + asmEx.getMessage() + "\n"
                    + "Use patch_bytes with raw hex instead. Common encodings:\n"
                    + "  NOP         = 90\n"
                    + "  RET         = C3\n"
                    + "  XOR EAX,EAX = 31C0\n"
                    + "  MOV EAX,1   = B801000000\n"
                    + "  JMP rel8    = EB<offset> (2 bytes)\n"
                    + "  JNE rel8    = 75<offset> NOP with 9090\n"
                    + "  JE  rel8    = 74<offset> NOP with 9090";
                sendResponse(ex, 400, tip);
            } catch (Exception e) {
                prog().endTransaction(tx, false);
                sendResponse(ex, 500,
                    "patch_instruction failed: " + e.getMessage()
                    + "\nUse patch_bytes with raw hex as a reliable fallback.");
            }
        } catch (Exception outer) {
            try { prog().endTransaction(tx, false); } catch (Exception ignored) {}
            sendResponse(ex, 500, "patch_instruction error: " + outer.getMessage());
        }
    }

    private void handleNopRange(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String startStr = b.get("start"), endStr = b.get("end");
        if (startStr == null || endStr == null) { sendResponse(ex, 400, "start and end required"); return; }

        Address start = parseAddr(startStr);
        Address end   = parseAddr(endStr);
        if (start == null) { sendResponse(ex, 400, "Invalid start address: " + startStr); return; }
        if (end   == null) { sendResponse(ex, 400, "Invalid end address: "   + endStr);   return; }

        int tx = prog().startTransaction("nop_range");
        try {
            int count = (int)(end.subtract(start)) + 1;
            byte[] nops = new byte[count];
            Arrays.fill(nops, (byte)0x90);

            // Make ALL blocks in range writable (range may span multiple blocks)
            for (MemoryBlock mb : prog().getMemory().getBlocks()) {
                if (!mb.isInitialized() || !mb.isLoaded()) continue;
                if (mb.getEnd().compareTo(start) < 0) continue;
                if (mb.getStart().compareTo(end) > 0) continue;
                if (!mb.isWrite()) mb.setWrite(true);
            }

            prog().getListing().clearCodeUnits(start, end, false);
            prog().getMemory().setBytes(start, nops);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "NOP'd " + count + " byte(s) from " + startStr + " to " + endStr);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleSetComment(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrParam = b.get("address"), comment = b.get("comment");
        String type = b.getOrDefault("type","EOL").toUpperCase();
        if (addrParam == null || comment == null) { sendResponse(ex, 400, "address and comment required"); return; }
        Address a = parseAddr(addrParam);
        if (a == null) { sendResponse(ex, 400, "Invalid address: " + addrParam); return; }
        int commentType;
        switch (type) {
            case "PRE":        commentType = 1; break;
            case "POST":       commentType = 2; break;
            case "PLATE":      commentType = 3; break;
            case "REPEATABLE": commentType = 4; break;
            default:           commentType = 0; break;
        }
        int tx = prog().startTransaction("set_comment");
        try {
            prog().getListing().setComment(a, commentType, comment);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Comment set @ " + addrParam);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleSetBookmark(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrParam = b.get("address");
        if (addrParam == null) { sendResponse(ex, 400, "address required"); return; }
        Address a = parseAddr(addrParam);
        if (a == null) { sendResponse(ex, 400, "Invalid address: " + addrParam); return; }
        String category = b.getOrDefault("category","MCP");
        String note = b.getOrDefault("note","");
        int tx = prog().startTransaction("set_bookmark");
        try {
            prog().getBookmarkManager().setBookmark(a, BookmarkType.NOTE, category, note);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Bookmark set @ " + addrParam);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleSetDataType(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrParam = b.get("address"), typeName = b.get("type");
        if (addrParam == null || typeName == null) { sendResponse(ex, 400, "address and type required"); return; }
        Address a = parseAddr(addrParam);
        if (a == null) { sendResponse(ex, 400, "Invalid address: " + addrParam); return; }
        DataTypeManager dtm = prog().getDataTypeManager();
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt == null) {
            // Try without leading slash (some types are at root)
            dt = dtm.getDataType(typeName);
        }
        if (dt == null) { sendResponse(ex, 404, "Unknown data type: " + typeName); return; }
        int tx = prog().startTransaction("set_data_type");
        try {
            prog().getListing().clearCodeUnits(a, a.add(dt.getLength()-1), false);
            prog().getListing().createData(a, dt);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Data type '" + typeName + "' applied @ " + addrParam);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    /**
     * FIX 1a: set_function_signature — was never registered, now wired up.
     * Parses the C prototype string and applies it via FlatProgramAPI.
     */
    private void handleSetFunctionSignature(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String funcName = b.get("name"), sig = b.get("signature");
        if (funcName == null || sig == null) { sendResponse(ex, 400, "name and signature required"); return; }
        Function f = findFunctionByName(funcName);
        if (f == null) { sendResponse(ex, 404, "Function not found: " + funcName); return; }
        int tx = prog().startTransaction("set_function_signature");
        try {
            // Build a FunctionDefinitionDataType from the signature string using
            // Ghidra's built-in C parser via the program's data type manager.
            ghidra.app.util.cparser.C.CParser parser =
                new ghidra.app.util.cparser.C.CParser(prog().getDataTypeManager());
            String sigNorm = sig.trim().replaceAll(";+$", "");
            DataType dt = parser.parse(sigNorm + ";");
            if (!(dt instanceof ghidra.program.model.data.FunctionDefinitionDataType)) {
                throw new Exception("Parsed type is not a function definition: " + dt.getClass().getSimpleName());
            }
            ghidra.program.model.data.FunctionDefinitionDataType fdt =
                (ghidra.program.model.data.FunctionDefinitionDataType) dt;
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                f.getEntryPoint(), fdt, SourceType.USER_DEFINED);
            cmd.applyTo(prog(), TaskMonitor.DUMMY);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Signature applied to " + funcName + ": " + sig);
        } catch (Exception e) {
            try { prog().endTransaction(tx, false); } catch (Exception ignored) {}
            sendResponse(ex, 500, "Signature parse failed: " + e.getMessage() +
                "\nTip: use full C prototype, e.g. 'int foo(char* a, int b)'");
        }
    }

    /**
     * FIX 1b: run_analysis — was never registered, now wired up.
     */
    private void handleRunAnalysis(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        int tx = prog().startTransaction("run_analysis");
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(prog());
            mgr.reAnalyzeAll(null);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Analysis scheduled. Check Ghidra's Analysis menu for progress.");
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    // ── EXPORT ────────────────────────────────────────────────────────────────

    private void handleExportBinary(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String outPath = b.get("path");
        if (outPath == null) { sendResponse(ex, 400, "path required"); return; }

        String origPath = prog().getExecutablePath();
        if (origPath == null || origPath.isEmpty()) {
            sendResponse(ex, 500, "Cannot determine original executable path from Ghidra"); return;
        }
        File origFile = new File(origPath);
        if (!origFile.exists()) {
            sendResponse(ex, 500, "Original file not found: " + origPath); return;
        }

        File outFile = new File(outPath);
        if (outFile.getParentFile() != null) outFile.getParentFile().mkdirs();

        // Step 1: copy original file verbatim — ELF/PE structure fully preserved
        Files.copy(origFile.toPath(), outFile.toPath(),
                   java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        // Step 2: read original file bytes into memory for diff comparison
        byte[] origBytes = Files.readAllBytes(origFile.toPath());

        // Step 3: Only patch executable sections (.text and similar).
        // NEVER touch .got, .got.plt, .plt, .dynamic, .data — Ghidra stores
        // resolved runtime addresses there which differ from on-disk relocatable
        // entries, causing GOT corruption and SIGSEGV on startup.
        int patchCount = 0;
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(outFile, "rw")) {
            for (MemoryBlock block : prog().getMemory().getBlocks()) {
                if (!block.isInitialized()) continue;
                if (!block.isExecute()) continue; // ONLY executable blocks (.text)

                java.util.List<MemoryBlockSourceInfo> infos = block.getSourceInfos();
                if (infos == null || infos.isEmpty()) continue;

                MemoryBlockSourceInfo info = infos.get(0);
                long fileOffset = info.getFileBytesOffset();
                if (fileOffset < 0) continue;

                long blockSize = block.getSize();
                long available = origBytes.length - fileOffset;
                if (available <= 0) continue;
                int readSize = (int) Math.min(blockSize, available);

                // Read current (possibly patched) bytes from Ghidra memory
                byte[] memBytes = new byte[readSize];
                block.getBytes(block.getStart(), memBytes);

                // Write ONLY bytes that differ from original (surgical patch)
                for (int i = 0; i < readSize; i++) {
                    if (memBytes[i] != origBytes[(int)(fileOffset + i)]) {
                        raf.seek(fileOffset + i);
                        raf.write(memBytes[i]);
                        patchCount++;
                    }
                }
            }
        }

        outFile.setExecutable(true);
        if (patchCount == 0) {
            sendResponse(ex, 200, "WARNING: no byte differences found — exported unmodified copy of " + origPath);
        } else {
            sendResponse(ex, 200, "Exported to " + outPath +
                " (" + patchCount + " byte(s) patched from original: " + origPath + ")");
        }
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    private Function findFunctionByName(String name) {
        FunctionIterator it = prog().getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.getName().equals(name)) return f;
        }
        return null;
    }
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

}
