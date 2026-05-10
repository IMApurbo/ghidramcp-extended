package ghidramcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
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
import ghidra.util.task.TaskMonitor;

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
        server.createContext("/list_methods",       ex -> safe(ex, this::handleListMethods));
        server.createContext("/list_classes",        ex -> safe(ex, this::handleListClasses));
        server.createContext("/list_imports",        ex -> safe(ex, this::handleListImports));
        server.createContext("/list_exports",        ex -> safe(ex, this::handleListExports));
        server.createContext("/list_segments",       ex -> safe(ex, this::handleListSegments));
        server.createContext("/list_strings",        ex -> safe(ex, this::handleListStrings));
        server.createContext("/decompile_function",  ex -> safe(ex, this::handleDecompile));
        server.createContext("/get_function_by_name",ex -> safe(ex, this::handleGetFunctionByName));
        server.createContext("/read_bytes",          ex -> safe(ex, this::handleReadBytes));
        server.createContext("/xrefs_to",            ex -> safe(ex, this::handleXrefsTo));
        server.createContext("/xrefs_from",          ex -> safe(ex, this::handleXrefsFrom));
        server.createContext("/search_bytes",        ex -> safe(ex, this::handleSearchBytes));
        server.createContext("/search_strings",      ex -> safe(ex, this::handleSearchStrings));
        // WRITE
        server.createContext("/rename_function",     ex -> safe(ex, this::handleRenameFunction));
        server.createContext("/rename_data",         ex -> safe(ex, this::handleRenameData));
        server.createContext("/rename_variable",     ex -> safe(ex, this::handleRenameVariable));
        server.createContext("/patch_bytes",         ex -> safe(ex, this::handlePatchBytes));
        server.createContext("/patch_instruction",   ex -> safe(ex, this::handlePatchInstruction));
        server.createContext("/nop_range",           ex -> safe(ex, this::handleNopRange));
        server.createContext("/set_comment",         ex -> safe(ex, this::handleSetComment));
        server.createContext("/set_bookmark",        ex -> safe(ex, this::handleSetBookmark));
        server.createContext("/set_data_type",       ex -> safe(ex, this::handleSetDataType));
        // EXPORT
        server.createContext("/export_binary",       ex -> safe(ex, this::handleExportBinary));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    @FunctionalInterface interface Handler { void handle(HttpExchange ex) throws Exception; }

    private void safe(HttpExchange ex, Handler h) {
        try { h.handle(ex); }
        catch (Exception e) {
            try { sendResponse(ex, 500, "Error: " + e.getMessage()); }
            catch (IOException ignored) {}
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

    private Address addr(String s) {
        return prog().getAddressFactory().getAddress(s);
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
        // Iterate all symbols and filter by namespace type
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
        decomp.openProgram(prog());
        DecompileResults res = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
        if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
            sendResponse(ex, 200, res.getDecompiledFunction().getC());
        } else {
            sendResponse(ex, 500, "Decompilation failed: " + res.getErrorMessage());
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
            "name: " + f.getName() + "\n" +
            "address: " + addrStr(f.getEntryPoint()) + "\n" +
            "signature: " + f.getSignature().getPrototypeString() + "\n" +
            "size: " + f.getBody().getNumAddresses() + " bytes");
    }

    private void handleReadBytes(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String addrStr = q.get("address");
        int length = Integer.parseInt(q.getOrDefault("length","16"));
        if (addrStr == null) { sendResponse(ex, 400, "?address= required"); return; }
        byte[] buf = new byte[length];
        prog().getMemory().getBytes(addr(addrStr), buf);
        StringBuilder sb = new StringBuilder();
        for (byte b : buf) sb.append(String.format("%02x ", b));
        sendResponse(ex, 200, sb.toString().trim());
    }

    private void handleXrefsTo(HttpExchange ex) throws Exception {
        if (!checkProgram(ex)) return;
        Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
        String a = q.get("address");
        if (a == null) { sendResponse(ex, 400, "?address= required"); return; }
        StringBuilder sb = new StringBuilder();
        for (Reference r : prog().getReferenceManager().getReferencesTo(addr(a)))
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
        StringBuilder sb = new StringBuilder();
        for (Reference r : prog().getReferenceManager().getReferencesFrom(addr(a)))
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
        if (b.containsKey("address"))
            f = prog().getFunctionManager().getFunctionAt(addr(b.get("address")));
        else if (b.containsKey("old_name"))
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
        String addrStr = b.get("address"), newName = b.get("new_name");
        if (addrStr == null || newName == null) { sendResponse(ex, 400, "address and new_name required"); return; }
        int tx = prog().startTransaction("rename_data");
        try {
            Address a = addr(addrStr);
            Symbol sym = prog().getSymbolTable().getPrimarySymbol(a);
            if (sym != null) sym.setName(newName, SourceType.USER_DEFINED);
            else prog().getSymbolTable().createLabel(a, newName, SourceType.USER_DEFINED);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Label set: " + newName + " @ " + addrStr);
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
        decomp.openProgram(prog());
        DecompileResults res = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
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

    private void handlePatchBytes(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrStr = b.get("address"), hexBytes = b.get("bytes");
        if (addrStr == null || hexBytes == null) { sendResponse(ex, 400, "address and bytes required"); return; }
        hexBytes = hexBytes.replaceAll("\\s","");
        byte[] patch = new byte[hexBytes.length()/2];
        for (int i = 0; i < patch.length; i++)
            patch[i] = (byte) Integer.parseInt(hexBytes.substring(i*2, i*2+2), 16);
        int tx = prog().startTransaction("patch_bytes");
        try {
            Address a = addr(addrStr);
            prog().getMemory().setBytes(a, patch);
            // Clear stale disassembly so listing stays correct
            prog().getListing().clearCodeUnits(a, a.add(patch.length - 1), false);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Patched " + patch.length + " byte(s) @ " + addrStr);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handlePatchInstruction(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrStr = b.get("address"), asmText = b.get("asm");
        if (addrStr == null || asmText == null) { sendResponse(ex, 400, "address and asm required"); return; }
        int tx = prog().startTransaction("patch_instruction");
        try {
            Address a = addr(addrStr);
            Assembler asm = Assemblers.getAssembler(prog());
            asm.assemble(a, asmText);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Assembled '" + asmText + "' @ " + addrStr);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleNopRange(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String startStr = b.get("start"), endStr = b.get("end");
        if (startStr == null || endStr == null) { sendResponse(ex, 400, "start and end required"); return; }
        int tx = prog().startTransaction("nop_range");
        try {
            Address start = addr(startStr), end = addr(endStr);
            int count = (int)(end.subtract(start)) + 1;
            byte[] nops = new byte[count];
            Arrays.fill(nops, (byte)0x90); // x86 NOP; adjust for other archs
            prog().getMemory().setBytes(start, nops);
            prog().getListing().clearCodeUnits(start, end, false);
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
        String addrStr = b.get("address"), comment = b.get("comment");
        String type = b.getOrDefault("type","EOL").toUpperCase();
        if (addrStr == null || comment == null) { sendResponse(ex, 400, "address and comment required"); return; }
        // Use integer constants directly to avoid deprecated symbol issues
        int commentType;
        switch (type) {
            case "PRE":        commentType = 1; break; // CodeUnit.PRE_COMMENT
            case "POST":       commentType = 2; break; // CodeUnit.POST_COMMENT
            case "PLATE":      commentType = 3; break; // CodeUnit.PLATE_COMMENT
            case "REPEATABLE": commentType = 4; break; // CodeUnit.REPEATABLE_COMMENT
            default:           commentType = 0; break; // CodeUnit.EOL_COMMENT
        }
        int tx = prog().startTransaction("set_comment");
        try {
            prog().getListing().setComment(addr(addrStr), commentType, comment);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Comment set @ " + addrStr);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleSetBookmark(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrStr = b.get("address");
        if (addrStr == null) { sendResponse(ex, 400, "address required"); return; }
        String category = b.getOrDefault("category","MCP");
        String note = b.getOrDefault("note","");
        int tx = prog().startTransaction("set_bookmark");
        try {
            prog().getBookmarkManager().setBookmark(addr(addrStr),
                BookmarkType.NOTE, category, note);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Bookmark set @ " + addrStr);
        } catch (Exception e) {
            prog().endTransaction(tx, false);
            throw e;
        }
    }

    private void handleSetDataType(HttpExchange ex) throws Exception {
        if (!requirePost(ex) || !checkProgram(ex)) return;
        Map<String,String> b = parseBody(ex);
        String addrStr = b.get("address"), typeName = b.get("type");
        if (addrStr == null || typeName == null) { sendResponse(ex, 400, "address and type required"); return; }
        DataTypeManager dtm = prog().getDataTypeManager();
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt == null) { sendResponse(ex, 404, "Unknown data type: " + typeName); return; }
        int tx = prog().startTransaction("set_data_type");
        try {
            Address a = addr(addrStr);
            prog().getListing().clearCodeUnits(a, a.add(dt.getLength()-1), false);
            prog().getListing().createData(a, dt);
            prog().endTransaction(tx, true);
            sendResponse(ex, 200, "Data type '" + typeName + "' applied @ " + addrStr);
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

        // Export: read every initialized byte from memory and write to file
        // This works regardless of format because we write the raw memory image
        File outFile = new File(outPath);
        outFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            for (MemoryBlock block : prog().getMemory().getBlocks()) {
                if (!block.isInitialized()) continue;
                byte[] buf = new byte[(int) block.getSize()];
                block.getBytes(block.getStart(), buf);
                fos.write(buf);
            }
        }
        sendResponse(ex, 200, "Exported " + outFile.length() + " bytes to " + outPath);
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
}
