#!/usr/bin/env python3
"""
bridge_mcp_ghidra_extended.py
"""

import argparse
import asyncio
import sys
import urllib.parse
import urllib.request

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

parser = argparse.ArgumentParser(description="GhidraMCP Extended Bridge")
parser.add_argument("--transport",     default="stdio", choices=["stdio", "sse"])
parser.add_argument("--ghidra-server", default="http://127.0.0.1:8080/")
parser.add_argument("--mcp-host",      default="127.0.0.1")
parser.add_argument("--mcp-port",      type=int, default=8081)
args = parser.parse_args()

GHIDRA = args.ghidra_server.rstrip("/")

def ghidra_get(path, params=None):
    url = f"{GHIDRA}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read().decode("utf-8")
    except Exception as e:
        return f"ERROR: {e}"

def ghidra_post(path, data):
    url = f"{GHIDRA}{path}"
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode("utf-8")
    except Exception as e:
        return f"ERROR: {e}"

app = Server("ghidramcp-extended")

ALL_TOOLS = [

    Tool(name="list_methods",
         description="List all functions/methods in the open binary.",
         inputSchema={"type":"object","properties":{
             "offset":{"type":"integer","description":"Pagination offset (default 0)"},
             "limit": {"type":"integer","description":"Max results (default 100)"}
         }}),

    Tool(name="list_classes",
         description="List all classes/namespaces defined in the binary.",
         inputSchema={"type":"object","properties":{}}),

    Tool(name="list_imports",
         description="List all imported symbols.",
         inputSchema={"type":"object","properties":{}}),

    Tool(name="list_exports",
         description="List all exported symbols with their addresses.",
         inputSchema={"type":"object","properties":{}}),

    Tool(name="list_segments",
         description="List all memory segments/sections with permissions and addresses.",
         inputSchema={"type":"object","properties":{}}),

    Tool(name="list_strings",
         description="List all defined strings in the binary with their addresses.",
         inputSchema={"type":"object","properties":{}}),

    Tool(name="decompile_function",
         description="Decompile a function by name and return C pseudocode.",
         inputSchema={"type":"object","required":["name"],"properties":{
             "name":{"type":"string","description":"Function name"}
         }}),

    Tool(name="get_function_by_name",
         description="Look up a function by name and return its address and signature.",
         inputSchema={"type":"object","required":["name"],"properties":{
             "name":{"type":"string"}
         }}),

    Tool(name="read_bytes",
         description="Read raw bytes at an address (returned as hex).",
         inputSchema={"type":"object","required":["address"],"properties":{
             "address":{"type":"string","description":"Hex address e.g. 0x00401000"},
             "length": {"type":"integer","description":"Number of bytes (default 16)"}
         }}),

    Tool(name="xrefs_to",
         description="List all cross-references TO a given address.",
         inputSchema={"type":"object","required":["address"],"properties":{
             "address":{"type":"string"}
         }}),

    Tool(name="xrefs_from",
         description="List all cross-references FROM a given address.",
         inputSchema={"type":"object","required":["address"],"properties":{
             "address":{"type":"string"}
         }}),

    Tool(name="search_bytes",
         description=(
             "Search memory for a byte pattern. Use ?? as a wildcard byte. "
             "Example: 'e8????????85c0' finds a call followed by test eax,eax."
         ),
         inputSchema={"type":"object","required":["pattern"],"properties":{
             "pattern":{"type":"string","description":"Hex pattern with optional ?? wildcards"}
         }}),

    Tool(name="search_strings",
         description="Search all defined strings for a substring (case-insensitive).",
         inputSchema={"type":"object","required":["query"],"properties":{
             "query":{"type":"string"}
         }}),

    Tool(name="rename_function",
         description="Rename a function by its current name or address.",
         inputSchema={"type":"object","required":["new_name"],"properties":{
             "old_name":{"type":"string"},
             "address": {"type":"string"},
             "new_name":{"type":"string"}
         }}),

    Tool(name="rename_data",
         description="Create or rename a data label at an address.",
         inputSchema={"type":"object","required":["address","new_name"],"properties":{
             "address": {"type":"string"},
             "new_name":{"type":"string"}
         }}),

    Tool(name="rename_variable",
         description="Rename a local variable inside a decompiled function.",
         inputSchema={"type":"object","required":["function","old_name","new_name"],"properties":{
             "function":{"type":"string"},
             "old_name":{"type":"string"},
             "new_name":{"type":"string"}
         }}),

    Tool(name="patch_bytes",
         description=(
             "Write raw bytes at an address. CRITICAL RULES:\n"
             "1. You MUST read_bytes at the target address first to see the current instruction.\n"
             "2. You MUST patch the COMPLETE instruction — never patch only part of a multi-byte instruction.\n"
             "   Example: 'jne rel8' is ALWAYS 2 bytes (75 XX). To NOP it: bytes='9090' (two NOPs).\n"
             "   Example: 'jne rel32' is ALWAYS 6 bytes (0F 85 XX XX XX XX). To NOP it: bytes='909090909090'.\n"
             "   Example: 'call rel32' is ALWAYS 5 bytes (E8 XX XX XX XX). To NOP it: bytes='9090909090'.\n"
             "   Example: 'test eax,eax' is ALWAYS 2 bytes (85 C0). To zero eax: bytes='31C0' (xor eax,eax).\n"
             "   Example: 'mov eax,1' + 'ret' = 6 bytes total: bytes='B801000000C3'.\n"
             "3. Count your hex chars: 2 hex chars = 1 byte. '9090' = 2 bytes. '909090' = 3 bytes.\n"
             "4. To force a function to always return true (1): patch entry with 'B801000000C3' (6 bytes).\n"
             "5. To force a function to always return false (0): patch entry with '31C0C3' (3 bytes).\n"
             "6. To bypass a conditional jump (jne/jnz 75 XX): always use bytes='9090' (2 NOPs, not 1).\n"
             "7. To bypass a conditional jump (je/jz 74 XX): always use bytes='9090' (2 NOPs, not 1).\n"
             "8. The listing is re-disassembled automatically after patching."
         ),
         inputSchema={"type":"object","required":["address","bytes"],"properties":{
             "address":{"type":"string","description":"Hex address of the first byte to patch"},
             "bytes":  {"type":"string","description":"Hex string of replacement bytes, no spaces. Length must cover the complete instruction(s)."}
         }}),

    Tool(name="patch_instruction",
         description=(
             "Assemble a single instruction and write it at an address using Ghidra's assembler.\n"
             "IMPORTANT RULES:\n"
             "1. Use this ONLY for simple instructions: NOP, MOV EAX,1, RET, JMP <addr>.\n"
             "2. For conditional jump bypasses, use patch_bytes with '9090' instead — it is more reliable.\n"
             "3. For 'always return true': use patch_bytes with 'B801000000C3' at function entry.\n"
             "4. For 'always return false/zero': use patch_bytes with '31C0C3' at function entry.\n"
             "5. JMP targets must be absolute hex addresses, e.g. 'JMP 0x00401050'.\n"
             "6. If patch_instruction returns HTTP 500, fall back to patch_bytes with the raw hex bytes.\n"
             "Common encodings for reference:\n"
             "  NOP            = 90\n"
             "  RET            = C3\n"
             "  XOR EAX,EAX    = 31 C0  (return 0)\n"
             "  MOV EAX,1      = B8 01 00 00 00  (return 1, must be followed by C3 ret)\n"
             "  JMP rel8       = EB XX  (2 bytes)\n"
             "  JMP rel32      = E9 XX XX XX XX  (5 bytes)\n"
             "  JE  rel8       = 74 XX  (2 bytes) — NOP with 9090\n"
             "  JNE rel8       = 75 XX  (2 bytes) — NOP with 9090\n"
             "  JE  rel32      = 0F 84 XX XX XX XX  (6 bytes) — NOP with 909090909090\n"
             "  JNE rel32      = 0F 85 XX XX XX XX  (6 bytes) — NOP with 909090909090\n"
             "  CALL rel32     = E8 XX XX XX XX  (5 bytes)"
         ),
         inputSchema={"type":"object","required":["address","asm"],"properties":{
             "address":{"type":"string","description":"Hex address to write the instruction"},
             "asm":    {"type":"string","description":"Assembly mnemonic + operands, e.g. 'MOV EAX, 1' or 'JMP 0x00401050'"}
         }}),

    Tool(name="nop_range",
         description=(
             "Fill an inclusive address range with NOP (0x90) bytes.\n"
             "CRITICAL: The end address is INCLUSIVE and must cover complete instructions.\n"
             "ALWAYS call read_bytes first to check instruction boundaries before using nop_range.\n"
             "Examples:\n"
             "  To NOP a 2-byte 'jne' at 0x1234: start='0x1234' end='0x1235'  (covers both bytes)\n"
             "  To NOP a 5-byte 'call' at 0x1234: start='0x1234' end='0x1238'\n"
             "  To NOP a 6-byte 'jne rel32' at 0x1234: start='0x1234' end='0x1239'\n"
             "NEVER set start==end for a multi-byte instruction — that only NOPs 1 byte and leaves "
             "the remaining bytes as garbage opcodes, causing illegal instruction crashes."
         ),
         inputSchema={"type":"object","required":["start","end"],"properties":{
             "start":{"type":"string","description":"Start address (inclusive)"},
             "end":  {"type":"string","description":"End address (inclusive). Must be start + instruction_length - 1."}
         }}),

    Tool(name="set_comment",
         description="Set a comment at an address.",
         inputSchema={"type":"object","required":["address","comment"],"properties":{
             "address":{"type":"string"},
             "comment":{"type":"string"},
             "type":   {"type":"string","description":"EOL | PRE | POST | PLATE | REPEATABLE (default EOL)"}
         }}),

    Tool(name="set_bookmark",
         description="Add a bookmark at an address.",
         inputSchema={"type":"object","required":["address"],"properties":{
             "address": {"type":"string"},
             "category":{"type":"string","description":"Bookmark category (default MCP)"},
             "note":    {"type":"string"}
         }}),

    Tool(name="set_function_signature",
         description="Apply a C-style function prototype to a function. Example: 'int check(char* input, int len)'",
         inputSchema={"type":"object","required":["name","signature"],"properties":{
             "name":     {"type":"string"},
             "signature":{"type":"string"}
         }}),

    Tool(name="set_data_type",
         description="Apply a Ghidra data type to an address (e.g. 'dword', 'char[16]').",
         inputSchema={"type":"object","required":["address","type"],"properties":{
             "address":{"type":"string"},
             "type":   {"type":"string"}
         }}),

    Tool(name="run_analysis",
         description="Trigger Ghidra auto-analysis on the currently open program.",
         inputSchema={"type":"object","properties":{}}),

    Tool(name="export_binary",
         description=(
             "Export the patched binary to disk. WORKFLOW RULES:\n"
             "1. Always apply ALL patches with patch_bytes/patch_instruction BEFORE calling export_binary.\n"
             "2. export_binary writes only the bytes that differ from the original — it never corrupts "
             "headers, GOT, PLT, or dynamic sections.\n"
             "3. The exported file is automatically made executable (chmod +x).\n"
             "4. path must be an absolute path on the Ghidra host, e.g. '/home/kali/patched_binary'.\n"
             "5. The response reports how many bytes were changed. If it says '0 bytes patched', "
             "the patches were not applied yet — apply them first then export again.\n"
             "6. Do NOT call export_binary in parallel with patch_bytes — always patch first, then export."
         ),
         inputSchema={"type":"object","required":["path"],"properties":{
             "path":  {"type":"string","description":"Absolute output path, e.g. /home/kali/patched_binary"},
             "format":{"type":"string","description":"binary (default) | intel_hex"}
         }}),
]


@app.list_tools()
async def list_tools():
    return ALL_TOOLS


@app.call_tool()
async def call_tool(name, arguments):
    def text(s):
        return [TextContent(type="text", text=s)]

    if name == "list_methods":
        return text(ghidra_get("/list_methods", {"offset": arguments.get("offset", 0), "limit": arguments.get("limit", 100)}))
    if name == "list_classes":
        return text(ghidra_get("/list_classes"))
    if name == "list_imports":
        return text(ghidra_get("/list_imports"))
    if name == "list_exports":
        return text(ghidra_get("/list_exports"))
    if name == "list_segments":
        return text(ghidra_get("/list_segments"))
    if name == "list_strings":
        return text(ghidra_get("/list_strings"))
    if name == "decompile_function":
        return text(ghidra_get("/decompile_function", {"name": arguments["name"]}))
    if name == "get_function_by_name":
        return text(ghidra_get("/get_function_by_name", {"name": arguments["name"]}))
    if name == "read_bytes":
        return text(ghidra_get("/read_bytes", {"address": arguments["address"], "length": arguments.get("length", 16)}))
    if name == "xrefs_to":
        return text(ghidra_get("/xrefs_to", {"address": arguments["address"]}))
    if name == "xrefs_from":
        return text(ghidra_get("/xrefs_from", {"address": arguments["address"]}))
    if name == "search_bytes":
        return text(ghidra_get("/search_bytes", {"pattern": arguments["pattern"]}))
    if name == "search_strings":
        return text(ghidra_get("/search_strings", {"query": arguments["query"]}))

    if name == "rename_function":
        data = {"new_name": arguments["new_name"]}
        if "old_name" in arguments: data["old_name"] = arguments["old_name"]
        if "address"  in arguments: data["address"]  = arguments["address"]
        return text(ghidra_post("/rename_function", data))
    if name == "rename_data":
        return text(ghidra_post("/rename_data", {"address": arguments["address"], "new_name": arguments["new_name"]}))
    if name == "rename_variable":
        return text(ghidra_post("/rename_variable", {"function": arguments["function"], "old_name": arguments["old_name"], "new_name": arguments["new_name"]}))

    if name == "patch_bytes":
        return text(ghidra_post("/patch_bytes", {"address": arguments["address"], "bytes": arguments["bytes"]}))
    if name == "patch_instruction":
        return text(ghidra_post("/patch_instruction", {"address": arguments["address"], "asm": arguments["asm"]}))
    if name == "nop_range":
        return text(ghidra_post("/nop_range", {"start": arguments["start"], "end": arguments["end"]}))

    if name == "set_comment":
        return text(ghidra_post("/set_comment", {"address": arguments["address"], "comment": arguments["comment"], "type": arguments.get("type", "EOL")}))
    if name == "set_bookmark":
        return text(ghidra_post("/set_bookmark", {"address": arguments["address"], "category": arguments.get("category", "MCP"), "note": arguments.get("note", "")}))
    if name == "set_function_signature":
        return text(ghidra_post("/set_function_signature", {"name": arguments["name"], "signature": arguments["signature"]}))
    if name == "set_data_type":
        return text(ghidra_post("/set_data_type", {"address": arguments["address"], "type": arguments["type"]}))
    if name == "run_analysis":
        return text(ghidra_post("/run_analysis", {}))
    if name == "export_binary":
        return text(ghidra_post("/export_binary", {"path": arguments["path"], "format": arguments.get("format", "binary")}))

    return text(f"Unknown tool: {name}")


async def main():
    if args.transport == "sse":
        try:
            from mcp.server.sse import SseServerTransport
            from starlette.applications import Starlette
            from starlette.routing import Route
            import uvicorn

            sse = SseServerTransport("/messages")

            async def handle_sse(request):
                async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
                    await app.run(streams[0], streams[1], app.create_initialization_options())

            async def handle_messages(request):
                await sse.handle_post_message(request.scope, request.receive, request._send)

            starlette_app = Starlette(routes=[
                Route("/sse", endpoint=handle_sse),
                Route("/messages", endpoint=handle_messages, methods=["POST"]),
            ])
            uvicorn.run(starlette_app, host=args.mcp_host, port=args.mcp_port)
        except ImportError as e:
            print(f"SSE needs: pip3 install uvicorn starlette --break-system-packages", file=sys.stderr)
            sys.exit(1)
    else:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
