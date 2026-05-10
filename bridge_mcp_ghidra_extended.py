#!/usr/bin/env python3
"""
bridge_mcp_ghidra_extended.py
==============================
Full-featured MCP bridge for Ghidra.

Usage (stdio, for Claude Desktop):
  python bridge_mcp_ghidra_extended.py

Usage (SSE, for Cline / web clients):
  python bridge_mcp_ghidra_extended.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081

The Ghidra HTTP server defaults to http://127.0.0.1:8080
Override with --ghidra-server http://HOST:PORT/
"""

import argparse
import asyncio
import sys
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="GhidraMCP Extended Bridge")
parser.add_argument("--transport",     default="stdio", choices=["stdio", "sse"])
parser.add_argument("--ghidra-server", default="http://127.0.0.1:8080/")
parser.add_argument("--mcp-host",      default="127.0.0.1")
parser.add_argument("--mcp-port",      type=int, default=8081)
args = parser.parse_args()

GHIDRA = args.ghidra_server.rstrip("/")

# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────

def ghidra_get(path: str, params: dict = None) -> str:
    url = f"{GHIDRA}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read().decode("utf-8")
    except Exception as e:
        return f"ERROR: {e}"

def ghidra_post(path: str, data: dict) -> str:
    url = f"{GHIDRA}{path}"
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8")
    except Exception as e:
        return f"ERROR: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# MCP server
# ─────────────────────────────────────────────────────────────────────────────

app = Server("ghidramcp-extended")

# ── Tool catalogue ────────────────────────────────────────────────────────────

ALL_TOOLS = [

    # ── READ ──────────────────────────────────────────────────────────────────
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
             "Example pattern: 'deadbeef??' finds 5-byte sequences starting with 0xDE 0xAD 0xBE 0xEF."
         ),
         inputSchema={"type":"object","required":["pattern"],"properties":{
             "pattern":{"type":"string","description":"Hex pattern, e.g. 'deadbeef??' or '558bec'"}
         }}),

    Tool(name="search_strings",
         description="Search all defined strings for a substring (case-insensitive).",
         inputSchema={"type":"object","required":["query"],"properties":{
             "query":{"type":"string"}
         }}),

    # ── RENAME ────────────────────────────────────────────────────────────────
    Tool(name="rename_function",
         description=(
             "Rename a function. Identify it either by its current name (old_name) "
             "or by its entry-point address."
         ),
         inputSchema={"type":"object","required":["new_name"],"properties":{
             "old_name":{"type":"string","description":"Current function name (optional if address given)"},
             "address": {"type":"string","description":"Entry-point address (optional if old_name given)"},
             "new_name":{"type":"string","description":"New name to assign"}
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
             "function":{"type":"string","description":"Function name that contains the variable"},
             "old_name":{"type":"string"},
             "new_name":{"type":"string"}
         }}),

    # ── PATCH ─────────────────────────────────────────────────────────────────
    Tool(name="patch_bytes",
         description=(
             "Write raw bytes at an address. The listing is re-disassembled after patching. "
             "bytes must be a hex string, e.g. '909090' for three NOPs."
         ),
         inputSchema={"type":"object","required":["address","bytes"],"properties":{
             "address":{"type":"string"},
             "bytes":  {"type":"string","description":"Hex bytes, no spaces, e.g. '9090'"}
         }}),

    Tool(name="patch_instruction",
         description=(
             "Assemble a single instruction and write it at an address using Ghidra's built-in assembler. "
             "Example asm: 'NOP', 'MOV EAX, 1', 'JMP 0x00401050'."
         ),
         inputSchema={"type":"object","required":["address","asm"],"properties":{
             "address":{"type":"string"},
             "asm":    {"type":"string","description":"Assembly mnemonic + operands"}
         }}),

    Tool(name="nop_range",
         description=(
             "Fill an inclusive address range with NOP (0x90) bytes. "
             "Useful for removing checks or dead-code elimination."
         ),
         inputSchema={"type":"object","required":["start","end"],"properties":{
             "start":{"type":"string","description":"Start address (inclusive)"},
             "end":  {"type":"string","description":"End address (inclusive)"}
         }}),

    # ── ANNOTATIONS ───────────────────────────────────────────────────────────
    Tool(name="set_comment",
         description="Set a comment at an address. type can be EOL, PRE, POST, PLATE, or REPEATABLE.",
         inputSchema={"type":"object","required":["address","comment"],"properties":{
             "address":{"type":"string"},
             "comment":{"type":"string"},
             "type":   {"type":"string","description":"EOL | PRE | POST | PLATE | REPEATABLE (default EOL)"}
         }}),

    Tool(name="set_bookmark",
         description="Add a bookmark at an address with an optional category and note.",
         inputSchema={"type":"object","required":["address"],"properties":{
             "address": {"type":"string"},
             "category":{"type":"string","description":"Bookmark category (default MCP)"},
             "note":    {"type":"string"}
         }}),

    # ── TYPES & SIGNATURES ────────────────────────────────────────────────────
    Tool(name="set_function_signature",
         description=(
             "Apply a C-style function prototype to a function. "
             "Example signature: 'int check_password(char* input, int len)'"
         ),
         inputSchema={"type":"object","required":["name","signature"],"properties":{
             "name":     {"type":"string","description":"Function name"},
             "signature":{"type":"string","description":"Full C prototype string"}
         }}),

    Tool(name="set_data_type",
         description="Apply a Ghidra data type to an address (e.g. 'dword', 'char[16]', 'DWORD').",
         inputSchema={"type":"object","required":["address","type"],"properties":{
             "address":{"type":"string"},
             "type":   {"type":"string","description":"Ghidra data type name"}
         }}),

    # ── ANALYSIS ──────────────────────────────────────────────────────────────
    Tool(name="run_analysis",
         description="Trigger Ghidra's auto-analysis on the currently open program.",
         inputSchema={"type":"object","properties":{}}),

    # ── EXPORT ────────────────────────────────────────────────────────────────
    Tool(name="export_binary",
         description=(
             "Export the (possibly patched) binary to disk. "
             "format can be 'binary' (raw, default) or 'intel_hex'."
         ),
         inputSchema={"type":"object","required":["path"],"properties":{
             "path":  {"type":"string","description":"Absolute output path on the Ghidra host"},
             "format":{"type":"string","description":"binary | intel_hex (default: binary)"}
         }}),
]


@app.list_tools()
async def list_tools():
    return ALL_TOOLS


# ── Tool dispatch ─────────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict):

    def text(s: str):
        return [TextContent(type="text", text=s)]

    # ── READ ──────────────────────────────────────────────────────────────────
    if name == "list_methods":
        return text(ghidra_get("/list_methods", {
            "offset": arguments.get("offset", 0),
            "limit":  arguments.get("limit",  100),
        }))

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
        return text(ghidra_get("/read_bytes", {
            "address": arguments["address"],
            "length":  arguments.get("length", 16),
        }))

    if name == "xrefs_to":
        return text(ghidra_get("/xrefs_to", {"address": arguments["address"]}))

    if name == "xrefs_from":
        return text(ghidra_get("/xrefs_from", {"address": arguments["address"]}))

    if name == "search_bytes":
        return text(ghidra_get("/search_bytes", {"pattern": arguments["pattern"]}))

    if name == "search_strings":
        return text(ghidra_get("/search_strings", {"query": arguments["query"]}))

    # ── RENAME ────────────────────────────────────────────────────────────────
    if name == "rename_function":
        data = {"new_name": arguments["new_name"]}
        if "old_name" in arguments: data["old_name"] = arguments["old_name"]
        if "address"  in arguments: data["address"]  = arguments["address"]
        return text(ghidra_post("/rename_function", data))

    if name == "rename_data":
        return text(ghidra_post("/rename_data", {
            "address":  arguments["address"],
            "new_name": arguments["new_name"],
        }))

    if name == "rename_variable":
        return text(ghidra_post("/rename_variable", {
            "function": arguments["function"],
            "old_name": arguments["old_name"],
            "new_name": arguments["new_name"],
        }))

    # ── PATCH ─────────────────────────────────────────────────────────────────
    if name == "patch_bytes":
        return text(ghidra_post("/patch_bytes", {
            "address": arguments["address"],
            "bytes":   arguments["bytes"],
        }))

    if name == "patch_instruction":
        return text(ghidra_post("/patch_instruction", {
            "address": arguments["address"],
            "asm":     arguments["asm"],
        }))

    if name == "nop_range":
        return text(ghidra_post("/nop_range", {
            "start": arguments["start"],
            "end":   arguments["end"],
        }))

    # ── ANNOTATIONS ───────────────────────────────────────────────────────────
    if name == "set_comment":
        return text(ghidra_post("/set_comment", {
            "address": arguments["address"],
            "comment": arguments["comment"],
            "type":    arguments.get("type", "EOL"),
        }))

    if name == "set_bookmark":
        return text(ghidra_post("/set_bookmark", {
            "address":  arguments["address"],
            "category": arguments.get("category", "MCP"),
            "note":     arguments.get("note", ""),
        }))

    # ── TYPES ─────────────────────────────────────────────────────────────────
    if name == "set_function_signature":
        return text(ghidra_post("/set_function_signature", {
            "name":      arguments["name"],
            "signature": arguments["signature"],
        }))

    if name == "set_data_type":
        return text(ghidra_post("/set_data_type", {
            "address": arguments["address"],
            "type":    arguments["type"],
        }))

    # ── ANALYSIS ──────────────────────────────────────────────────────────────
    if name == "run_analysis":
        return text(ghidra_post("/run_analysis", {}))

    # ── EXPORT ────────────────────────────────────────────────────────────────
    if name == "export_binary":
        return text(ghidra_post("/export_binary", {
            "path":   arguments["path"],
            "format": arguments.get("format", "binary"),
        }))

    return text(f"Unknown tool: {name}")


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

async def main():
    if args.transport == "sse":
        # SSE transport for web clients / Cline
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
            print(f"SSE transport requires extra packages: {e}", file=sys.stderr)
            print("Install with: pip3 install uvicorn starlette --break-system-packages", file=sys.stderr)
            sys.exit(1)
    else:
        # stdio transport for Claude Desktop
        from mcp.server.models import InitializationOptions
        import mcp.types as types

        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )


if __name__ == "__main__":
    asyncio.run(main())
