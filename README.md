# GhidraMCP Extended

A full-featured Model Context Protocol (MCP) bridge for [Ghidra](https://ghidra-sre.org/), enabling AI assistants like Claude to interact directly with Ghidra's reverse engineering capabilities — reading, renaming, patching, annotating, and analyzing binaries through natural language.

---

## Features

- **Read** — list functions, classes, imports, exports, segments, strings, raw bytes
- **Decompile** — get C pseudocode for any function
- **Cross-references** — xrefs to/from any address
- **Search** — byte pattern search (with wildcards) and string search
- **Rename** — functions, data labels, and local variables
- **Patch** — write raw bytes, assemble instructions, NOP ranges
- **Annotate** — set comments (EOL, PRE, POST, PLATE, REPEATABLE) and bookmarks
- **Types** — apply function signatures and data types
- **Analysis** — trigger Ghidra's auto-analysis
- **Export** — dump the (patched) binary to disk

---

## Project Structure

```
ghidramcp-extended/
├── bridge_mcp_ghidra_extended.py       # MCP bridge (Python, runs as stdio/SSE server)
├── src/
│   └── main/java/ghidramcp/
│       └── GhidraMCPExtendedPlugin.java  # Ghidra plugin (Java, HTTP server on :8080)
├── lib/                                # Ghidra jars for compilation
├── pom.xml                             # Maven build file
├── dist/                               # Built extension files
│   ├── extension.properties
│   ├── Module.manifest
│   └── lib/
│       └── GhidraMCPExtended.jar
└── GhidraMCPExtended.zip               # Installable Ghidra extension
```

---

## Requirements

| Component | Requirement |
|---|---|
| Ghidra | 11.x or 12.x |
| Java | 21+ |
| Maven | 3.8+ |
| Python | 3.10+ |
| MCP package | `pip install mcp` |

---

## Installation

### Part 1 — Build the Ghidra Plugin

**1. Clone and set up the project**

```bash
git clone https://github.com/IMApurbo/ghidramcp-extended.git
cd ghidramcp-extended
```

**2. Copy Ghidra jars into `lib/`**

```bash
mkdir -p lib
GHIDRA=/usr/share/ghidra   # adjust to your Ghidra install path

cp $GHIDRA/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar lib/
cp $GHIDRA/Ghidra/Framework/Generic/lib/Generic.jar                   lib/
cp $GHIDRA/Ghidra/Framework/Project/lib/Project.jar                   lib/
cp $GHIDRA/Ghidra/Framework/Utility/lib/Utility.jar                   lib/
cp $GHIDRA/Ghidra/Framework/Docking/lib/Docking.jar                   lib/
cp $GHIDRA/Ghidra/Framework/DB/lib/DB.jar                             lib/
cp $GHIDRA/Ghidra/Framework/FileSystem/lib/FileSystem.jar             lib/
cp $GHIDRA/Ghidra/Features/Base/lib/Base.jar                          lib/
cp $GHIDRA/Ghidra/Features/Decompiler/lib/Decompiler.jar              lib/
cp $GHIDRA/Ghidra/Framework/Gui/lib/Gui.jar                           lib/
cp $GHIDRA/Ghidra/Features/WildcardAssembler/lib/WildcardAssembler.jar lib/
```

**3. Build the fat jar**

```bash
mvn clean package assembly:single
```

**4. Package as a Ghidra extension**

```bash
rm -rf dist_fixed
mkdir -p dist_fixed/GhidraMCPExtended/lib
mkdir -p dist_fixed/GhidraMCPExtended/data

cp dist/extension.properties          dist_fixed/GhidraMCPExtended/
cp dist/Module.manifest               dist_fixed/GhidraMCPExtended/
cp dist/lib/GhidraMCPExtended.jar     dist_fixed/GhidraMCPExtended/lib/
touch dist_fixed/GhidraMCPExtended/data/ExtensionPoint.manifest

cd dist_fixed
zip -r ../GhidraMCPExtended.zip GhidraMCPExtended/
cd ..
```

---

### Part 2 — Install the Extension into Ghidra

**Option A — Manual install (recommended)**

```bash
# Find your Ghidra profile directory (adjust version/release as needed)
GHIDRA_EXT=~/.ghidra/.ghidra_12.0.4_DEV/Extensions
mkdir -p "$GHIDRA_EXT/GhidraMCPExtended/lib"
mkdir -p "$GHIDRA_EXT/GhidraMCPExtended/data"

cp dist/extension.properties      "$GHIDRA_EXT/GhidraMCPExtended/"
cp dist/Module.manifest           "$GHIDRA_EXT/GhidraMCPExtended/"
cp dist/lib/GhidraMCPExtended.jar "$GHIDRA_EXT/GhidraMCPExtended/lib/"
touch "$GHIDRA_EXT/GhidraMCPExtended/data/ExtensionPoint.manifest"
```

Then restart Ghidra — the extension loads automatically.

**Option B — Via Ghidra GUI**

1. Open Ghidra → **File → Install Extensions**
2. Click the **green "+" button**
3. Select `GhidraMCPExtended.zip`
4. Click **OK** and restart Ghidra

**Enable the plugin after restart:**

Open a binary in the CodeBrowser → **File → Configure** → search for `GhidraMCPExtended` → check the box → **OK**

The HTTP server starts automatically on `http://127.0.0.1:8080` when a program is open.

---

### Part 3 — Set Up the Python Bridge

**1. Install dependencies**

```bash
pip3 install mcp --break-system-packages
```

**2. Test the bridge**

```bash
python3 bridge_mcp_ghidra_extended.py
# Should hang silently — it's waiting for MCP stdio input. Ctrl+C to exit.
```

---

### Part 4 — Connect to Claude Desktop

Edit (or create) `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python3",
      "args": [
        "/home/kali/ghidramcp-extended/bridge_mcp_ghidra_extended.py",
        "--transport", "stdio",
        "--ghidra-server", "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Restart Claude Desktop. You should see the Ghidra tools available (hammer icon).

---

## Usage

### SSE mode (for Cline, VS Code, web clients)

```bash
python3 bridge_mcp_ghidra_extended.py \
  --transport sse \
  --mcp-host 127.0.0.1 \
  --mcp-port 8081 \
  --ghidra-server http://127.0.0.1:8080/
```

Then point your MCP client at `http://127.0.0.1:8081/sse`.

### Custom Ghidra host

If Ghidra is running on a different machine:

```bash
python3 bridge_mcp_ghidra_extended.py --ghidra-server http://192.168.1.100:8080/
```

### Verify the Ghidra server is live

```bash
curl http://127.0.0.1:8080/list_methods
```

---

## Available MCP Tools

| Tool | Type | Description |
|---|---|---|
| `list_methods` | Read | All functions in the binary |
| `list_classes` | Read | All classes/namespaces |
| `list_imports` | Read | Imported symbols |
| `list_exports` | Read | Exported symbols with addresses |
| `list_segments` | Read | Memory segments/sections |
| `list_strings` | Read | All defined strings |
| `decompile_function` | Read | C pseudocode for a function |
| `get_function_by_name` | Read | Address and signature of a function |
| `read_bytes` | Read | Raw bytes at an address (hex) |
| `xrefs_to` | Read | Cross-references to an address |
| `xrefs_from` | Read | Cross-references from an address |
| `search_bytes` | Search | Byte pattern search with wildcard `??` |
| `search_strings` | Search | Substring search across all strings |
| `rename_function` | Write | Rename a function by name or address |
| `rename_data` | Write | Rename/create a data label |
| `rename_variable` | Write | Rename a local variable in a function |
| `patch_bytes` | Patch | Write raw hex bytes at an address |
| `patch_instruction` | Patch | Assemble and write a single instruction |
| `nop_range` | Patch | Fill an address range with NOPs |
| `set_comment` | Annotate | Set EOL/PRE/POST/PLATE/REPEATABLE comment |
| `set_bookmark` | Annotate | Add a bookmark with category and note |
| `set_function_signature` | Types | Apply a C prototype to a function |
| `set_data_type` | Types | Apply a Ghidra data type at an address |
| `run_analysis` | Analysis | Trigger Ghidra auto-analysis |
| `export_binary` | Export | Export the binary to disk |

---

## Troubleshooting

**Plugin not showing up in Ghidra**
Make sure you restarted Ghidra after installing the extension.

**`curl` returns connection refused**
You must have a binary open in the CodeBrowser, not just the Ghidra project window. The HTTP server only runs while a program is open.

**Port 8080 already in use**
```bash
lsof -i :8080   # find the occupying process
kill <PID>
```

**MCP server exits with code 1**
```bash
python3 bridge_mcp_ghidra_extended.py 2>&1   # see the full error
pip3 install mcp --break-system-packages       # reinstall if import fails
```

**Extension zip rejected by Ghidra installer**
Use the manual install (Option A above) — it bypasses the zip validator entirely.

---

## License

MIT License

Copyright (c) 2026 IMApurbo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Author

**IMApurbo** — [github.com/IMApurbo](https://github.com/IMApurbo)
