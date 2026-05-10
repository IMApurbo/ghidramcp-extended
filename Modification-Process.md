## Edit → Rebuild → Reinstall (Full Cycle)

### Step 1 — Edit your files
```bash
# Edit the Java plugin
nano ~/ghidramcp-extended/src/main/java/ghidramcp/GhidraMCPExtendedPlugin.java

# Edit the Python bridge
nano ~/ghidramcp-extended/bridge_mcp_ghidra_extended.py
```

---

### Step 2 — Rebuild the Java plugin
```bash
cd ~/ghidramcp-extended
mvn clean package assembly:single
```
Look for `BUILD SUCCESS` before continuing.

---

### Step 3 — Repackage the extension
```bash
cd ~/ghidramcp-extended

# Update the jar in dist_fixed
cp target/GhidraMCPExtended-1.0.0-jar-with-dependencies.jar \
   dist_fixed/GhidraMCPExtended/lib/GhidraMCPExtended.jar

# Rebuild the zip
rm -f GhidraMCPExtended.zip
cd dist_fixed
zip -r ../GhidraMCPExtended.zip GhidraMCPExtended/
cd ..
```

---

### Step 4 — Reinstall into Ghidra (manual, no GUI needed)
```bash
GHIDRA_EXT=~/.ghidra/.ghidra_12.0.4_DEV/Extensions

# Overwrite just the jar (fastest if only Java changed)
cp dist_fixed/GhidraMCPExtended/lib/GhidraMCPExtended.jar \
   "$GHIDRA_EXT/GhidraMCPExtended/lib/GhidraMCPExtended.jar"
```

---

### Step 5 — Restart Ghidra
Close and reopen Ghidra. The new jar is picked up automatically.

---

## One-liner Script (save this as `rebuild.sh`)

```bash
cat > ~/ghidramcp-extended/rebuild.sh << 'EOF'
#!/bin/bash
set -e
cd ~/ghidramcp-extended

echo "[1/4] Building Java plugin..."
mvn clean package assembly:single -q

echo "[2/4] Copying jar to dist..."
cp target/GhidraMCPExtended-1.0.0-jar-with-dependencies.jar \
   dist_fixed/GhidraMCPExtended/lib/GhidraMCPExtended.jar

echo "[3/4] Rebuilding zip..."
rm -f GhidraMCPExtended.zip
cd dist_fixed && zip -r ../GhidraMCPExtended.zip GhidraMCPExtended/ -q && cd ..

echo "[4/4] Installing into Ghidra..."
cp dist_fixed/GhidraMCPExtended/lib/GhidraMCPExtended.jar \
   ~/.ghidra/.ghidra_12.0.4_DEV/Extensions/GhidraMCPExtended/lib/GhidraMCPExtended.jar

echo "Done. Restart Ghidra to load the new plugin."
EOF

chmod +x ~/ghidramcp-extended/rebuild.sh
```

Then every time you make changes, just run:
```bash
cd ~/ghidramcp-extended && ./rebuild.sh
```

> The Python bridge (`bridge_mcp_ghidra_extended.py`) doesn't need any build step — changes take effect immediately on the next Claude Desktop restart since it's interpreted.
