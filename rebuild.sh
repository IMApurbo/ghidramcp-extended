#!/bin/bash
set -e
cd ~/ghidramcp-extended

echo "[1/4] Building Java plugin..."
mvn clean package assembly:single -q

echo "[2/4] Checking jar size..."
JAR=target/GhidraMCPExtended-1.0.0-jar-with-dependencies.jar
SIZE=$(stat -c%s "$JAR")
echo "      Jar size: $SIZE bytes"
if [ "$SIZE" -lt 50000 ]; then
  echo "ERROR: jar too small ($SIZE bytes) — assembly:single may have failed"
  exit 1
fi

echo "[3/4] Installing directly from target into Ghidra..."
cp "$JAR" ~/.ghidra/.ghidra_12.0.4_DEV/Extensions/GhidraMCPExtended/lib/GhidraMCPExtended.jar

echo "[4/4] Rebuilding zip from target..."
rm -rf dist_fixed
mkdir -p dist_fixed/GhidraMCPExtended/lib
mkdir -p dist_fixed/GhidraMCPExtended/data
cp dist/extension.properties      dist_fixed/GhidraMCPExtended/
cp dist/Module.manifest           dist_fixed/GhidraMCPExtended/
cp "$JAR"                         dist_fixed/GhidraMCPExtended/lib/GhidraMCPExtended.jar
touch dist_fixed/GhidraMCPExtended/data/ExtensionPoint.manifest
rm -f GhidraMCPExtended.zip
cd dist_fixed && zip -r ../GhidraMCPExtended.zip GhidraMCPExtended/ -q && cd ..

ls -lh ~/.ghidra/.ghidra_12.0.4_DEV/Extensions/GhidraMCPExtended/lib/GhidraMCPExtended.jar
echo "Done. Restart Ghidra to load the new plugin."
