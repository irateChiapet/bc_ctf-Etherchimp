#!/bin/bash
# Build fully static binary using staticx (Linux only)
# This creates a truly standalone binary with zero external dependencies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  Etherchimp Static Binary Builder"
echo "  (Linux Only - Zero Dependencies)"
echo "=========================================="
echo ""

# Check if running on Linux
if [ "$(uname)" != "Linux" ]; then
    echo "ERROR: Static builds are only supported on Linux"
    exit 1
fi

# Check if staticx is installed
if ! command -v staticx &> /dev/null; then
    echo "Installing staticx..."
    pip install staticx

    # staticx requires patchelf
    if ! command -v patchelf &> /dev/null; then
        echo "Installing patchelf..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y patchelf
        elif command -v yum &> /dev/null; then
            yum install -y patchelf
        else
            echo "ERROR: Please install patchelf manually"
            exit 1
        fi
    fi
fi

# First build with PyInstaller
echo "[1/3] Building with PyInstaller..."
./build.sh onefile

if [ ! -f "dist/etherchimp" ]; then
    echo "ERROR: PyInstaller build failed"
    exit 1
fi

# Create static binary with staticx
echo ""
echo "[2/3] Creating fully static binary with staticx..."
staticx dist/etherchimp dist/etherchimp-static

# Display results
echo ""
echo "[3/3] Build complete!"
echo ""
echo "=========================================="
echo "  Static Build Results"
echo "=========================================="

if [ -f "dist/etherchimp-static" ]; then
    ORIGINAL_SIZE=$(du -sh dist/etherchimp | cut -f1)
    STATIC_SIZE=$(du -sh dist/etherchimp-static | cut -f1)

    echo "Original binary: $ORIGINAL_SIZE"
    echo "Static binary: $STATIC_SIZE"
    echo ""
    echo "Static binary location: dist/etherchimp-static"
    echo ""
    echo "This binary includes all system libraries and has ZERO dependencies."
    echo "It can run on any Linux system, even without Python or system libraries."
    echo ""
    echo "To run: sudo ./dist/etherchimp-static -p 5001"
else
    echo "ERROR: Static build failed"
    exit 1
fi
