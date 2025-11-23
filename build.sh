#!/bin/bash
# Build script for Etherchimp standalone binary

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  Etherchimp Standalone Binary Builder"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if PyInstaller is installed
if ! command -v pyinstaller &> /dev/null && ! python3 -m PyInstaller --version &> /dev/null 2>&1; then
    echo -e "${YELLOW}PyInstaller not found. Installing...${NC}"
    pip install pyinstaller
fi

# Clean previous builds
echo -e "${GREEN}[1/4] Cleaning previous builds...${NC}"
rm -rf build/ dist/ __pycache__
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Build type selection
BUILD_TYPE="${1:-onefile}"

if [ "$BUILD_TYPE" = "onedir" ]; then
    echo -e "${GREEN}[2/4] Building directory-based distribution...${NC}"
    echo "This will create a folder with the executable and dependencies."
    echo "Faster startup, but larger distribution size."

    # Modify spec file for onedir build
    sed -i.bak 's/^exe = EXE(/# ONEFILE VERSION\n# exe = EXE(/' etherchimp.spec
    sed -i 's/^# exe = EXE(/exe = EXE(/' etherchimp.spec
    sed -i 's/^# coll = COLLECT(/coll = COLLECT(/' etherchimp.spec
else
    echo -e "${GREEN}[2/4] Building single-file executable...${NC}"
    echo "This will create a single portable binary."
    echo "Slower startup (extraction needed), but easier to distribute."
fi

# Run PyInstaller
echo -e "${GREEN}[3/4] Running PyInstaller...${NC}"
/usr/local/bin/pyinstaller --clean etherchimp.spec

# Restore original spec if modified
if [ -f etherchimp.spec.bak ]; then
    mv etherchimp.spec.bak etherchimp.spec
fi

# Display results
echo ""
echo -e "${GREEN}[4/4] Build complete!${NC}"
echo ""
echo "=========================================="
echo "  Build Results"
echo "=========================================="

if [ "$BUILD_TYPE" = "onedir" ]; then
    if [ -f "dist/etherchimp/etherchimp" ]; then
        SIZE=$(du -sh dist/etherchimp | cut -f1)
        echo -e "Output directory: ${GREEN}dist/etherchimp/${NC}"
        echo -e "Executable: ${GREEN}dist/etherchimp/etherchimp${NC}"
        echo -e "Total size: ${YELLOW}$SIZE${NC}"
        echo ""
        echo "To run: ./dist/etherchimp/etherchimp -p 5001"
    else
        echo -e "${RED}Build failed! Check the output above for errors.${NC}"
        exit 1
    fi
else
    if [ -f "dist/etherchimp" ]; then
        SIZE=$(du -sh dist/etherchimp | cut -f1)
        echo -e "Executable: ${GREEN}dist/etherchimp${NC}"
        echo -e "Size: ${YELLOW}$SIZE${NC}"
        echo ""
        echo "To run: ./dist/etherchimp -p 5001"
        echo ""
        echo -e "${YELLOW}Note: First run will be slower due to extraction.${NC}"
    else
        echo -e "${RED}Build failed! Check the output above for errors.${NC}"
        exit 1
    fi
fi

echo ""
echo "=========================================="
echo "  Usage Instructions"
echo "=========================================="
echo ""
echo "The binary requires root/sudo for packet capture:"
echo "  sudo ./dist/etherchimp -p 5001"
echo ""
echo "Available command-line options:"
echo "  -p, --port PORT    : Specify port (default: 5000)"
echo "  -d, --daemon       : Run as daemon"
echo "  --stop            : Stop daemon"
echo "  --restart         : Restart daemon"
echo "  --status          : Check daemon status"
echo ""
echo -e "${GREEN}Build successful!${NC}"
