#!/bin/bash
# DroneAware Node — Binary Build Script
#
# Compiles ble_feeder.py and wifi_feeder.py into self-contained ARM64
# executables using PyInstaller. Run this on a Raspberry Pi 4 (64-bit OS)
# or any aarch64 Linux machine.
#
# Output: dist/ble_feeder  and  dist/wifi_feeder
#
# After building, copy the binaries to your server's static file host:
#   scp dist/ble_feeder dist/wifi_feeder user@droneaware.io:/srv/node/
#
# Usage:
#   bash build.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_VENV="$SCRIPT_DIR/.build_venv"
DIST_DIR="$SCRIPT_DIR/dist"

echo ""
echo "=================================================="
echo " DroneAware Node Binary Builder"
echo " Architecture: $(uname -m)"
echo "=================================================="
echo ""

# Verify ARM64
if [[ "$(uname -m)" != "aarch64" ]]; then
    echo "WARNING: This should be run on an aarch64 (ARM64) machine."
    echo "         Binaries built here will NOT run on Raspberry Pi (64-bit OS)."
    read -rp "Continue anyway? [y/N]: " CONT
    [[ "${CONT,,}" == "y" ]] || exit 1
fi

# ---------------------------------------------------------------------------
# 1. Build venv with PyInstaller + all feeder dependencies
# ---------------------------------------------------------------------------
echo "[1/3] Setting up build environment..."

python3 -m venv "$BUILD_VENV"
"$BUILD_VENV/bin/pip" install --quiet --upgrade pip
"$BUILD_VENV/bin/pip" install --quiet \
    "pyinstaller==6.19.0" \
    "bleak==2.1.1" \
    "requests==2.32.5" \
    "charset-normalizer==3.4.6"

echo "      Done."

# ---------------------------------------------------------------------------
# 2. Build binaries
# ---------------------------------------------------------------------------
echo "[2/3] Compiling binaries..."
mkdir -p "$DIST_DIR"

# ble_feeder — bleak uses DBus backends dynamically; collect all submodules
echo "      Building ble_feeder..."
"$BUILD_VENV/bin/pyinstaller" \
    --onefile \
    --distpath "$DIST_DIR" \
    --workpath "$SCRIPT_DIR/.build_work/ble" \
    --specpath "$SCRIPT_DIR/.build_specs" \
    --name ble_feeder \
    --collect-all bleak \
    --hidden-import bleak.backends.bluezdbus \
    --hidden-import bleak.backends.bluezdbus.scanner \
    --hidden-import bleak.backends.bluezdbus.client \
    "$SCRIPT_DIR/ble_feeder.py" \
    > /dev/null 2>&1

# wifi_feeder — scapy has extensive dynamic imports; collect everything
echo "      Building wifi_feeder..."
"$BUILD_VENV/bin/pyinstaller" \
    --onefile \
    --distpath "$DIST_DIR" \
    --workpath "$SCRIPT_DIR/.build_work/wifi" \
    --specpath "$SCRIPT_DIR/.build_specs" \
    --name wifi_feeder \
    "$SCRIPT_DIR/wifi_feeder.py" \
    > /dev/null 2>&1

echo "      Done."

# ---------------------------------------------------------------------------
# 3. Verify and report
# ---------------------------------------------------------------------------
echo "[3/3] Verifying output..."

for binary in ble_feeder wifi_feeder; do
    path="$DIST_DIR/$binary"
    if [[ -f "$path" ]]; then
        size=$(du -sh "$path" | cut -f1)
        echo "      $binary  ($size)  — OK"
    else
        echo "      ERROR: $binary not found in dist/"
        exit 1
    fi
done

echo ""
echo "=================================================="
echo " Build complete!"
echo ""
echo " Binaries are in: $DIST_DIR/"
echo ""
echo " Deploy to your server:"
echo "   scp $DIST_DIR/ble_feeder  $DIST_DIR/wifi_feeder \\"
echo "       user@droneaware.io:/srv/node/"
echo ""
echo " Test locally on this Pi:"
echo "   sudo $DIST_DIR/ble_feeder --help"
echo "   sudo $DIST_DIR/wifi_feeder --help"
echo "=================================================="
echo ""

# Clean up PyInstaller temp artifacts (keep dist/)
rm -rf "$SCRIPT_DIR/.build_work" "$SCRIPT_DIR/.build_specs"
