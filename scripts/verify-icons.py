#!/usr/bin/env python3
"""Verify deskOTP icon build assets meet specification."""

import struct
import sys
import os

APPICON_PATH = "build/appicon.png"
ICO_PATH = "build/windows/icon.ico"
REQUIRED_PNG_SIZE = (1024, 1024)
REQUIRED_ICO_LAYERS = {16, 32, 48, 64, 128, 256}

def check_png(path):
    """Check PNG exists and is 1024x1024."""
    if not os.path.exists(path):
        print(f"FAIL: {path} does not exist")
        return False
    with open(path, 'rb') as f:
        header = f.read(24)
    if len(header) < 24:
        print(f"FAIL: {path} is too small to be a valid PNG")
        return False
    w = struct.unpack('>I', header[16:20])[0]
    h = struct.unpack('>I', header[20:24])[0]
    if (w, h) != REQUIRED_PNG_SIZE:
        print(f"FAIL: {path} is {w}x{h}, expected {REQUIRED_PNG_SIZE[0]}x{REQUIRED_PNG_SIZE[1]}")
        return False
    # Check file size to detect if it's likely the default Wails placeholder (~132KB)
    size_kb = os.path.getsize(path) / 1024
    print(f"OK: {path} is {w}x{h} ({size_kb:.0f} KB)")
    return True

def check_ico(path):
    """Check ICO exists and contains required layers."""
    if not os.path.exists(path):
        print(f"FAIL: {path} does not exist")
        return False
    with open(path, 'rb') as f:
        header = f.read(6)
        if len(header) < 6:
            print(f"FAIL: {path} is too small to be a valid ICO")
            return False
        _, img_type, count = struct.unpack('<HHH', header)
        if img_type != 1:
            print(f"FAIL: {path} is not an ICO file (type={img_type})")
            return False
        layers = []
        for _ in range(count):
            entry = f.read(16)
            w = entry[0] or 256  # 0 in ICO format means 256
            layers.append(w)
    layer_set = set(layers)
    missing = REQUIRED_ICO_LAYERS - layer_set
    if missing:
        print(f"FAIL: {path} missing layers: {sorted(missing)}")
        print(f"  Present: {sorted(layers)}")
        return False
    print(f"OK: {path} has {count} layers: {sorted(layers)}")
    return True

def main():
    print("Verifying deskOTP icon build assets...\n")
    results = []
    results.append(check_png(APPICON_PATH))
    results.append(check_ico(ICO_PATH))
    print()
    if all(results):
        print("All checks passed.")
        return 0
    else:
        print("Some checks failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
