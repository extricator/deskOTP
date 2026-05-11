#!/usr/bin/env python3
"""Generate Linux icon variants from build/appicon.png.

Run with: uv run --with Pillow python3 scripts/generate-linux-icons.py
"""
import os
from PIL import Image

SOURCE = "build/appicon.png"
SIZES = [48, 128, 256]

with Image.open(SOURCE) as img:
    img = img.convert("RGBA")
    for size in SIZES:
        out_dir = f"build/linux/icons/{size}x{size}"
        os.makedirs(out_dir, exist_ok=True)
        resized = img.resize((size, size), Image.LANCZOS)
        resized.save(f"{out_dir}/deskotp.png")
        print(f"  {out_dir}/deskotp.png ({size}x{size})")

print("Done.")
