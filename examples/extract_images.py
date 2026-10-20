"""Write each page's own image (JPEG, CCITT G3/G4 TIFF or BMP) without re-encoding,
or the low-resolution preview when the page image itself cannot be decoded.

usage: python examples/extract_images.py document.xdw output_dir
"""
import sys
from pathlib import Path

from pyxdw import XdwReader

reader = XdwReader(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
for page in reader.pages:
    if page.images:
        for image in page.images:
            path = out / f"page{page.index + 1:03d}_{image.name}"
            path.write_bytes(image.data)
            print("wrote", path)
    elif page.preview_bmp:
        path = out / f"page{page.index + 1:03d}_preview.bmp"
        path.write_bytes(page.preview_bmp)
        print("wrote", path, "(preview only)")
