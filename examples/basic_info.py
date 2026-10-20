"""Print document properties and the layout of every page.

usage: python examples/basic_info.py document.xdw
"""
import sys

from pyxdw import XdwReader

reader = XdwReader(sys.argv[1])
print("format version:", reader.format_version)
print("pages:", len(reader.pages))
print("title:", reader.metadata.title)
for page in reader.pages:
    box = page.mediabox
    print(f"page {page.index + 1}: {page.resource_types}, {page.image_status}, "
          f"{box.width:.0f} x {box.height:.0f} pt, rotation {page.rotation}, "
          f"{len(page.annotations)} annotation(s)")
