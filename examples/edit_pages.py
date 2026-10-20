"""Copy a document with pypdf-style page operations.

Reverses the pages, rotates the first one by 90 degrees and appends a second
document. Pages whose rotation is not verified are skipped with a message.

usage: python examples/edit_pages.py input.xdw other.xdw output.xdw
"""
import sys

from pyxdw import XdwReader, XdwUnsupportedFeatureError, XdwWriter

reader = XdwReader(sys.argv[1])
with XdwWriter() as writer:
    for page in reversed(reader.pages):
        writer.add_page(page)
    try:
        writer.rotate_page(0, 90)
    except XdwUnsupportedFeatureError as error:
        print("rotation skipped:", error)
    writer.append(sys.argv[2])
    writer.write(sys.argv[3])
print("pages written:", len(XdwReader(sys.argv[3]).pages))
