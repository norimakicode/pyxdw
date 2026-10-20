"""Add annotations and document properties.

Positions and sizes are in 0.01 mm on the displayed page; colours are (r, g, b).

usage: python examples/annotate.py input.xdw output.xdw
"""
import sys

from pyxdw import XdwReader, XdwWriter

writer = XdwWriter(XdwReader(sys.argv[1]))
writer.add_text_annotation(0, 1000, 1000, "Checked\nby pyxdw", color=(255, 0, 0))
writer.add_sticky_note(0, 1000, 4000, size=(6000, 2000), color=(255, 255, 0))
writer.add_rectangle(0, 9000, 4000, fill="transparent", border=(0, 0, 255))
writer.add_metadata({"/Title": "Annotated with pyxdw", "usrdef_Reviewed": True})
writer.write(sys.argv[2])

result = XdwReader(sys.argv[2])
print("title:", result.metadata.title)
for annotation in result.pages[0].annotations:
    print(annotation.subtype, annotation.position, annotation.size, repr(annotation.extract_text()))
