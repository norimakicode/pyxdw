"""Public writer façade for the experimental XDW editing operations.

The implementation lives in :mod:`pyxdw.experimental` while compatibility
acceptance of generated files is being established. Keeping this small module
separate gives applications a stable import location analogous to
``pypdf.PdfWriter`` without hiding the interoperability caveat.
"""

from .experimental import (
    XdwWriter,
    compact_document_bytes,
    delete_pages_bytes,
    extract_page_bytes,
    merge_documents_bytes,
    rotate_page_bytes,
    select_pages_bytes,
    split_document_bytes,
    split_pages_bytes,
)

__all__ = [
    "XdwWriter",
    "compact_document_bytes",
    "delete_pages_bytes",
    "extract_page_bytes",
    "merge_documents_bytes",
    "rotate_page_bytes",
    "select_pages_bytes",
    "split_document_bytes",
    "split_pages_bytes",
]
