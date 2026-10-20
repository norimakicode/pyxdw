"""Command-line interface for the verified XDW reader and writer subset."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .reader import XdwReader
from .writer import (
    compact_document_bytes,
    delete_pages_bytes,
    extract_page_bytes,
    merge_documents_bytes,
    rotate_page_bytes,
    select_pages_bytes,
    split_pages_bytes,
)

COMMANDS = {
    "info",
    "text",
    "extract",
    "extract-page",
    "compact",
    "select",
    "delete",
    "split",
    "rotate",
    "merge",
}


def _page_indices(value: str) -> tuple[int, ...]:
    try:
        indices = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "pages must be comma-separated integers"
        ) from exc
    if not indices:
        raise argparse.ArgumentTypeError("at least one page index is required")
    return indices


def _add_history_options(parser: argparse.ArgumentParser) -> None:
    """Add safe compact output with an explicit append-history opt-out."""

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--compact",
        dest="compact",
        action="store_true",
        default=True,
        help="write only current pages (default)",
    )
    group.add_argument(
        "--preserve-history",
        dest="compact",
        action="store_false",
        help="retain DocuWorks-style append-only history",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyxdw",
        description="Read and experimentally edit observed DocuWorks XDW layouts",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    info = commands.add_parser(
        "info", help="show current and historical page structure"
    )
    info.add_argument("path", type=Path)

    text = commands.add_parser("text", help="extract EMF or stored OCR text")
    text.add_argument("path", type=Path)
    text.add_argument(
        "--annotations", action="store_true", help="include annotation EMF text"
    )
    text.add_argument(
        "--layout", action="store_true", help="sort by coordinates and expose cell gaps"
    )

    extract = commands.add_parser(
        "extract", help="extract known page images, previews and text"
    )
    extract.add_argument("source", type=Path)
    extract.add_argument("output_dir", type=Path)
    extract.add_argument(
        "--layout", action="store_true", help="write coordinate-layout text"
    )

    extract_page = commands.add_parser(
        "extract-page", help="write one compact zero-based page as XDW"
    )
    extract_page.add_argument("source", type=Path)
    extract_page.add_argument("output", type=Path)
    extract_page.add_argument("--page", required=True, type=int)

    compact = commands.add_parser(
        "compact", help="remove old generations and unreferenced resources"
    )
    compact.add_argument("source", type=Path)
    compact.add_argument("output", type=Path)

    select = commands.add_parser(
        "select", help="write selected/reordered zero-based pages"
    )
    select.add_argument("source", type=Path)
    select.add_argument("output", type=Path)
    select.add_argument("--pages", required=True, type=_page_indices)
    _add_history_options(select)

    delete = commands.add_parser("delete", help="delete zero-based pages")
    delete.add_argument("source", type=Path)
    delete.add_argument("output", type=Path)
    delete.add_argument("--pages", required=True, type=_page_indices)
    _add_history_options(delete)

    split = commands.add_parser("split", help="write one XDW per current page")
    split.add_argument("source", type=Path)
    split.add_argument("output_dir", type=Path)
    split.add_argument(
        "--pages-per-file",
        type=int,
        default=1,
        metavar="N",
        help="write consecutive chunks of N pages (default: 1)",
    )

    rotate = commands.add_parser(
        "rotate", help="rotate one zero-based observed page clockwise by an increment"
    )
    rotate.add_argument("source", type=Path)
    rotate.add_argument("output", type=Path)
    rotate.add_argument("--page", required=True, type=int)
    rotate.add_argument("--degrees", required=True, type=int, choices=(90, 180, 270))
    _add_history_options(rotate)

    merge = commands.add_parser(
        "merge", help="merge observed v7/v10 XDW documents (mixed output is v10)"
    )
    merge.add_argument("output", type=Path)
    merge.add_argument("sources", type=Path, nargs="+")
    return parser


def _print_info(path: Path) -> None:
    reader = XdwReader(path)
    print(
        f"{path}: XDW format v{reader.format_version}, "
        f"{reader.page_count} pages, {len(reader.generations)} generations"
    )
    for generation in reader.generations:
        print(
            f"generation {generation.index}: {len(generation.pages)} pages, "
            f"directory=0x{generation.directory.offset:X}, "
            f"removed={list(map(hex, generation.removed_resource_offsets))}"
        )
        for page in generation.pages:
            dimensions = (
                f"{page.width_mm:.2f}x{page.height_mm:.2f} mm"
                if page.width_mm is not None and page.height_mm is not None
                else "dimensions unknown"
            )
            pixels = (
                f", {page.pixel_width}x{page.pixel_height} px"
                if page.pixel_width is not None and page.pixel_height is not None
                else ""
            )
            print(
                f"  page {page.index}: types={page.resource_types}, "
                f"{dimensions}{pixels}, rotation={page.rotation}, "
                f"embedded_images={sum(i.format == 'JPEG' for i in page.images)}, "
                f"annotations={len(page.annotations)}, ocr_resources={len(page.ocr_resources)}, "
                "thumbnail="
                + (
                    f"{page.thumbnail.width}x{page.thumbnail.height}"
                    if page.thumbnail is not None
                    else "none"
                )
            )


def _extract(
    reader: XdwReader,
    output: Path,
    extraction_mode: str = "plain",
) -> int:
    output.mkdir(parents=True, exist_ok=True)
    written = 0
    for index, page in enumerate(reader.pages, 1):
        stem = f"page_{index:03d}"
        if page.main_image_bmp is not None:
            (output / f"{stem}.bmp").write_bytes(page.main_image_bmp)
            written += 1
        if page.main_image_tiff is not None:
            (output / f"{stem}.tif").write_bytes(page.main_image_tiff)
            written += 1
        if page.application_data is not None:
            (output / f"{stem}.emf").write_bytes(page.application_data)
            written += 1
        if page.preview_bmp is not None:
            (output / f"{stem}_preview.bmp").write_bytes(page.preview_bmp)
            written += 1
        text = page.extract_text(extraction_mode=extraction_mode)
        if text:
            (output / f"{stem}.txt").write_text(text, encoding="utf-8")
            written += 1
        # page.images also lists the page's own TIFF/BMP (pypdf style); those were written above.
        embedded = [image for image in page.images if image.format == "JPEG"]
        if embedded:
            folder = output / f"{stem}_images"
            folder.mkdir(parents=True, exist_ok=True)
            for image in embedded:
                (folder / f"image_{image.index + 1:03d}{image.extension}").write_bytes(image.data)
            written += len(embedded)
    return written


def main(argv: Sequence[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Keep ``pyxdw document.xdw`` as shorthand for ``pyxdw info document.xdw``.
    if arguments and arguments[0] not in COMMANDS and not arguments[0].startswith("-"):
        arguments.insert(0, "info")
    parser = _parser()
    args = parser.parse_args(arguments)

    if args.command == "info":
        _print_info(args.path)
    elif args.command == "text":
        content = XdwReader(args.path).extract_text(
            extraction_mode="layout" if args.layout else "plain",
            include_annotations=args.annotations,
        )
        print(content, end="" if content.endswith("\n") else "\n")
    elif args.command == "extract":
        count = _extract(
            XdwReader(args.source),
            args.output_dir,
            extraction_mode="layout" if args.layout else "plain",
        )
        print(f"wrote {count} files to {args.output_dir}")
    elif args.command == "extract-page":
        args.output.write_bytes(extract_page_bytes(XdwReader(args.source), args.page))
        print(f"wrote compact page to {args.output}; interoperability is experimental")
    elif args.command == "compact":
        args.output.write_bytes(compact_document_bytes(args.source))
        print(
            f"wrote compact document to {args.output}; interoperability is experimental"
        )
    elif args.command == "select":
        data = select_pages_bytes(XdwReader(args.source), args.pages)
        if args.compact:
            data = compact_document_bytes(data)
        args.output.write_bytes(data)
        print(f"wrote {args.output}; DocuWorks interoperability is experimental")
    elif args.command == "delete":
        data = delete_pages_bytes(XdwReader(args.source), args.pages)
        if args.compact:
            data = compact_document_bytes(data)
        args.output.write_bytes(data)
        print(f"wrote {args.output}; DocuWorks interoperability is experimental")
    elif args.command == "split":
        args.output_dir.mkdir(parents=True, exist_ok=True)
        parts = split_pages_bytes(XdwReader(args.source), args.pages_per_file)
        for index, data in enumerate(parts, 1):
            if args.pages_per_file == 1:
                name = f"page_{index:03d}.xdw"
            else:
                name = f"part_{index:03d}.xdw"
            (args.output_dir / name).write_bytes(data)
        print(f"wrote {len(parts)} XDW files to {args.output_dir}")
    elif args.command == "rotate":
        data = rotate_page_bytes(XdwReader(args.source), args.page, args.degrees)
        if args.compact:
            data = compact_document_bytes(data)
        args.output.write_bytes(data)
        print(f"wrote {args.output}; DocuWorks interoperability is experimental")
    elif args.command == "merge":
        if len(args.sources) < 2:
            parser.error("merge requires at least two source files")
        data = merge_documents_bytes(XdwReader(path) for path in args.sources)
        args.output.write_bytes(data)
        print(f"wrote {args.output}; DocuWorks interoperability is experimental")


if __name__ == "__main__":
    main()
