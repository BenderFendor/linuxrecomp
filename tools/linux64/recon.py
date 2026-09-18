"""PE32+/AMD64 reconnaissance: read an image and emit the program spec.

This is the whole of milestone P1. It writes no lifted code and executes
nothing; it produces ``program.json``, the document every later stage reads.

Usage:
  python -m tools.linux64 recon game.exe
  python -m tools.linux64 recon game.exe -o work/linux64/myprogram.json
  python -m tools.linux64 recon game.exe --bounds work/linux64/ghidra/bounds.csv
  python -m tools.linux64 recon game.exe --no-write          # report only
  python -m tools.linux64 recon game.exe --strict            # fail on range problems

``--bounds`` takes a CSV from the repo's existing Ghidra script
(``tools/ghidra/DumpBounds.java``), which fills the gaps the linker's ``.pdata``
table leaves: both MSVC and MinGW omit leaf functions there.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

import spec as spec_mod
from functions import (export_kind, load_bounds_csv, recover_functions, summarize,
                       validate_ranges)
from pe64 import PE64Image, PEFormatError
from schema_check import SchemaError

DEFAULT_OUTPUT = "work/linux64/program.json"


def analyze(path: str, bounds_path: Optional[str] = None):
    """Read *path* and return ``(image, functions, notes, problems, stats)``.

    Raises PEFormatError for anything that is not a PE32+ image, and ValueError
    for a malformed bounds CSV.
    """
    image = PE64Image.load(path)
    if not image.is_amd64:
        raise PEFormatError(
            f"{image.name}: machine {image.machine_name} is not AMD64; "
            "the linux64 pipeline only consumes PE32+/AMD64 images")

    notes = set()
    bounds = ()
    if bounds_path:
        bounds = load_bounds_csv(bounds_path)
        notes.add(f"external_bounds:{bounds_path}")

    functions, merge_notes = recover_functions(image, bounds)
    notes |= merge_notes
    problems = validate_ranges(image, functions)
    stats = summarize(functions)
    return image, functions, notes, problems, stats


def print_summary(image: PE64Image, functions, notes, problems, stats, output: Optional[str]) -> None:
    print(f"linuxrecomp recon: {image.name}")
    print(f"  sha256       {image.sha256}")
    print(f"  file         {image.filesize:,} bytes, {image.machine_name}, "
          f"{image.subsystem_name}, {'DLL' if image.is_dll else 'EXE'}, "
          f"linker {image.linker_version}")
    print(f"  image base   0x{image.image_base:X}, entry 0x{image.entrypoint_va:X} "
          f"(rva 0x{image.entrypoint_rva:X}), size 0x{image.size_of_image:X}")
    print(f"  alignment    section 0x{image.section_alignment:X}, "
          f"file 0x{image.file_alignment:X}, "
          f"{'dynamic base' if image.has_dynamic_base else 'fixed base'}")

    code = image.code_sections
    code_span = sum(section.mapped_size for section in code)
    print(f"  sections     {len(image.sections)} ({len(code)} code, "
          f"{code_span:,} code bytes)")
    for section in image.sections:
        if section.is_code or section.name in (".pdata", ".xdata", ".reloc", ".tls"):
            print(f"    0x{section.rva:08X}-0x{section.end_rva:08X} "
                  f"{section.name:<9} {','.join(section.flags)}")

    present = [entry for entry in image.directories if entry.present]
    print(f"  directories  {', '.join(f'{e.name}@0x{e.rva:X}/{e.size:X}' for e in present)}")

    dlls = image.import_dlls
    counts: dict = {}
    for symbol in image.imports:
        counts[symbol.dll] = counts.get(symbol.dll, 0) + 1
    print(f"  imports      {len(image.imports)} functions from {len(dlls)} DLLs")
    for dll in dlls:
        print(f"    {dll:<44} {counts[dll]}")

    kinds: dict = {}
    for symbol in image.exports:
        kind = export_kind(image, symbol)
        kinds[kind] = kinds.get(kind, 0) + 1
    print(f"  exports      {len(image.exports)} (code {kinds.get('code', 0)}, "
          f"data {kinds.get('data', 0)}, forwarder {kinds.get('forwarder', 0)})")

    tls = image.tls
    if tls is None:
        print("  tls          none")
    else:
        callbacks = ", ".join(f"0x{value:X}" for value in tls.callbacks) or "none"
        print(f"  tls          data 0x{tls.raw_start_va:X}-0x{tls.raw_end_va:X}, "
              f"index 0x{tls.index_va:X}, zerofill {tls.zero_fill_size}, "
              f"callbacks [{callbacks}]")

    reloc = image.relocation_counts()
    total_reloc = sum(reloc.values())
    detail = ", ".join(f"{kind} {count}" for kind, count in sorted(reloc.items()))
    print(f"  relocations  {total_reloc} ({detail or 'none'})")

    unwind_handlers = sum(1 for entry in image.runtime_functions
                          if (info := image.unwind_info(entry.unwind_rva)) is not None
                          and (info.has_exception_handler or info.has_termination_handler))
    print(f"  unwind       {len(image.runtime_functions)} .pdata entries, "
          f"{unwind_handlers} with language handlers")

    sources = ", ".join(f"{name} {count}" for name, count in sorted(stats["by_source"].items()))
    print(f"  functions    {stats['count']} ({sources}), "
          f"{stats['covered_bytes']:,} bytes covered, "
          f"{stats['unknown_end']} with unknown end")

    for note in sorted(notes):
        print(f"  note         {note}")
    if problems:
        print(f"  problems     {len(problems)}")
        for problem in problems[:10]:
            print(f"    {problem}")
        if len(problems) > 10:
            print(f"    ... and {len(problems) - 10} more")
    else:
        print("  problems     none")

    if output:
        print(f"  wrote        {output}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.linux64 recon",
        description="PE32+/AMD64 reconnaissance: emit a linuxrecomp-spec-v1 program document")
    parser.add_argument("image", help="PE32+ AMD64 executable or DLL")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help=f"spec output path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--bounds", help="Ghidra DumpBounds CSV of extra function ranges")
    parser.add_argument("--no-write", action="store_true", help="report only, write no spec")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero when recovered ranges are inconsistent")
    parser.add_argument("--quiet", action="store_true", help="write the spec, print nothing")
    args = parser.parse_args(argv)

    try:
        image, functions, notes, problems, stats = analyze(args.image, args.bounds)
    except (PEFormatError, ValueError, OSError) as exc:
        print(f"recon: {exc}", file=sys.stderr)
        return 1

    output = None
    if not args.no_write:
        document = spec_mod.build_spec(
            image, functions, notes=notes, problems=problems,
            bounds_source=args.bounds, stats=stats)
        try:
            spec_mod.write_spec(document, args.output)
        except SchemaError as exc:
            print(f"recon: spec failed validation, nothing written: {exc}", file=sys.stderr)
            return 1
        output = args.output

    if not args.quiet:
        print_summary(image, functions, notes, problems, stats, output)

    if problems and args.strict:
        print(f"recon: {len(problems)} range problem(s) with --strict", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
