"""Function range recovery for PE32+ images.

On AMD64 the linker emits an exception directory (``.pdata``) holding one
``RUNTIME_FUNCTION`` per function that needs unwind data. Those entries carry
``[begin, end)`` as RVAs written by the linker itself, so they are ground truth
for function bounds rather than a heuristic. That is the primary source here.

Sources, in trust order:

1. ``pdata``     linker-written ``.pdata`` ranges. Authoritative: an external
                 start that lands inside one of these is a split, not a new
                 function, and is reported as ``split_starts`` instead of being
                 added.
2. ``bounds``    external analysis (Ghidra ``DumpBounds.java`` CSV) filling
                 gaps the linker table does not cover. MinGW and MSVC both omit
                 leaf functions from ``.pdata``, so this is common.
3. ``export``    a start that is exported but not covered by either above.
4. ``entrypoint`` the image entry point, when nothing else covers it.

A function whose end is not known emits ``end_rva = None``; callers must not
read that as a zero-length range.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Optional, Sequence, Set, Tuple

from pe64 import Function, PE64Image

BOUNDS_SOURCE = "ghidra"


def load_bounds_csv(path: str) -> Tuple[Tuple[int, int], ...]:
    """Read a ``DumpBounds.java`` CSV: one ``start,end`` row per function, hex,
    end exclusive, no ``0x`` prefix. Blank lines and ``#`` comments are ignored.

    The values are guest VAs, matching what Ghidra reports for the analyzed
    program image.
    """
    out = []
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            parts = text.replace(",", " ").split()
            if len(parts) < 2:
                raise ValueError(f"{path}:{lineno}: expected 'start,end', got {text!r}")
            try:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: not hex: {text!r}") from exc
            if end < start:
                raise ValueError(f"{path}:{lineno}: end < start: {text!r}")
            out.append((start, end))
    return tuple(out)


def _covered_by(ranges: Sequence[Function], rva: int) -> Optional[Function]:
    for function in ranges:
        if function.end_rva is not None and function.start_rva <= rva < function.end_rva:
            return function
    return None


def _at_start(ranges: Sequence[Function], rva: int) -> Optional[Function]:
    for function in ranges:
        if function.start_rva == rva:
            return function
    return None


def export_kind(image: PE64Image, symbol) -> str:
    """Classify an export as ``forwarder``, ``code`` or ``data``.

    An export is not automatically a function. MSVC exports vftables and other
    data with decorated names — ``??_7CPackage@HLLib@@6B@`` is "vftable for
    CPackage" — and those live in ``.rdata``/``.data``. Treating them as
    functions puts lifters on data, which produces code that was never in the
    program.
    """
    if symbol.forwarder is not None:
        return "forwarder"
    return "code" if any(lo <= symbol.rva < hi for lo, hi in image.code_ranges()) else "data"


def recover_functions(
    image: PE64Image,
    bounds: Iterable[Tuple[int, int]] = (),
) -> Tuple[Tuple[Function, ...], Set[str]]:
    """Return ``(functions, notes)`` for *image*.

    *bounds* is an optional iterable of ``(start_va, end_va)`` pairs from an
    external analyzer. ``notes`` records what the merge dropped, keyed by
    reason, so a caller can report it instead of silently losing information.
    No returned range overlaps another: a start that falls inside an existing
    range is either recognised as that range's start (and gives it a name) or
    counted as a split.
    """
    functions = [
        Function(start_rva=entry.begin_rva, end_rva=entry.end_rva, source="pdata")
        for entry in image.runtime_functions
        if entry.end_rva > entry.begin_rva
    ]
    functions.sort(key=lambda function: function.start_rva)

    notes: Set[str] = set()
    code_ranges = image.code_ranges()

    def add(function: Function) -> None:
        functions.append(function)
        functions.sort(key=lambda item: item.start_rva)

    external = []
    for start_va, end_va in bounds:
        start_rva = start_va - image.image_base
        end_rva = end_va - image.image_base if end_va is not None else None
        if start_rva < 0:
            notes.add("bounds_outside_image")
            continue
        external.append((start_rva, end_rva))
    external.sort()

    for start_rva, end_rva in external:
        if _covered_by(functions, start_rva) is not None:
            notes.add("split_starts")
            continue
        add(Function(start_rva=start_rva, end_rva=end_rva, source=BOUNDS_SOURCE))

    names = {}
    for symbol in image.exports:
        if symbol.forwarder is not None:
            continue
        names.setdefault(symbol.rva, symbol.name or f"ordinal_{symbol.ordinal}")

    # Only exports that live in executable code can be function starts.
    for start_rva, name in names.items():
        if not any(lo <= start_rva < hi for lo, hi in code_ranges):
            continue
        existing = _at_start(functions, start_rva)
        if existing is not None:
            continue  # named below, from the name map
        if _covered_by(functions, start_rva) is not None:
            notes.add("split_starts")
            continue
        add(Function(start_rva=start_rva, end_rva=None, name=name, source="export"))

    entry_rva = image.entrypoint_rva
    if entry_rva:
        existing = _at_start(functions, entry_rva)
        if existing is None and _covered_by(functions, entry_rva) is None:
            add(Function(start_rva=entry_rva, end_rva=None,
                         name=names.get(entry_rva, "entrypoint"), source="entrypoint"))

    named = []
    for function in functions:
        name = function.name or names.get(function.start_rva)
        if name is None and function.source == "entrypoint":
            name = "entrypoint"
        named.append(function if function.name == name else replace(function, name=name))
    named.sort(key=lambda function: function.start_rva)
    return tuple(named), notes


def validate_ranges(image: PE64Image, functions: Sequence[Function]) -> Tuple[str, ...]:
    """Structural checks on recovered ranges. Returns human-readable problems;
    an empty tuple means the ranges are internally consistent.

    Checks: start before end, no overlaps, and starts inside executable code.
    These are cheap invariants that catch a mis-parsed table before it reaches a
    lifter, where the failure would look like an unresolved call instead.
    """
    problems = []
    code = image.code_ranges()
    previous = None
    for function in functions:
        if function.end_rva is not None and function.end_rva <= function.start_rva:
            problems.append(
                f"0x{function.start_rva:X}: end 0x{function.end_rva:X} not after start")
        if not any(start <= function.start_rva < end for start, end in code):
            problems.append(
                f"0x{function.start_rva:X}: start outside executable sections")
        if previous is not None:
            if previous[0] == function.start_rva:
                problems.append(f"0x{function.start_rva:X}: duplicate start")
            elif (previous[1] is not None and function.end_rva is not None
                  and function.start_rva < previous[1]):
                problems.append(
                    f"0x{function.start_rva:X}: overlaps 0x{previous[0]:X}-0x{previous[1]:X}")
        previous = (function.start_rva, function.end_rva)
    return tuple(problems)


def summarize(functions: Sequence[Function]) -> dict:
    """Counts by source plus byte coverage, for reporting."""
    by_source: dict = {}
    covered = 0
    unknown_end = 0
    for function in functions:
        by_source[function.source] = by_source.get(function.source, 0) + 1
        if function.end_rva is None:
            unknown_end += 1
        else:
            covered += function.end_rva - function.start_rva
    return {
        "count": len(functions),
        "by_source": by_source,
        "unknown_end": unknown_end,
        "covered_bytes": covered,
    }
