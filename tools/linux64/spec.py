"""Assemble and validate the ``linuxrecomp-spec-v1`` program document.

This document is the project's own stable intermediate representation: one JSON
file describing a PE32+/AMD64 image and the functions recovered from it. Lifting
backends read it, so it must not embed any backend's data structures. Swapping
Remill for a different lifter should not change this file, and fixing
reconnaissance should not change a backend.

``spec_schema.json`` next to this module is the authoritative description and is
enforced by :func:`validate_spec` (see ``schema_check.py`` for the validator's
supported keyword subset).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional, Sequence

from pe64 import Function, PE64Image
import functions as _functions
import schema_check as _schema

SPEC_FORMAT = "linuxrecomp-spec-v1"
SPEC_ARCH = "amd64"
TOOL_NAME = "linuxrecomp recon"
TOOL_VERSION = "0.1.0"

SCHEMA_PATH = Path(__file__).resolve().parent / "spec_schema.json"


def _section_entry(image: PE64Image, section) -> dict:
    return {
        "name": section.name,
        "rva": section.rva,
        "va": image.va(section.rva),
        "virtual_size": section.virtual_size,
        "raw_offset": section.raw_offset,
        "raw_size": section.raw_size,
        "mapped_size": section.mapped_size,
        "characteristics": section.characteristics,
        "flags": list(section.flags),
    }


def _import_entry(image: PE64Image, symbol) -> dict:
    return {
        "dll": symbol.dll,
        "name": symbol.name,
        "ordinal": symbol.ordinal,
        "hint": symbol.hint,
        "iat_va": image.va(symbol.iat_rva),
        "ilt_va": image.va(symbol.ilt_rva),
    }


def _function_entry(image: PE64Image, function: Function) -> dict:
    return {
        "start": image.va(function.start_rva),
        "end": None if function.end_rva is None else image.va(function.end_rva),
        "name": function.name,
        "source": function.source,
    }


def _unwind_entries(image: PE64Image) -> list:
    out = []
    for entry in image.runtime_functions:
        info = image.unwind_info(entry.unwind_rva)
        record = {
            "begin": image.va(entry.begin_rva),
            "end": image.va(entry.end_rva),
            "unwind_rva": entry.unwind_rva,
            "version": 0,
            "flags": 0,
            "prolog_size": 0,
            "code_slots": 0,
            "frame_register": 0,
            "frame_offset": 0,
            "handler_va": None,
            "chained_begin_va": None,
        }
        if info is not None:
            record.update({
                "version": info.version,
                "flags": info.flags,
                "prolog_size": info.prolog_size,
                "code_slots": info.code_slots,
                "frame_register": info.frame_register,
                "frame_offset": info.frame_offset,
                "handler_va": None if info.handler_rva is None else image.va(info.handler_rva),
                "chained_begin_va": (None if info.chained_begin_rva is None
                                     else image.va(info.chained_begin_rva)),
            })
        out.append(record)
    return out


def _tls_entry(image: PE64Image, tls) -> Optional[dict]:
    if tls is None:
        return None
    return {
        "raw_start_va": tls.raw_start_va,
        "raw_end_va": tls.raw_end_va,
        "index_va": tls.index_va,
        "callbacks_va": tls.callbacks_va,
        "callbacks": list(tls.callbacks),
        "zero_fill_size": tls.zero_fill_size,
        "characteristics": tls.characteristics,
    }


def _export_entries(image: PE64Image) -> list:
    """Export table entries, each classified as code, data or forwarder.

    The classification is what keeps data exports out of the function list: MSVC
    exports vftables with decorated names such as ``??_7CPackage@HLLib@@6B@``,
    and a lifter pointed at those addresses executes data.
    """
    out = []
    for symbol in image.exports:
        kind = _functions.export_kind(image, symbol)
        section = None
        if kind != "forwarder":
            found = image.section_for_rva(symbol.rva)
            section = found.name if found else None
        out.append({
            "name": symbol.name,
            "ordinal": symbol.ordinal,
            "va": image.va(symbol.rva),
            "forwarder": symbol.forwarder,
            "kind": kind,
            "section": section,
        })
    return out


def _export_kind_counts(entries) -> dict:
    counts = {"code": 0, "data": 0, "forwarder": 0}
    for entry in entries:
        counts[entry["kind"]] = counts.get(entry["kind"], 0) + 1
    return counts


def build_spec(
    image: PE64Image,
    functions: Sequence[Function],
    notes: Iterable[str] = (),
    problems: Iterable[str] = (),
    bounds_source: Optional[str] = None,
    stats: Optional[dict] = None,
) -> dict:
    """Build the spec document for *image* and the recovered *functions*.

    *notes* and *problems* are carried through verbatim so a reader of the JSON
    sees the same caveats the CLI printed. *stats* is the output of
    ``functions.summarize``; it is recomputed here when omitted.
    """
    if stats is None:
        stats = _functions.summarize(functions)

    exports = _export_entries(image)

    spec = {
        "format": SPEC_FORMAT,
        "arch": SPEC_ARCH,
        "generator": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "source_file": image.name,
            "source_sha256": image.sha256,
            "source_size": image.filesize,
            "function_bounds_source": bounds_source,
        },
        "image": {
            "image_base": image.image_base,
            "entrypoint": image.entrypoint_va,
            "entrypoint_rva": image.entrypoint_rva,
            "machine": image.machine_name,
            "subsystem": image.subsystem_name,
            "is_dll": image.is_dll,
            "size_of_image": image.size_of_image,
            "size_of_headers": image.size_of_headers,
            "section_alignment": image.section_alignment,
            "file_alignment": image.file_alignment,
            "checksum": image.checksum,
            "timestamp": image.timestamp,
            "linker_version": image.linker_version,
            "dll_characteristics": image.dll_characteristics,
            "has_dynamic_base": image.has_dynamic_base,
            "large_address_aware": image.is_large_address_aware,
            "stack_reserve": image.size_of_stack_reserve,
            "stack_commit": image.size_of_stack_commit,
            "heap_reserve": image.size_of_heap_reserve,
            "heap_commit": image.size_of_heap_commit,
        },
        "sections": [_section_entry(image, section) for section in image.sections],
        "directories": [
            {"index": entry.index, "name": entry.name, "rva": entry.rva,
             "size": entry.size, "present": entry.present}
            for entry in image.directories
        ],
        "functions": [_function_entry(image, function) for function in functions],
        "imports": [_import_entry(image, symbol) for symbol in image.imports],
        "import_dlls": list(image.import_dlls),
        "exports": exports,
        "relocations": [
            {"type": relocation.type, "kind": relocation.kind, "va": image.va(relocation.rva)}
            for relocation in image.relocations
        ],
        "tls": _tls_entry(image, image.tls),
        "unwind": _unwind_entries(image),
        "recon": {
            "function_count": stats["count"],
            "function_sources": stats["by_source"],
            "functions_with_unknown_end": stats["unknown_end"],
            "covered_code_bytes": stats["covered_bytes"],
            "relocation_counts": image.relocation_counts(),
            "export_kinds": _export_kind_counts(exports),
            "notes": list(notes),
            "problems": list(problems),
        },
    }
    return spec


def validate_spec(spec: dict, schema_path: Optional[Path] = None) -> None:
    """Validate *spec* against the shipped schema. Raises ``schema.SchemaError``."""
    _schema.validate_document(spec, str(schema_path or SCHEMA_PATH))


def write_spec(spec: dict, path: str, pretty: bool = True) -> None:
    """Write *spec* to *path*, validating first so a bad document is never
    persisted. Parent directories are created."""
    validate_spec(spec)
    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(spec, handle, indent=2 if pretty else None, sort_keys=False)
        handle.write("\n")


def load_spec(path: str) -> dict:
    """Read and validate a spec document."""
    with open(path, "r", encoding="utf-8") as handle:
        spec = json.load(handle)
    validate_spec(spec)
    return spec
