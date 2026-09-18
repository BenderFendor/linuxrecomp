"""Lift one function from a PE32+ image with Remill.

This is milestone P2's front end. It reads a function's bytes straight out of the
image, hands them to Remill's lifter, and records what it did in a manifest so a
later step can tell which image and which bytes produced a given artifact.

    python -m tools.linux64 lift IMAGE --function 0x140006D80
    python -m tools.linux64 lift IMAGE --function 0x140006D80 --out work/linux64/lift

Outputs, under ``work/linux64/lift/<name>/``:

* ``<name>.ll``          LLVM IR for the trace
* ``<name>.manifest.json``  inputs, tool identity, hashes

The manifest is validated against ``lift_manifest_schema.json`` before it is
written, for the same reason the program spec is: a consumer should be able to
trust it rather than re-derive it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence, Tuple

import functions as fn
import schema_check
import spec as spec_mod
from pe64 import PE64Image, PEFormatError

MANIFEST_SCHEMA = Path(__file__).resolve().parent / "lift_manifest_schema.json"
DEFAULT_OUTPUT = "work/linux64/lift"
TOOL_NAME = "linuxrecomp lift"
TOOL_VERSION = "0.1.0"

# Remill installs its lifter under a name that carries the LLVM major version.
REMILL_SEARCH = (
    ".deps/src/remill/install/bin",
)


def remill_lift_path(llvm_major: Optional[str] = None) -> Optional[str]:
    """Locate ``remill-lift-<major>``, honouring ``REMILL_LIFT`` first."""
    override = os.environ.get("REMILL_LIFT")
    if override:
        return override if os.path.exists(override) else None
    root = Path(__file__).resolve().parents[2]
    for directory in REMILL_SEARCH:
        candidate_dir = root / directory
        if not candidate_dir.is_dir():
            continue
        names = sorted(entry.name for entry in candidate_dir.iterdir()
                       if entry.name.startswith("remill-lift-"))
        if llvm_major:
            exact = candidate_dir / f"remill-lift-{llvm_major}"
            if exact.exists():
                return str(exact)
        if names:
            return str(candidate_dir / names[-1])
    found = shutil.which("remill-lift")
    return found


def remill_version(binary: str) -> str:
    """Version string of the installed Remill, from its lifter's parent tree."""
    prefix = Path(binary).resolve().parents[1]
    for relative in ("include/remill/Version/Version.h", "share/remill/version.txt"):
        candidate = prefix / relative
        if candidate.is_file():
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                if "REMILL_VERSION" in line or line.strip().startswith("v"):
                    return line.strip()[:120]
    return "unknown"


def function_at(image: PE64Image, va: int) -> Tuple[int, int]:
    """Return the ``(start_rva, end_rva)`` of the recovered range at or holding *va*.

    The range is an unwind range, so an end can sit short of the real function
    tail when the tail carries no unwind record. Lifting stops at the end of the
    bytes it is given, so a caller that needs the whole function must pass
    ``--bytes-length`` explicitly and accept that the extra bytes are whatever
    follows in the section.
    """
    functions, _notes = fn.recover_functions(image)
    rva = image.rva_of(va)
    for function in functions:
        if function.start_rva == rva:
            end = function.end_rva if function.end_rva is not None else rva
            return function.start_rva, end
    for function in functions:
        if function.end_rva is not None and function.start_rva <= rva < function.end_rva:
            return function.start_rva, function.end_rva
    raise ValueError(f"0x{va:X} is not inside a recovered function range")


def _remill_command(binary: str, arch: str, address: int, payload: bytes,
                    output: Path, os_name: str = "windows") -> list:
    return [binary, "--arch", arch, "--os", os_name, "--address", hex(address),
            "--bytes", payload.hex(), "--ir_out", str(output)]


def lift(image_path: str, va: int, out_dir: str = DEFAULT_OUTPUT, arch: str = "amd64",
         byte_length: Optional[int] = None, os_name: str = "windows") -> dict:
    """Lift the function at *va* and return its manifest."""
    binary = remill_lift_path()
    if not binary:
        raise FileNotFoundError(
            "remill-lift is not installed; build it with "
            ".deps/src/remill (see docs/linux64/ROADMAP.md P2)")

    image = PE64Image.load(image_path)
    if not image.is_amd64:
        raise PEFormatError(f"{image.name}: {image.machine_name} is not AMD64")

    start_rva, end_rva = function_at(image, va)
    length = byte_length if byte_length else end_rva - start_rva
    if length <= 0:
        raise ValueError(f"0x{va:X} has no bytes to lift (unwind range is empty)")

    payload = image.read_rva(start_rva, length)
    if payload is None:
        raise ValueError(f"0x{va:X}: cannot read {length} bytes at rva 0x{start_rva:X}")

    name = f"sub_{image.va(start_rva):X}"
    target_dir = Path(out_dir) / name
    target_dir.mkdir(parents=True, exist_ok=True)
    ir_path = target_dir / f"{name}.ll"

    completed = subprocess.run(
        _remill_command(binary, arch, image.va(start_rva), payload, ir_path, os_name),
        capture_output=True, text=True, timeout=600)
    if completed.returncode != 0 or not ir_path.exists():
        raise RuntimeError(
            f"remill-lift failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-800:]}")

    manifest = {
        "format": "linuxrecomp-lift-manifest-v1",
        "arch": arch,
        "os": os_name,
        "generator": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "lifter": os.path.basename(binary),
            "lifter_version": remill_version(binary),
        },
        "source": {
            "image": os.path.basename(image_path),
            "image_sha256": image.sha256,
            "function_va": image.va(start_rva),
            "function_start_rva": start_rva,
            "range_end_rva": end_rva,
            "byte_length": len(payload),
            "bytes_sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": payload.hex(),
        },
        "artifact": {
            "ir": os.path.relpath(ir_path, out_dir) if str(out_dir) else str(ir_path),
            "ir_bytes": ir_path.stat().st_size,
        },
    }
    schema_check.validate_document(manifest, str(MANIFEST_SCHEMA))
    manifest_path = target_dir / f"{name}.manifest.json"
    import json
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return manifest


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.linux64 lift",
        description="Lift one PE32+/AMD64 function to LLVM IR with Remill")
    parser.add_argument("image", help="PE32+ AMD64 image")
    parser.add_argument("--function", required=True,
                        help="guest virtual address of the function to lift")
    parser.add_argument("--arch", default="amd64", choices=["amd64", "amd64_avx",
                                                            "amd64_avx512"])
    parser.add_argument("--bytes-length", type=lambda text: int(text, 0), default=None,
                        help="lift this many bytes instead of the recovered range")
    parser.add_argument("--out", default=DEFAULT_OUTPUT, help=f"output root "
                        f"(default: {DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)

    try:
        va = int(args.function, 0)
    except ValueError:
        print(f"lift: --function wants an address, got {args.function!r}", file=sys.stderr)
        return 1

    try:
        manifest = lift(args.image, va, args.out, args.arch, args.bytes_length)
    except (FileNotFoundError, PEFormatError, ValueError, RuntimeError) as exc:
        print(f"lift: {exc}", file=sys.stderr)
        return 1
    except schema_check.SchemaError as exc:
        print(f"lift: manifest failed validation: {exc}", file=sys.stderr)
        return 1

    print(f"lifted {manifest['source']['function_va']:#x} "
          f"({manifest['source']['byte_length']} bytes) -> {manifest['artifact']['ir']}")
    print(f"  lifter        {manifest['generator']['lifter']}")
    print(f"  bytes sha256  {manifest['source']['bytes_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
