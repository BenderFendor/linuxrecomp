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
import json
import os
import re
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


def image_key(image_path: str) -> str:
    """Directory name for one image's lifts.

    Keying on the image name and content hash, not on the address alone. Two
    PE32+ images share an image base, so their first function is often at the
    same address: with a per-address layout, lifting one image overwrote the
    other's manifest and the build then saw a hash mismatch. It stubbed the
    symbol, which is safe but silent about the real cause.
    """
    with open(image_path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    stem = Path(image_path).stem
    return f"{stem}-{digest[:8]}"


def lift_dir(out_dir: str, image_path: str) -> Path:
    return Path(out_dir) / image_key(image_path)


def lift(image_path: str, va: int, out_dir: str = DEFAULT_OUTPUT, arch: str = "amd64",
         byte_length: Optional[int] = None, os_name: str = "windows",
         length_source: str = "unwind-range",
         start_rva: Optional[int] = None) -> dict:
    """Lift the function at *va* and return its manifest.

    A recovered range supplies the default byte range. *start_rva* overrides that
    for a call target inside no recovered range, which is how closure lifting
    reaches functions reconnaissance never listed. *length_source* records how
    the range was chosen, because an unwind record and a guess from the next
    function start are not equally trustworthy.
    """
    binary = remill_lift_path()
    if not binary:
        raise FileNotFoundError(
            "remill-lift is not installed; build it with "
            ".deps/src/remill (see docs/linux64/ROADMAP.md P2)")

    image = PE64Image.load(image_path)
    if not image.is_amd64:
        raise PEFormatError(f"{image.name}: {image.machine_name} is not AMD64")

    if start_rva is None:
        start_rva, end_rva = function_at(image, va)
        length = byte_length if byte_length else end_rva - start_rva
    else:
        if not byte_length:
            raise ValueError(f"0x{va:X}: an explicit start needs an explicit length")
        length = byte_length
        end_rva = start_rva + length
    if length <= 0:
        raise ValueError(f"0x{va:X} has no bytes to lift (unwind range is empty)")

    payload = image.read_rva(start_rva, length)
    if payload is None:
        raise ValueError(f"0x{va:X}: cannot read {length} bytes at rva 0x{start_rva:X}")

    name = f"sub_{image.va(start_rva):X}"
    target_dir = lift_dir(out_dir, image_path) / name
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
            "length_source": length_source,
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


def lift_all(image_path: str, out_dir: str = DEFAULT_OUTPUT, arch: str = "amd64",
             os_name: str = "windows", jobs: Optional[int] = None,
             limit: Optional[int] = None, progress=None) -> dict:
    """Lift every recovered function in *image_path*.

    Resumable: a function whose existing manifest records the same bytes is
    skipped, so a rerun after a failure does not redo the work. Returns a summary
    with the lifted, skipped, and failed functions.
    """
    import concurrent.futures
    import json

    binary = remill_lift_path()
    if not binary:
        raise FileNotFoundError(
            "remill-lift is not installed; build it under .deps/src/remill "
            "(see docs/linux64/ROADMAP.md P2)")

    image = PE64Image.load(image_path)
    if not image.is_amd64:
        raise PEFormatError(f"{image.name}: {image.machine_name} is not AMD64")

    functions, _notes = fn.recover_functions(image)
    targets = [function for function in functions if function.end_rva is not None
               and function.end_rva > function.start_rva]
    if limit:
        targets = targets[:limit]

    lifted, skipped, failed = [], [], []
    pending = []
    for function in targets:
        payload = image.read_rva(function.start_rva, function.end_rva - function.start_rva)
        if payload is None:
            failed.append((function.start_rva, "bytes not readable"))
            continue
        digest = hashlib.sha256(payload).hexdigest()
        symbol = f"sub_{image.va(function.start_rva):X}"
        manifest_path = lift_dir(out_dir, image_path) / symbol / f"{symbol}.manifest.json"
        if manifest_path.exists():
            try:
                existing = json.loads(manifest_path.read_text())
                if existing.get("source", {}).get("bytes_sha256") == digest:
                    skipped.append(function.start_rva)
                    continue
            except (OSError, ValueError):
                pass
        pending.append(function)

    def work(function):
        try:
            lift(image_path, image.va(function.start_rva), out_dir, arch,
                 function.end_rva - function.start_rva, os_name)
            return function.start_rva, None
        except (RuntimeError, ValueError, FileNotFoundError, PEFormatError,
                schema_check.SchemaError) as exc:
            return function.start_rva, str(exc)

    workers = jobs or min(8, os.cpu_count() or 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for index, (start_rva, error) in enumerate(pool.map(work, pending), 1):
            if error:
                failed.append((start_rva, error))
            else:
                lifted.append(start_rva)
            if progress:
                progress(index, len(pending), start_rva, error)

    return {
        "image": image_path,
        "image_sha256": image.sha256,
        "candidates": len(targets),
        "lifted": sorted(lifted),
        "skipped": sorted(skipped),
        "failed": failed,
    }


SYMBOL_RE = re.compile(r"@(sub_[0-9a-fA-F]+)\s*\(")


def referenced_symbols(out_dir: str) -> "set[int]":
    """Guest VAs that lifted IR refers to as ``sub_<hex>``.

    Remill names a direct call target ``sub_<address>`` and expects the whole
    program to be linked, so these are the addresses the lifter itself decided
    are functions. Some are inside an already recovered range (a continuation
    entry), and the rest are functions reconnaissance never listed.
    """
    found = set()
    for ir in Path(out_dir).glob("*/*/*.ll"):
        for match in SYMBOL_RE.finditer(ir.read_text(encoding="utf-8", errors="replace")):
            found.add(int(match.group(1)[4:], 16))
    return found


def lifted_symbols(out_dir: str) -> "set[int]":
    """Guest VAs that already have a lifted function in *out_dir*."""
    found = set()
    for manifest_path in Path(out_dir).glob("*/*/*.manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            continue
        found.add(manifest["source"]["function_va"])
    return found


def choose_length(image: PE64Image, va: int, known_starts: "list[int]") -> Tuple[int, str]:
    """Byte range to lift from *va*, with the reason it was chosen.

    *known_starts* are RVAs. Inside a recovered range the unwind record gives the
    extent. Outside one, the next known start bounds it, capped so a bad guess
    cannot run away, and the smallest cap applies when nothing bounds it at all.
    """
    rva = image.rva_of(va)
    functions, _notes = fn.recover_functions(image)
    for function in functions:
        if function.end_rva is None:
            continue
        if function.start_rva <= rva < function.end_rva:
            return function.end_rva - rva, "unwind-range"
    for start in sorted(known_starts):
        if start > rva:
            return min(start - rva, 4096), "next-function"
    return 256, "default"


def lift_reachable(image_path: str, out_dir: str = DEFAULT_OUTPUT, arch: str = "amd64",
                   os_name: str = "windows", jobs: Optional[int] = None,
                   rounds: int = 6, progress=None) -> dict:
    """Lift the recovered functions, then everything they call, until closed.

    Remill links direct calls by symbol, so a call to a function that was never
    lifted is an undefined reference. Closing over the referenced addresses both
    satisfies the link and discovers call targets reconnaissance missed: on the
    project's test executable, 49 of the referenced addresses are outside every
    recovered range.
    """
    summary = {"rounds": [], "lifted": [], "failed": [], "referenced": 0}
    known = set()
    for round_index in range(rounds):
        if round_index == 0:
            result = lift_all(image_path, out_dir, arch, os_name, jobs, progress=progress)
            summary["rounds"].append({"round": 0, "kind": "recovered",
                                      "lifted": len(result["lifted"]),
                                      "failed": len(result["failed"])})
            summary["failed"].extend(result["failed"])
        else:
            image = PE64Image.load(image_path)
            already = lifted_symbols(out_dir)
            referenced = referenced_symbols(out_dir)
            pending = sorted(referenced - already)
            summary["referenced"] = len(referenced)
            if not pending:
                break
            starts = sorted({entry.begin_rva for entry in image.runtime_functions} |
                            {image.rva_of(va) for va in already})
            lifted_this_round, failed_this_round = [], []
            for va in pending:
                length, source = choose_length(image, va, starts)
                if length <= 0:
                    failed_this_round.append((image.rva_of(va), "no bytes to lift"))
                    continue
                try:
                    lift(image_path, va, out_dir, arch, length, os_name, source,
                         start_rva=image.rva_of(va))
                    lifted_this_round.append(va)
                except (RuntimeError, ValueError, FileNotFoundError, PEFormatError,
                        schema_check.SchemaError) as exc:
                    failed_this_round.append((image.rva_of(va), str(exc)))
                    # A target that cannot be lifted still needs a symbol for the
                    # link; the build generates a stub that reports the address.
                    marker = lift_dir(out_dir, image_path) / f"sub_{va:X}"
                    marker.mkdir(parents=True, exist_ok=True)
                    (marker / f"sub_{va:X}.failed").write_text(str(exc))
            summary["rounds"].append({"round": round_index, "kind": "referenced",
                                      "lifted": len(lifted_this_round),
                                      "failed": len(failed_this_round)})
            summary["lifted"].extend(lifted_this_round)
            summary["failed"].extend(failed_this_round)
            known |= set(lifted_this_round)
            if not lifted_this_round:
                break
    return summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.linux64 lift",
        description="Lift PE32+/AMD64 functions to LLVM IR with Remill")
    parser.add_argument("image", help="PE32+ AMD64 image")
    parser.add_argument("--function", default=None,
                        help="guest virtual address of one function to lift")
    parser.add_argument("--all", action="store_true",
                        help="lift every recovered function in the image")
    parser.add_argument("--reachable", action="store_true",
                        help="with --all, also lift every call target the lifted "
                             "code references, until closed")
    parser.add_argument("--jobs", type=int, default=None,
                        help="parallel lifters (default: up to 8)")
    parser.add_argument("--limit", type=int, default=None,
                        help="with --all, stop after this many functions")
    parser.add_argument("--arch", default="amd64", choices=["amd64", "amd64_avx",
                                                            "amd64_avx512"])
    parser.add_argument("--os", default="windows", choices=["windows", "linux", "macos",
                                                            "solaris"])
    parser.add_argument("--bytes-length", type=lambda text: int(text, 0), default=None,
                        help="lift this many bytes instead of the recovered range")
    parser.add_argument("--out", default=DEFAULT_OUTPUT, help=f"output root "
                        f"(default: {DEFAULT_OUTPUT})")
    args = parser.parse_args(argv)

    if args.all:
        if args.function:
            print("lift: use either --function or --all", file=sys.stderr)
            return 2

        def progress(index: int, total: int, start_rva: int, error) -> None:
            if index % 25 == 0 or index == total:
                print(f"  {index}/{total} lifted (last 0x{start_rva:X}"
                      f"{', failed' if error else ''})", flush=True)

        try:
            if args.reachable:
                summary = lift_reachable(args.image, args.out, args.arch, args.os,
                                         args.jobs, progress=progress)
                total_lifted = sum(round_["lifted"] for round_ in summary["rounds"])
                print(f"lift: {total_lifted} lifted across "
                      f"{len(summary['rounds'])} round(s), "
                      f"{len(summary['failed'])} failed, "
                      f"{summary['referenced']} distinct call targets referenced")
                for round_ in summary["rounds"]:
                    print(f"  round {round_['round']} ({round_['kind']}): "
                          f"{round_['lifted']} lifted, {round_['failed']} failed")
            else:
                summary = lift_all(args.image, args.out, args.arch, args.os, args.jobs,
                                   args.limit, progress=progress)
                print(f"lift: {len(summary['lifted'])} lifted, "
                      f"{len(summary['skipped'])} already current, "
                      f"{len(summary['failed'])} failed, "
                      f"{summary['candidates']} candidates")
        except (FileNotFoundError, PEFormatError, ValueError) as exc:
            print(f"lift: {exc}", file=sys.stderr)
            return 1

        failures = summary["failed"]
        for start_rva, error in failures[:10]:
            print(f"  failed 0x{start_rva:X}: {error[:160]}")
        if len(failures) > 10:
            print(f"  ... and {len(failures) - 10} more failures")
        return 1 if failures else 0

    if not args.function:
        print("lift: give --function ADDRESS or --all", file=sys.stderr)
        return 2

    try:
        va = int(args.function, 0)
    except ValueError:
        print(f"lift: --function wants an address, got {args.function!r}", file=sys.stderr)
        return 1

    try:
        manifest = lift(args.image, va, args.out, args.arch, args.bytes_length, args.os)
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
