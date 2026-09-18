"""Environment check for the linux64 pipeline.

Reports what the pipeline needs at each stage so a failure shows up here rather
than as a confusing error four steps later. Groups marked required make the
command exit non-zero; ``opt`` lines never do.

Run: ``python -m tools.linux64 doctor``
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]

# The Win32 API layer is Wine's own DLLs linked through winelib, so the wine
# toolchain is a hard dependency of the runtime, not of reconnaissance.
WINE_PE_DLL_DIRS = (
    Path("/usr/lib/wine/x86_64-windows"),
    Path("/usr/lib64/wine/x86_64-windows"),
    Path("/usr/local/lib/wine/x86_64-windows"),
)

HEADLESS_CANDIDATES = (
    Path("/opt/ghidra/support/analyzeHeadless"),
    Path("/usr/share/ghidra/support/analyzeHeadless"),
    Path("/usr/local/share/ghidra/support/analyzeHeadless"),
)


class Report:
    """Accumulates check results and prints them grouped."""

    def __init__(self) -> None:
        self.failures: List[str] = []
        self._group: Optional[str] = None

    def group(self, title: str) -> None:
        print(f"\n{title}")
        self._group = title

    def line(self, state: str, label: str, detail: str = "", required: bool = True) -> None:
        print(f"  [{state:^4}] {label:<28} {detail}")
        if state == "miss" and required:
            self.failures.append(f"{self._group}: {label}")

    def found(self, label: str, path: Optional[str], version: str = "",
              required: bool = True, optional: bool = False) -> None:
        if path:
            self.line("ok", label, f"{path} {version}".strip(), required=False)
        else:
            self.line("opt" if optional else "miss", label, version or "not found",
                      required=not optional)


def _version(command: Sequence[str]) -> str:
    try:
        out = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return ""
    text = (out.stdout or out.stderr).strip().splitlines()
    return text[0][:70] if text else ""


def _python_module(name: str) -> Optional[str]:
    return name if importlib.util.find_spec(name) is not None else None


def _headless() -> Optional[str]:
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    for candidate in HEADLESS_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    return None


def _wine_pe_dir() -> Optional[Path]:
    for candidate in WINE_PE_DLL_DIRS:
        if (candidate / "kernel32.dll").is_file():
            return candidate
    return None


def run() -> int:
    report = Report()
    print(f"linuxrecomp linux64 doctor\nrepo: {ROOT}")
    print(f"python: {sys.version.split()[0]} ({sys.executable})")

    report.group("toolchain (required)")
    for tool in ("git", "cmake", "clang", "clang++"):
        report.found(tool, shutil.which(tool))
    report.found("mingw-w64 (fixtures)", shutil.which("x86_64-w64-mingw32-gcc"),
                 _version(["x86_64-w64-mingw32-gcc", "--version"]))

    report.group("win32 api layer (required for the runtime)")
    report.found("wine", shutil.which("wine"), _version(["wine", "--version"]))
    report.found("winegcc", shutil.which("winegcc"))
    report.found("winebuild", shutil.which("winebuild"))
    pe_dir = _wine_pe_dir()
    report.found("wine pe dlls", str(pe_dir) if pe_dir else None,
                 "(kernel32.dll etc.)" if pe_dir else "none of "
                 + ", ".join(str(path) for path in WINE_PE_DLL_DIRS))

    report.group("pinned upstreams")
    lock = ROOT / "upstreams.lock.toml"
    report.found("upstreams.lock.toml", str(lock) if lock.is_file() else None)
    for name in ("remill", "dxvk", "FAudio"):
        path = ROOT / ".deps" / "src" / name
        present = path.is_dir()
        report.line("ok" if present else "opt", f".deps/src/{name}",
                    "present" if present else "run scripts/bootstrap-linux64.sh",
                    required=False)

    report.group("optional analysis backends")
    report.found("ghidra analyzeHeadless", _headless(), optional=True)
    for tool in ("ninja", "meson", "llvm-config", "opt", "llc",
                 "remill-lift", "rellic-decomp", "revng"):
        report.found(tool, shutil.which(tool), optional=True)
    for module in ("capstone", "unicorn", "pefile", "jsonschema"):
        found = _python_module(module)
        report.found(f"python {module}", module if found else None,
                     "" if found else "used by some upstream tests/tools", optional=True)

    print()
    if report.failures:
        print(f"doctor: {len(report.failures)} missing required item(s):")
        for failure in report.failures:
            print(f"  - {failure}")
        return 1
    print("doctor: required toolchain present")
    return 0


if __name__ == "__main__":
    sys.exit(run())
