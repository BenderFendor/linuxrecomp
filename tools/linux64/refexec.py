"""Call the reference executor (``runtime/linux64/refexec.c``) from Python.

The reference executor maps a PE32+ image at its preferred base and runs
original guest code on the real CPU. Differential tests use it as the oracle:
the lifted function and the original function get the same inputs and their
results are compared.

The binary is built on demand by ``scripts/build-runtime-linux64.sh``.

    from refexec import run, RefExecError
    result = run(image_path, 0x140006D80, args=(1, 2))
    print(result.result)
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Sequence, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = os.path.join(ROOT, "work", "linux64", "bin", "refexec")
HARNESS = os.path.join(ROOT, "work", "linux64", "bin", "lifted_harness")
BUILD_SCRIPT = os.path.join(ROOT, "scripts", "build-runtime-linux64.sh")

# Both executors print the same report, so one parser serves both. The lifted
# harness adds the symbol it dispatched to.
RESULT_RE = re.compile(
    r"^(?P<tool>refexec|lifted): image=(?P<image>\S+) base=(?P<base>\S+) "
    r"section=(?P<section>\S+) (?:symbol=(?P<symbol>\S+) )?va=(?P<va>\S+) "
    r"args=(?P<args>\S+) result=(?P<result>\S+) result_dec=(?P<dec>\d+)")
MEMORY_RE = re.compile(
    r"^(?P<tool>refexec|lifted): memory (?P<addr>0x[0-9a-fA-F]+)\+(?P<len>\d+) ="
    r"(?P<bytes>.*)")
STOP_RE = re.compile(r"^lifted: stop (?P<reason>\S+) at (?P<pc>\S+) \((?P<detail>.*)\)")


class RefExecError(RuntimeError):
    """The reference executor could not run the request at all."""


class GuestFault(RefExecError):
    """The guest code faulted while running on the real CPU."""


@dataclass
class RefRun:
    """One execution report, from either executor."""

    image: str
    va: int
    args: Tuple[int, ...]
    result: int
    section: str
    image_base: int
    tool: str = "refexec"
    symbol: Optional[str] = None
    stop: Optional[str] = None
    stop_pc: Optional[int] = None
    memory: Dict[int, bytes] = field(default_factory=dict)

    @property
    def result32(self) -> int:
        """Return value as the guest's 32-bit `eax`, which is what most
        functions actually define."""
        return self.result & 0xFFFFFFFF


def ensure_built() -> str:
    """Build the reference executor when it is missing. Returns its path."""
    if os.path.exists(BINARY):
        return BINARY
    subprocess.run(["bash", BUILD_SCRIPT], check=True, cwd=ROOT)
    if not os.path.exists(BINARY):
        raise RefExecError(f"build did not produce {BINARY}")
    return BINARY


def _parse_report(text: str, stderr: str) -> RefRun:
    """Parse one executor report. Raises when the report is missing what a
    comparison needs."""
    match = None
    memory: Dict[int, bytes] = {}
    stop = None
    stop_pc = None
    for line in text.splitlines():
        found = RESULT_RE.match(line)
        if found:
            match = found
            continue
        found = MEMORY_RE.match(line)
        if found:
            payload = found["bytes"].strip()
            memory[int(found["addr"], 16)] = bytes.fromhex(payload) if payload else b""
            continue
        found = STOP_RE.match(line)
        if found:
            stop = found["reason"]
            stop_pc = int(found["pc"], 16)

    if not match:
        raise RefExecError(f"unexpected executor output: {text.strip()!r} {stderr.strip()!r}")

    return RefRun(
        image=match["image"],
        va=int(match["va"], 16),
        args=tuple(int(part, 16) for part in match["args"].split(",")),
        result=int(match["result"], 16),
        section=match["section"],
        image_base=int(match["base"], 16),
        tool=match["tool"],
        symbol=match["symbol"],
        stop=stop,
        stop_pc=stop_pc,
        memory=memory,
    )


def _execute(binary: str, image: str, va: int, args: Sequence[int],
             pokes: Iterable[Tuple[int, bytes]], dumps: Iterable[Tuple[int, int]],
             timeout: float, extra: Sequence[str] = ()) -> RefRun:
    command = [binary, image, hex(va)]
    command.extend(hex(arg) for arg in args)
    command.extend(extra)
    for address, payload in pokes:
        command.extend(["--poke", f"{hex(address)}={payload.hex()}"])
    for address, length in dumps:
        command.extend(["--dump", f"{hex(address)}:{length}"])

    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if completed.returncode == 2 or "guest faulted" in completed.stderr:
        raise GuestFault(completed.stderr.strip() or "guest faulted")
    if completed.returncode not in (0, 4):
        raise RefExecError(completed.stderr.strip() or f"{binary} exited {completed.returncode}")
    return _parse_report(completed.stdout, completed.stderr)


def run(
    image: str,
    va: int,
    args: Sequence[int] = (),
    pokes: Iterable[Tuple[int, bytes]] = (),
    dumps: Iterable[Tuple[int, int]] = (),
    timeout: float = 30.0,
) -> RefRun:
    """Run ``image``'s function at ``va`` with Microsoft ABI integer *args*.

    *pokes* writes ``(address, bytes)`` into guest memory before the call so a
    function that reads data gets the input its disassembly expects. *dumps*
    reads ``(address, length)`` back afterwards.
    """
    return _execute(ensure_built(), image, va, args, pokes, dumps, timeout)


def run_lifted(
    image: str,
    va: int,
    args: Sequence[int] = (),
    pokes: Iterable[Tuple[int, bytes]] = (),
    dumps: Iterable[Tuple[int, int]] = (),
    timeout: float = 30.0,
    harness: Optional[str] = None,
    report_undefined: bool = True,
) -> RefRun:
    """Run the lifted function at *va* through the lifted harness.

    The harness is built by ``scripts/build-lifted-harness.sh`` for one image.
    """
    binary = harness or os.environ.get("LIFTED_HARNESS") or HARNESS
    if not os.path.exists(binary):
        raise RefExecError(
            f"no lifted harness at {binary}; build it with "
            "scripts/build-lifted-harness.sh IMAGE")
    extra = ("--report-undefined",) if report_undefined else ()
    return _execute(binary, image, va, args, pokes, dumps, timeout, extra)


def _selftest() -> None:
    """Check the wrapper against the HLExtract fixtures when they are present."""
    exe = "/home/bender/projects/filestorecomp/HLExtract/HLExtract.exe"
    if not os.path.exists(exe):
        print("refexec wrapper: SKIP (no HLExtract.exe)")
        return
    # A function whose disassembly is "mov ebx,1; mov eax,ebx": returns 1.
    simple = run(exe, 0x140006D80)
    assert simple.result == 1, hex(simple.result)
    assert simple.section == ".text"

    # Compares a pointed-to dword against 0xC0000005 and returns the result.
    pointer = run(exe, 0x14000C5F0, args=(0x14001E010,),
                  pokes=((0x14001E000, bytes.fromhex("050000c0")),
                         (0x14001E010, bytes.fromhex("00e0014001000000"))),
                  dumps=((0x14001E010, 8),))
    assert pointer.result == 1, hex(pointer.result)
    assert pointer.memory[0x14001E010] == bytes.fromhex("00e0014001000000")

    other = run(exe, 0x14000C5F0, args=(0x14001E010,),
                pokes=((0x14001E000, bytes.fromhex("060000c0")),
                       (0x14001E010, bytes.fromhex("00e0014001000000"))))
    assert other.result == 0, hex(other.result)

    try:
        run(exe, 0x1400055C4)
    except GuestFault:
        pass
    else:
        raise AssertionError("a non-entry fragment should fault in the guest")

    print("refexec wrapper: ok")


if __name__ == "__main__":
    _selftest()
