"""Differential tests: lifted code against the reference execution.

Milestone P2's acceptance check. Each case runs the same function twice, once as
the original bytes on the real CPU (through ``refexec``) and once as Remill-lifted
code under the project's runtime (through ``lifted_harness``), then compares the
reports.

    python -m tools.linux64 difftest IMAGE
    python -m tools.linux64 difftest IMAGE --case compares-other-value

What is compared: the return value, any requested guest memory, and that the
lifted trace stopped by returning rather than running into a boundary the runtime
does not model yet. Cases are fixed rather than random so a failure is
reproducible.

What is not compared: stack contents. The reference runs the guest function on
the host stack while the lifted harness gives it a guest stack, so stack
addresses differ by construction. Image memory is comparable and is what the
cases read.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import refexec
from refexec import GuestFault, RefExecError, RefRun

SCRATCH = 0x14001E000          # a writable guest address in HLExtract.exe's .data
POINTER_SLOT = SCRATCH + 0x10


@dataclass
class Case:
    """One differential case."""

    label: str
    va: int
    args: Tuple[int, ...] = ()
    pokes: Tuple[Tuple[int, bytes], ...] = ()
    dumps: Tuple[Tuple[int, int], ...] = ()
    expect: Optional[int] = None
    note: str = ""


@dataclass
class CaseResult:
    case: Case
    reference: Optional[RefRun]
    lifted: Optional[RefRun]
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def compare(reference: RefRun, lifted: RefRun, case: Case) -> List[str]:
    """Differences between two runs of the same inputs."""
    problems = []
    if reference.result != lifted.result:
        problems.append(f"result {reference.result:#x} != {lifted.result:#x}")
    if case.expect is not None and reference.result != case.expect:
        problems.append(f"reference returned {reference.result:#x}, expected {case.expect:#x}")
    if lifted.stop != "returned":
        problems.append(f"lifted trace stopped with {lifted.stop} ({lifted.stop_pc and hex(lifted.stop_pc)})")
    for address, expected in reference.memory.items():
        actual = lifted.memory.get(address)
        if actual != expected:
            problems.append(
                f"memory at {address:#x}: reference {expected.hex()} != "
                f"lifted {None if actual is None else actual.hex()}")
    return problems


def run_case(image: str, case: Case, harness: Optional[str] = None,
             timeout: float = 30.0) -> CaseResult:
    """Run one case through both executors and compare."""
    result = CaseResult(case=case, reference=None, lifted=None)
    try:
        result.reference = refexec.run(image, case.va, case.args, case.pokes, case.dumps,
                                       timeout=timeout)
    except (GuestFault, RefExecError) as exc:
        result.problems.append(f"reference failed: {exc}")
        return result
    try:
        result.lifted = refexec.run_lifted(image, case.va, case.args, case.pokes,
                                           case.dumps, timeout=timeout, harness=harness)
    except (GuestFault, RefExecError) as exc:
        result.problems.append(f"lifted failed: {exc}")
        return result
    result.problems.extend(compare(result.reference, result.lifted, case))
    return result


def _pointed_dword(value: int) -> Tuple[Tuple[int, bytes], ...]:
    """Pokes for a function that reads a pointer and then a dword at it.

    The pointer slot holds the address of the dword, so the second read lands on
    the value the case is about.
    """
    dword = value.to_bytes(4, "little")
    pointer = SCRATCH.to_bytes(8, "little")
    return ((SCRATCH, dword), (POINTER_SLOT, pointer))


CASES: Dict[str, List[Case]] = {
    "HLExtract.exe": [
        Case(label="returns-constant", va=0x140006D80, expect=1,
             note="the whole function is mov ebx,1; mov eax,ebx"),
        Case(label="returns-constant-with-args", va=0x140006D80,
             args=(0x11, 0x22, 0x33, 0x44), expect=1,
             note="arguments must not change the result"),
        Case(label="compares-pointed-dword-match", va=0x14000C5F0,
             args=(POINTER_SLOT,), pokes=_pointed_dword(0xC0000005),
             dumps=((POINTER_SLOT, 8),), expect=1,
             note="cmpl against 0xC0000005, then sete: exercises lazy flags"),
        Case(label="compares-pointed-dword-other", va=0x14000C5F0,
             args=(POINTER_SLOT,), pokes=_pointed_dword(0xC0000006),
             dumps=((POINTER_SLOT, 8),), expect=0,
             note="same code path, comparison fails"),
    ],
}


def cases_for(image: str) -> List[Case]:
    return CASES.get(os.path.basename(image), [])


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.linux64 difftest",
        description="Compare lifted code against the reference execution")
    parser.add_argument("image", help="PE32+ image whose functions were lifted")
    parser.add_argument("--case", action="append", default=None,
                        help="run only this case label (repeatable)")
    parser.add_argument("--harness", default=None, help="path to lifted_harness")
    args = parser.parse_args(argv)

    cases = cases_for(args.image)
    if not cases:
        print(f"difftest: no cases registered for {os.path.basename(args.image)}")
        return 0
    if args.case:
        wanted = set(args.case)
        cases = [case for case in cases if case.label in wanted]
        if not cases:
            print(f"difftest: no case matched {sorted(wanted)}", file=sys.stderr)
            return 1

    failures = 0
    for case in cases:
        result = run_case(args.image, case, harness=args.harness)
        status = "ok  " if result.ok else "FAIL"
        detail = ""
        if result.ok and result.reference and result.lifted:
            detail = (f"result={result.reference.result:#x} "
                      f"stop={result.lifted.stop}")
        print(f"  [{status}] {case.label:<34} {detail}")
        for problem in result.problems:
            print(f"         {problem}")
            failures += 1

    print(f"difftest: {len(cases) - failures} of {len(cases)} cases matched")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
