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
import hashlib
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import refexec
from refexec import GuestFault, RefExecError, RefRun

SCRATCH = 0x14001E000          # a writable guest address in HLExtract.exe's .data
POINTER_SLOT = SCRATCH + 0x10
SCRATCH_LEN = 0x200
# Both executors get the same zeroed scratch area, so a function that reads
# through a pointer argument sees identical bytes in each and the comparison
# stays about the lift rather than about uninitialised data.
ZERO_SCRATCH = ((SCRATCH, bytes(SCRATCH_LEN)),)
# A scratch area where every pointer-sized slot points back at the start of the
# area. A function that follows two levels of pointer lands in mapped memory
# instead of faulting, which turns a "cannot compare" into a comparison. The
# values are arbitrary but identical on both sides, which is all the comparison
# needs.
SELF_POINTER_SCRATCH = ((SCRATCH, (SCRATCH.to_bytes(8, "little")) * (SCRATCH_LEN // 8)),)
POINTER_ARGS = (
    (SCRATCH, SCRATCH + 0x40, SCRATCH + 0x80, SCRATCH + 0xC0),
    (SCRATCH + 0x100, 0, SCRATCH + 0x100, 0x10),
)
SELF_POINTER_ARGS = ((SCRATCH, SCRATCH + 0x10, SCRATCH + 0x20, 0x40),)


@dataclass
class Case:
    """One differential case."""

    label: str
    va: int
    args: Tuple[int, ...] = ()
    pokes: Tuple[Tuple[int, bytes], ...] = ()
    dumps: Tuple[Tuple[int, int], ...] = ()
    expect: Optional[int] = None
    expect_memory: Dict[int, bytes] = field(default_factory=dict)
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
    # An expected value in the case catches a case that was set up wrong (or a
    # write that never happened on either side), which comparing two runs alone
    # cannot see.
    for address, expected in case.expect_memory.items():
        actual = reference.memory.get(address)
        if actual != expected:
            problems.append(
                f"reference memory at {address:#x} is "
                f"{None if actual is None else actual.hex()}, expected {expected.hex()}")
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


def _data_read_cases(image: str) -> List[Case]:
    """Cases for the data-section fixture, with addresses read from the image.

    Every address comes from the export table, so nothing breaks if the fixture
    is rebuilt with different section layout. The fixture exports its globals for
    exactly this reason.
    """
    import pe64

    loaded = pe64.PE64Image.load(image)
    exports = {symbol.name: loaded.va(symbol.rva) for symbol in loaded.exports
               if symbol.forwarder is None}
    magic = 0x1234ABCD
    initial = 0x0BADF00D
    global_va = exports.get("global_value")
    read_magic = exports.get("read_magic")
    read_global = exports.get("read_global")
    write_global = exports.get("write_global")
    if not all((global_va, read_magic, read_global, write_global)):
        return []

    return [
        Case(label="read-rdata-constant", va=read_magic, expect=magic,
             note="a const in .rdata, so the address has to be right"),
        Case(label="read-data-global", va=read_global, expect=initial,
             note="a mutable global in .data"),
        Case(label="write-data-global", va=write_global, args=(0xDEADBEEF,),
             dumps=((global_va, 4),), expect=initial,
             expect_memory={global_va: (0xDEADBEEF).to_bytes(4, "little")},
             note="returns the previous value and the dump shows the write landed"),
        Case(label="write-data-global-zero", va=write_global, args=(0,),
             dumps=((global_va, 4),), expect=initial,
             expect_memory={global_va: bytes(4)},
             note="same path with a zero write"),
    ]


def cases_for(image: str) -> List[Case]:
    name = os.path.basename(image)
    if name == "data_read.exe":
        return _data_read_cases(image)
    return CASES.get(name, [])


def seeded_args(va: int, index: int, count: int = 4, mask: int = 0xFFFF) -> Tuple[int, ...]:
    """Deterministic pseudo-random arguments for a case.

    Values are masked to keep them small: a random 64-bit pointer makes most
    functions fault in the reference, which costs a comparison to learn nothing.
    Small values still exercise arithmetic, branches and comparisons.
    """
    digest = hashlib.blake2b(f"{va:x}:{index}".encode(), digest_size=32).digest()
    return tuple(int.from_bytes(digest[i * 8:(i + 1) * 8], "little") & mask
                 for i in range(count))


@dataclass
class SweepOutcome:
    label: str
    status: str          # matched, mismatch, blocked, reference-fault, timeout
    detail: str = ""


def sweep(image: str, harness: Optional[str] = None, limit: Optional[int] = None,
          per_function: int = 4, timeout: float = 5.0,
          progress=None) -> List[SweepOutcome]:
    """Compare every recovered function against the reference on seeded inputs.

    A function whose lifted run stops at an import is reported as blocked rather
    than mismatched: the pipeline has not implemented that import yet, and calling
    that a divergence would bury the real signal.
    """
    import functions as fn
    from pe64 import PE64Image

    pe = PE64Image.load(image)
    recovered, _notes = fn.recover_functions(pe)
    targets = [f for f in recovered if f.end_rva is not None and f.end_rva > f.start_rva]
    if limit:
        targets = targets[:limit]

    outcomes: List[SweepOutcome] = []
    for function in targets:
        va = pe.va(function.start_rva)
        label = function.name or f"sub_{va:X}"
        argument_sets = [(), (0, 0, 0, 0), (1, 2, 3, 4)]
        argument_sets += [seeded_args(va, index) for index in range(per_function)]
        argument_sets += list(POINTER_ARGS)
        argument_sets += list(SELF_POINTER_ARGS)
        for index, args in enumerate(argument_sets):
            if index >= 3 + per_function + len(POINTER_ARGS):
                pokes = SELF_POINTER_SCRATCH
            elif index >= 3 + per_function:
                pokes = ZERO_SCRATCH
            else:
                pokes = ()
            case = Case(label=f"{label}#{index}", va=va, args=args, pokes=pokes)
            try:
                reference = refexec.run(image, va, args, pokes, timeout=timeout)
            except GuestFault:
                outcomes.append(SweepOutcome(case.label, "reference-fault",
                                             "reference faulted, nothing to compare"))
                continue
            except RefExecError as exc:
                outcomes.append(SweepOutcome(case.label, "timeout", str(exc)[:120]))
                continue
            try:
                lifted = refexec.run_lifted(image, va, args, pokes, timeout=timeout,
                                            harness=harness)
            except GuestFault as exc:
                outcomes.append(SweepOutcome(case.label, "mismatch",
                                             f"lifted faulted: {exc}"))
                continue
            except RefExecError as exc:
                outcomes.append(SweepOutcome(case.label, "timeout", str(exc)[:120]))
                continue

            if lifted.stop != "returned":
                outcomes.append(SweepOutcome(
                    case.label, "blocked",
                    f"lifted stopped with {lifted.stop} at {lifted.stop_pc and hex(lifted.stop_pc)}"))
                continue
            if lifted.result != reference.result:
                outcomes.append(SweepOutcome(
                    case.label, "mismatch",
                    f"reference {reference.result:#x} != lifted {lifted.result:#x}"))
                continue
            outcomes.append(SweepOutcome(case.label, "matched"))
        if progress:
            progress(len(outcomes), label, outcomes[-1].status)
    return outcomes


def print_sweep(outcomes: List[SweepOutcome], show: int = 10) -> int:
    """Report a sweep. Returns the number of problems worth acting on."""
    counts: Dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
    total = len(outcomes)
    matched = counts.get("matched", 0)
    mismatched = counts.get("mismatch", 0)
    compared = matched + mismatched
    print(f"sweep: {matched} of {total} cases matched")
    if compared:
        print(f"compared {compared} of {total} cases "
              f"({100 * matched // compared}% of comparable cases agreed)")
    else:
        print("no case reached a comparison: every reference run faulted")
    for status in sorted(counts):
        print(f"  {status:<16} {counts[status]}")
    problems = [o for o in outcomes if o.status == "mismatch"]
    for outcome in problems[:show]:
        print(f"  MISMATCH {outcome.label}: {outcome.detail}")
    if len(problems) > show:
        print(f"  ... and {len(problems) - show} more mismatches")
    blocked = [o for o in outcomes if o.status == "blocked"]
    for outcome in blocked[:show]:
        print(f"  blocked  {outcome.label}: {outcome.detail}")
    if len(blocked) > show:
        print(f"  ... and {len(blocked) - show} more blocked cases")
    return len(problems)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.linux64 difftest",
        description="Compare lifted code against the reference execution")
    parser.add_argument("image", help="PE32+ image whose functions were lifted")
    parser.add_argument("--case", action="append", default=None,
                        help="run only this case label (repeatable)")
    parser.add_argument("--harness", default=None, help="path to lifted_harness")
    parser.add_argument("--sweep", action="store_true",
                        help="compare every recovered function on seeded inputs "
                             "instead of the fixed case list")
    parser.add_argument("--limit", type=int, default=None,
                        help="with --sweep, stop after this many functions")
    parser.add_argument("--per-function", type=int, default=4,
                        help="with --sweep, seeded argument sets per function")
    args = parser.parse_args(argv)

    if args.sweep:
        def progress(count: int, label: str, status: str) -> None:
            if count % 200 == 0:
                print(f"  {count} cases... (last {label}: {status})", flush=True)

        outcomes = sweep(args.image, harness=args.harness, limit=args.limit,
                         per_function=args.per_function, progress=progress)
        return 1 if print_sweep(outcomes) else 0

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
