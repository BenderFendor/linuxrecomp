"""Run a recompiled program, lifting what execution turns out to need.

Whole-program lifting is not affordable at this project's scale: Photoshop's
325,924 functions at the measured ~31 s each is about 113 days. What a program
actually executes is a far smaller set, so this drives the other direction: run the
program, read the addresses it stops on, lift exactly those, and run again. The
stops are precise ("missing-dispatch at 0x...", "missing-block at 0x..."), which is
what makes the loop safe to automate rather than a search.

Usage:
    python -m tools.linux64 run IMAGE --entry 0x140005310 [--rounds 20] [--jobs 6]
                                      [--flavour winelib|native] [--program-args A B]

Each round builds the harness, runs it, lifts every address the run reported, and
repeats until a run stops for a reason lifting cannot fix, or the round budget runs
out. The transcript of every round is kept in the run directory.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
HARNESS_DIR = ROOT / "work" / "linux64" / "bin"
RUN_DIR = ROOT / "work" / "linux64" / "runs"

# Every stop that means "execution reached code that is not lifted". The address in
# each is a guest address to lift.
STOP_PATTERNS = (
    re.compile(r"stop missing-dispatch at (0x[0-9a-fA-F]+)"),
    re.compile(r"stop missing-block at (0x[0-9a-fA-F]+)"),
    re.compile(r"stop call at (0x[0-9a-fA-F]+) \(call to unlifted address"),
    re.compile(r"stop jump at (0x[0-9a-fA-F]+) \(jump to unlifted address"),
)


def harness_path(image: str, flavour: str) -> pathlib.Path:
    stem = pathlib.Path(image).name
    if flavour == "winelib":
        return HARNESS_DIR / f"lifted_harness-{pathlib.Path(stem).stem}.winelib"
    return HARNESS_DIR / f"lifted_harness-{stem}"


def build_harness(image: str, lift_root: pathlib.Path) -> None:
    completed = subprocess.run(
        [str(ROOT / "scripts" / "build-lifted-harness.sh"), image, str(lift_root)],
        capture_output=True, text=True)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout[-4000:] + completed.stderr[-4000:])
        raise SystemExit(f"harness build failed for {image}")


def run_once(image: str, entry: int, flavour: str, arguments: Sequence[str],
             timeout: float) -> str:
    binary = harness_path(image, flavour)
    if not binary.exists():
        raise SystemExit(f"no harness at {binary}; build it first")
    command = [str(binary), image, hex(entry), *arguments]
    if flavour == "winelib":
        command = ["env", "WINEDEBUG=-all", *command]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        return (expired.stdout or "") + (expired.stderr or "")
    return completed.stdout + completed.stderr


def missing_targets(output: str) -> List[int]:
    found: Dict[int, None] = {}
    for pattern in STOP_PATTERNS:
        for match in pattern.finditer(output):
            found[int(match.group(1), 16)] = None
    return sorted(found)


def report_line(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("lifted: stop "):
            return line
    for line in output.splitlines():
        if line.startswith("lifted: image="):
            return line
    return output.strip().splitlines()[-1] if output.strip() else "(no output)"


def lift_addresses(image: str, lift_root: pathlib.Path, addresses: Iterable[int],
                   jobs: int) -> int:
    lifted = 0
    for address in addresses:
        completed = subprocess.run(
            [sys.executable, "-m", "tools.linux64", "lift", image, "--function", hex(address),
             "--jobs", str(jobs), "--out", str(lift_root)],
            cwd=ROOT, capture_output=True, text=True)
        if completed.returncode == 0:
            lifted += 1
            first = completed.stdout.strip().splitlines()
            print(f"  lifted {address:#x}: {first[0] if first else ''}")
        else:
            print(f"  could not lift {address:#x}: "
                  f"{(completed.stdout + completed.stderr).strip().splitlines()[-1]}")
    return lifted


def run(image: str, entry: int, rounds: int, jobs: int, flavour: str,
        arguments: Sequence[str], lift_root: pathlib.Path, timeout: float) -> int:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    transcript = RUN_DIR / f"{pathlib.Path(image).stem}-{flavour}.txt"
    with transcript.open("w") as handle:
        for round_number in range(1, rounds + 1):
            build_harness(image, lift_root)
            output = run_once(image, entry, flavour, arguments, timeout)
            handle.write(f"===== round {round_number} =====\n{output}\n")
            handle.flush()
            print(f"round {round_number}: {report_line(output)}")
            targets = missing_targets(output)
            if not targets:
                print(f"no unlifted code reached; full output in {transcript}")
                return 0
            print(f"  {len(targets)} address(es) to lift")
            if lift_addresses(image, lift_root, targets, jobs) == 0:
                print("  nothing could be lifted; stopping")
                return 1
        print(f"round budget exhausted; transcript in {transcript}")
        return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image", help="PE32+ AMD64 image to run")
    parser.add_argument("--entry", required=True, help="guest address to start at")
    parser.add_argument("--rounds", type=int, default=20, help="run/lift rounds (default 20)")
    parser.add_argument("--jobs", type=int, default=6, help="parallel lifters")
    parser.add_argument("--flavour", default="winelib", choices=["winelib", "native"],
                        help="which harness to run (default winelib: the host with Win32)")
    parser.add_argument("--lift-root", default=None, help="where lifts live")
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds per run")
    parser.add_argument("--program-args", nargs=argparse.REMAINDER, default=[],
                        help="arguments the program itself should see")
    options = parser.parse_args(argv)

    entry = int(options.entry, 0)
    lift_root = pathlib.Path(options.lift_root) if options.lift_root else (
        ROOT / "work" / "linux64" / "lift")
    arguments = [argument for argument in options.program_args if argument != "--"]
    return run(options.image, entry, options.rounds, options.jobs, options.flavour, arguments,
               lift_root, options.timeout)


if __name__ == "__main__":
    sys.exit(main())
