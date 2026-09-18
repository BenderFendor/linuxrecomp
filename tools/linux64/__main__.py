"""CLI for the linux64 pipeline.

  python -m tools.linux64 doctor      environment check
  python -m tools.linux64 recon IMAGE PE32+/AMD64 reconnaissance -> program spec
  python -m tools.linux64 selftest    parser/spec/recovery checks
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence


def _selftest(argv: Sequence[str]) -> int:
    import os

    import difftest
    import refexec
    import test_pe64

    status = test_pe64.main()
    refexec._selftest()

    # Differential tests need a lifted harness and the image. The fixture is
    # built here; the larger target is the project's test program (see
    # docs/linux64/ROADMAP.md) and can be pointed elsewhere with
    # LINUXRECOMP_TARGET. Both are absent in CI, where this step reports a skip.
    targets = [os.path.join(refexec.ROOT, "work", "linux64", "fixtures", "data_read.exe")]
    override = os.environ.get("LINUXRECOMP_TARGET",
                              "/home/bender/projects/filestorecomp/HLExtract/HLExtract.exe")
    if override:
        targets.append(override)
    ran_any = False
    for target in targets:
        if os.path.exists(target) and os.path.exists(refexec.harness_for(target)):
            status = difftest.main([target]) or status
            ran_any = True
    if not ran_any:
        print("difftest: SKIP (needs a lifted harness and a target image)")
    return status


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.linux64", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check required and optional toolchain pieces")
    recon = sub.add_parser("recon", help="analyze a PE32+ AMD64 image into a program spec")
    recon.add_argument("args", nargs=argparse.REMAINDER,
                       help="arguments for recon (see: recon --help)")
    lift = sub.add_parser("lift", help="lift one function to LLVM IR with Remill")
    lift.add_argument("args", nargs=argparse.REMAINDER,
                      help="arguments for lift (see: lift --help)")
    difftest = sub.add_parser("difftest",
                              help="compare lifted code against the reference execution")
    difftest.add_argument("args", nargs=argparse.REMAINDER,
                          help="arguments for difftest (see: difftest --help)")
    runner = sub.add_parser("run", help="run a recompiled program, lifting what it needs")
    runner.add_argument("args", nargs=argparse.REMAINDER,
                        help="arguments for run (see: run --help)")
    sub.add_parser("selftest", help="run the linux64 checks")

    args = parser.parse_args(argv)

    if args.command == "doctor":
        import doctor
        return doctor.run()
    if args.command == "recon":
        import recon as recon_module
        return recon_module.main(list(args.args))
    if args.command == "lift":
        import lift as lift_module
        return lift_module.main(list(args.args))
    if args.command == "difftest":
        import difftest as difftest_module
        return difftest_module.main(list(args.args))
    if args.command == "run":
        from . import run as run_module
        return run_module.main(args.args)
    if args.command == "selftest":
        return _selftest([])
    return 2


if __name__ == "__main__":
    sys.exit(main())
