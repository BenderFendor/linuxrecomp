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
    import test_pe64
    return test_pe64.main()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.linux64", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check required and optional toolchain pieces")
    recon = sub.add_parser("recon", help="analyze a PE32+ AMD64 image into a program spec")
    recon.add_argument("args", nargs=argparse.REMAINDER,
                       help="arguments for recon (see: recon --help)")
    sub.add_parser("selftest", help="run the linux64 checks")

    args = parser.parse_args(argv)

    if args.command == "doctor":
        import doctor
        return doctor.run()
    if args.command == "recon":
        import recon as recon_module
        return recon_module.main(list(args.args))
    if args.command == "selftest":
        return _selftest([])
    return 2


if __name__ == "__main__":
    sys.exit(main())
