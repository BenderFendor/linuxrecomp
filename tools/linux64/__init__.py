"""PE32+/AMD64 -> native Linux reconnaissance and pipeline helpers.

Modules here are flat-importable both as ``python -m tools.linux64 <cmd>`` and as
``python tools/linux64/<script>.py``, which is why the package __init__ puts its
own directory on ``sys.path``. That mirrors the rest of this repo: every tool
directory holds peer modules imported by name, not by package path.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
