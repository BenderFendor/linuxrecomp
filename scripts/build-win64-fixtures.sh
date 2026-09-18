#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${MINGW_CC:-x86_64-w64-mingw32-gcc}"
OUT="$ROOT/work/linux64/fixtures"
mkdir -p "$OUT"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "missing $CC (install a mingw-w64 x86_64 compiler or set MINGW_CC)" >&2
  exit 1
fi

"$CC" -O2 -g0 "$ROOT/tests/fixtures/win64/return42.c" -o "$OUT/return42.exe"
"$CC" -O2 -g0 "$ROOT/tests/fixtures/win64/kernel32.c" -o "$OUT/kernel32.exe"

file "$OUT/return42.exe" "$OUT/kernel32.exe"
