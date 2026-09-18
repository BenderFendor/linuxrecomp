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
"$CC" -O2 -g0 "$ROOT/tests/fixtures/win64/data_read.c" -o "$OUT/data_read.exe"

# The RTTI fixture must be MSVC-ABI, so it is not a MinGW build: GCC's Itanium
# RTTI has a different record layout. clang can target the MSVC ABI directly and
# lld-link can link it without a Windows SDK or a CRT.
if command -v clang >/dev/null 2>&1 && command -v lld-link >/dev/null 2>&1; then
  clang --target=x86_64-pc-windows-msvc -c -O1 \
    -o "$OUT/rtti_msvc.obj" "$ROOT/tests/fixtures/win64/rtti_msvc.cpp"
  lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /force:unresolved \
    /out:"$OUT/rtti_msvc.exe" "$OUT/rtti_msvc.obj" 2>/dev/null
  echo "built rtti_msvc.exe (MSVC ABI, x64 RTTI records present)"
else
  echo "skipping rtti_msvc.exe: needs clang and lld-link (MSVC ABI target)" >&2
fi

file "$OUT"/*.exe
