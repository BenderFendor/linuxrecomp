#!/usr/bin/env bash
# Verify the Win32 API layer strategy on this machine.
#
# The linux64 runtime takes the Windows API from Wine's own DLLs, linked with
# winelib, and keeps recompiled guest code as native ELF that knows nothing
# about Wine. That is a claim about the toolchain, so it is checked here instead
# of assumed:
#
#   1. winegcc produces a winelib module whose own code is native x86-64 ELF
#      (the .exe is a shell launcher; the code lives in the sibling .exe.so).
#   2. Win32 API calls in that module resolve to Wine's DLLs.
#   3. A plain native ELF shared library, standing in for lifted guest code,
#      links into the same process and is called from the Win32 side.
#   4. Wine can call back into a native function (CreateThread body).
#
# Nothing here boots a PE image through Wine: the guest binary is never loaded
# or executed by Wine's loader. Only Wine's Win32 implementations are used.
#
# Usage: ./scripts/check-winelib.sh
# Outputs under work/linux64/winelib/. Exits non-zero if any probe fails.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/tests/winelib"
OUT="$ROOT/work/linux64/winelib"
CC="${CC:-clang}"

failures=0
mkdir -p "$OUT"

say()  { printf '%s\n' "$*"; }
pass() { printf '  [ ok ] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; failures=$((failures + 1)); }

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    say "missing $1: the Win32 layer needs Wine's winelib toolchain (wine, winegcc, winebuild)"
    exit 1
  fi
}

# expect <label> <haystack> <needle>
expect() {
  case "$2" in
    *"$3"*) pass "$1" ;;
    *) fail "$1 (expected '$3')"; printf '    output: %s\n' "$2" ;;
  esac
}

require winegcc
require wine
require "$CC"

export WINEDEBUG="${WINEDEBUG:--all}"

say "linuxrecomp winelib check"
say "  wine:   $(wine --version 2>/dev/null)"
say "  output: $OUT"

# --- 1. winelib module whose code is native ELF ----------------------------

if ! winegcc -O1 -o "$OUT/win32_api.exe" "$SRC/win32_api.c" -lkernel32 >"$OUT/win32_api.build.log" 2>&1; then
  fail "build win32_api"
  sed -n '1,40p' "$OUT/win32_api.build.log"
  exit 1
fi
pass "build win32_api (winegcc -lkernel32)"

if file "$OUT/win32_api.exe.so" 2>/dev/null | grep -q 'ELF 64-bit LSB shared object, x86-64'; then
  pass "winelib code is native ELF (win32_api.exe.so)"
else
  fail "winelib code is native ELF (win32_api.exe.so)"
fi

if nm -D --defined-only "$OUT/win32_api.exe.so" 2>/dev/null | grep -q ' T main'; then
  pass "native main symbol exported from the winelib module"
else
  fail "native main symbol exported from the winelib module"
fi

out="$(timeout 60 "$OUT/win32_api.exe" 2>/dev/null)"
expect "win32 API calls reach Wine (pid/tid)" "$out" "win32 api: pid="

# --- 2. native lifted-code stand-in linked into a winelib host -------------

LIFTED="$OUT/liblifted.so"
if ! "$CC" -O2 -fPIC -shared -o "$LIFTED" "$SRC/lifted.c" >"$OUT/lifted.build.log" 2>&1; then
  fail "build native lifted-code library"
  sed -n '1,40p' "$OUT/lifted.build.log"
else
  pass "build native lifted-code library (clang -shared, no winegcc)"
  if nm -D --defined-only "$LIFTED" 2>/dev/null | grep -q 'sub_140001000'; then
    pass "guest-address symbol present in the native library"
  else
    fail "guest-address symbol present in the native library"
  fi
fi

if ! winegcc -O1 -o "$OUT/host.exe" "$SRC/host.c" "$LIFTED" \
      -Wl,-rpath,"$OUT" -lkernel32 >"$OUT/host.build.log" 2>&1; then
  fail "link native library into a winelib host"
  sed -n '1,40p' "$OUT/host.build.log"
else
  pass "link native library into a winelib host"
  out="$(timeout 60 "$OUT/host.exe" 2>/dev/null)"
  expect "dispatched call into native code returns 42" "$out" "dispatched=42"
  expect "second native function callable in the same process" "$out" "second=0x5a5a5a5a5a5a5a5a"
fi

# --- 3. Wine calling back into native code ---------------------------------

if ! winegcc -O1 -o "$OUT/callback.exe" "$SRC/callback.c" -lkernel32 >"$OUT/callback.build.log" 2>&1; then
  fail "build callback probe"
  sed -n '1,40p' "$OUT/callback.build.log"
else
  pass "build callback probe"
  out="$(timeout 60 "$OUT/callback.exe" 2>/dev/null)"
  expect "Wine thread body ran native code three times" "$out" "hits=3"
  expect "thread exit code survived the boundary" "$out" "exit=0x1234"
fi

say ""
if [ "$failures" -eq 0 ]; then
  say "winelib check: ok (no guest image was loaded or executed by Wine)"
  exit 0
fi
say "winelib check: $failures probe(s) failed"
exit 1
