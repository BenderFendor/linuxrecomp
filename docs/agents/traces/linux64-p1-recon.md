# Trace: linux64 fork + P1 reconnaissance

Status: complete (2026-09-18). Risk tier: medium (new pipeline, no runtime code
executed yet). Rollback: `git revert` this branch; nothing outside the fork is
touched.

## Goal / done criteria

Turn the `pcrecomp-linux64` overlay into a real fork named `linuxrecomp`, wire the
Win32 API strategy the user asked for (use Wine's libraries, do not emulate
through Wine, do not reimplement every DLL), and complete P1: PE32+/AMD64
reconnaissance that emits a schema-validated `program.json`.

## Decisions and the evidence behind them

**Win32 API = Wine's DLLs through winelib.** The user's constraint was "use wine
lib, don't emulate through wine itself, and don't remake each lib". Probes built
with winegcc and run on wine-11.15 showed:

* `winegcc -o probe probe.c -lkernel32` writes `probe.exe` (700-byte POSIX shell
  script) plus `probe.exe.so` (ELF 64-bit LSB shared object, `nm -D` shows
  `T main`) — our code is native ELF, Wine's loader just maps it.
* `winegcc` host + `clang -shared` library in one process: `dispatched=42`, with
  `GetTickCount64`/`Sleep` coming from Wine.
* `CreateThread` with a native body: `hits=3 wait=0 exit=0x1234` — the
  Wine → native callback direction works.

Codified as `scripts/check-winelib.sh` (12 checks, all passing) and documented in
`docs/linux64/WINE.md`.

**Function bounds come from `.pdata` first.** On AMD64 the linker writes the
function table itself, so `recon` treats it as authoritative and only fills gaps
from Ghidra's `DumpBounds.java` CSV (`source: ghidra`) or exports. An external
start inside a `.pdata` range is counted as `split_starts` rather than added.

**A separate PE32+ reader was necessary, not optional.** `tools/pe/pe_analyze.py`
walks import thunks in 4-byte steps with a 32-bit ordinal flag. On
`return42.exe` it reports 9 imports from 9 DLLs; objdump and `pe64.py` both show
45 imports from 9 DLLs (KERNEL32 alone has 14). Upstream PE2+ handling was left
untouched; the 32-bit path still uses the old analyzer.

## Files added or changed

* `tools/linux64/pe64.py` — PE32+ reader (stdlib only, bounds-checked).
* `tools/linux64/functions.py` — range recovery, bounds CSV, range validation.
* `tools/linux64/spec.py`, `schema_check.py`, `spec_schema.json` — spec build,
  validation, and the `linuxrecomp-spec-v1` contract (renamed from
  `pcrecomp-linux64-spec-v1`).
* `tools/linux64/recon.py`, `doctor.py`, `__main__.py`, `__init__.py` —
  `python -m tools.linux64 {doctor,recon,selftest}`.
* `tools/linux64/test_pe64.py` — synthetic PE32+ image plus fixture checks.
* `tests/winelib/*.c`, `scripts/check-winelib.sh` — the Win32 layer probes.
* `tests/README.md`, `docs/linux64/WINE.md`, `docs/linux64/RECON.md`; rewritten
  `README-LINUX64.md`, `docs/linux64/{ARCHITECTURE,ROADMAP,UPSTREAMS,LICENSES}.md`,
  `tools/linux64/backends/README.md`, `runtime/linux64/README.md`,
  `cmake/linux64/README.md`; `README.md` fork header; `upstreams.lock.toml`
  Wine entry; merged `.gitignore`.

## Commands run and what they showed

| Command | Result |
|---|---|
| `./scripts/build-win64-fixtures.sh` | two PE32+ images, 145 KB each |
| `python -m tools.linux64 selftest` | `schema: ok`, `pe64 synthetic: ok`, `fixtures: ok (2 images)` |
| `python -m tools.linux64 recon work/linux64/fixtures/return42.exe` | 45 imports/9 DLLs, 48 `.pdata`, 39 `dir64`, TLS callbacks `0x1400016D0`/`0x1400016B0`, no problems |
| `objdump -p` / `objdump -s -j .reloc` / `-j .rdata` | 45 import rows, 9 DLLs, 5+34 relocation entries, TLS bytes `d0160040 01000000 b0160040 01000000` — all match |
| `recon ... --bounds work/linux64/ghidra/bounds.csv` | 94 functions (`pdata` 48, `ghidra` 46), `add_then_mul` at `0x140001580` inside `[0x140001580,0x1400015A1)` |
| Ghidra 12.1.2 headless + `DumpBounds.java` | 94 functions written to `work/linux64/ghidra/bounds.csv` |
| `recon /usr/lib/wine/x86_64-windows/kernel32.dll` | 450 KB DLL: 2,668 functions, 932 imports, 1,362 exports (102 forwarders), zero range problems |
| `./scripts/check-winelib.sh` | 12/12 checks pass |
| `python -m tools.linux64 doctor` | exit 0; Wine 11.15, MinGW GCC 16.1.0, Ghidra headless found |
| upstream `--selftest` sweep (subagent) | 13 pass, 10 blocked on missing optional deps, 1 pre-existing C failure |

## Failed approaches / corrections

* Optional header read with four `I`s instead of five misread `ImageBase` from
  `BaseOfCode`; caught by the synthetic image test, which is why that test exists.
* Export directory unpacked as 10 fields instead of 11 — same test caught it.
* Synthetic import layout initially gave each DLL a thunk block that overlapped
  the previous DLL's terminator; the ordinal import then vanished. Fixed by
  giving each DLL its own ILT/IAT block, which also documents the real layout.
* `scripts/check-winelib.sh` first referenced `lifted.so` after building
  `liblifted.so`; the probe failure (`File does not exist`) was the fix signal.

## Remaining risks / outside this task

* `runtime/recomp32/mmx_selftest.c` fails to compile (`ptrdiff_t` without
  `<stddef.h>`) — pre-existing upstream debt, left alone.
* Remill is checked out but not built; P2 begins with its LLVM version constraint.
* The Wine probes are display-free by design; the first GUI verification arrives
  with P5.
* Wine version coupling: a Wine upgrade can change DLL availability and behaviour.
  Re-run `./scripts/check-winelib.sh` before blaming our code.

## Next executable step

P2: build Remill, lift one function from `work/linux64/program.json`, and compare
its execution against a reference for the same bytes.
