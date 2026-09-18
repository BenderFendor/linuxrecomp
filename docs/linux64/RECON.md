# Reconnaissance: the `program.json` contract

Milestone P1. Reconnaissance reads a PE32+/AMD64 image and writes one JSON
document describing it. Nothing is lifted and nothing is executed: this is the
step that has to be trustworthy before a lifter exists, because every later bug
either comes from here or is blamed on here.

```
python -m tools.linux64 recon game.exe
python -m tools.linux64 recon game.exe -o work/linux64/game.json
python -m tools.linux64 recon game.exe --bounds work/linux64/ghidra/bounds.csv
python -m tools.linux64 recon game.exe --no-write --quiet   # exit code only
```

Default output: `work/linux64/program.json`. The document is validated against
`tools/linux64/spec_schema.json` before it is written, so a malformed spec is
never persisted.

## What the document contains

| Key | Contents |
|---|---|
| `format`, `arch` | `linuxrecomp-spec-v1`, `amd64` |
| `generator` | Tool version, input file, sha256 of the image, bounds source |
| `image` | Image base, entry point (VA and RVA), subsystem, alignment, stack/heap sizes, link flags |
| `sections` | Name, RVA/VA, virtual and raw sizes, mapped size, characteristics, decoded flags |
| `directories` | Every data directory with its RVA/size/presence |
| `functions` | Recovered `[start, end)` ranges as guest VAs, with name and provenance |
| `imports` | One entry per IAT slot: DLL, name or ordinal, hint, IAT VA, ILT VA |
| `exports` | Name, ordinal, VA, and the forwarder string when the RVA points inside the export directory |
| `relocations` | Base relocations with type and decoded kind |
| `tls` | Raw data range, TLS index VA, callback VAs, zero-fill size |
| `unwind` | Every `.pdata` entry with decoded `UNWIND_INFO`: prolog size, code slots, frame register, handler VA, chain |
| `recon` | Function counts by source, coverage, relocation histogram, notes, and range problems |

Rule: **every address in the document is a guest virtual address** (image base
applied) unless the key ends in `_rva` or `_offset`. A lifter can therefore use
the numbers directly as guest addresses without re-adding the image base.

## Where function bounds come from

Trust order, recorded per function in the `source` field:

1. `pdata` — the AMD64 exception directory. On x64 the linker writes one
   `RUNTIME_FUNCTION` per function with unwind data, with `[begin, end)` in RVAs.
   This is the linker's own table, not a heuristic, so it is authoritative: an
   external start that lands inside one of these ranges is reported as a split
   (`recon.notes` = `split_starts`) rather than added as a new function.
2. `ghidra` — ranges from `--bounds`, the CSV written by the repo's existing
   `tools/ghidra/DumpBounds.java` (`start,end` hex, end exclusive). This fills
   what `.pdata` leaves out: both MinGW and MSVC omit leaf functions.
3. `export` — a start that is exported but covered by neither of the above.
   Its `end` is `null`, because nothing established it.
4. `entrypoint` — the image entry point when nothing else covers it.

`end` is `null` rather than equal to `start` in that case, so a consumer cannot
mistake "unknown extent" for "empty function".

## Measured results

Fixture `return42.exe` (MinGW-w64 GCC 16.1.0, built by
`./scripts/build-win64-fixtures.sh`), cross-checked against
`x86_64-w64-mingw32-objdump`:

| Quantity | recon | objdump |
|---|---|---|
| Imports | 45 from 9 DLLs (KERNEL32 14) | 45 rows, 9 `DLL Name:` entries |
| Base relocations | 39, all `dir64` | 5 + 34 entries in the two `.reloc` blocks |
| `.pdata` entries | 48 | exception directory size `0x240` / 12 |
| TLS callbacks | `0x1400016D0`, `0x1400016B0` | `.rdata`@`0x49E0`: `1400049e0 d0160040 01000000 b0160040 01000000` |

Same image with `--bounds work/linux64/ghidra/bounds.csv` (Ghidra 12.1.2, 94
functions): 94 recovered (`pdata` 48, `ghidra` 46), 6,473 of 7,168 code bytes
covered, no range problems, and the export `add_then_mul` lands at
`0x140001580` inside the recovered range `[0x140001580, 0x1400015A1)` — the same
range Ghidra independently reported.

Real-world check, Wine's own `kernel32.dll` (450 KB, 13 sections): 932 imports
from 2 DLLs, 1,362 exports (1,260 code, 102 forwarders), 1,869 `.pdata` entries,
2,668 functions, 158,627 covered code bytes, zero range problems.

## Why this does not reuse `tools/pe/pe_analyze.py`

That analyzer is 32-bit first, and its `struct` fallback walks import thunks in
4-byte steps with a 32-bit ordinal flag. On a PE32+ image the thunk array is
8 bytes per entry, so the walk reads the low half of thunk 0 (a name RVA), then
the high half of the same thunk (always zero) and stops — reporting exactly one
import per DLL. On the fixture above it reports 9 imports from 9 DLLs where the
image has 45 (KERNEL32 alone has 14).

`tools/linux64/pe64.py` therefore exists as a PE32+ reader with the
architecture-specific rules in one place: 8-byte thunks, 64-bit image base and
TLS addresses stored as VAs, `DIR64` relocations, and the `.pdata`
`RUNTIME_FUNCTION` table. It is stdlib-only, bounds-checks every read, and
refuses a PE32 image with a message pointing at the 32-bit pipeline. The 16/32-bit
paths in `tools/pe` and `tools/disasm` are untouched.

## Known gaps (deliberate, tracked in ROADMAP.md)

* Leaf functions are absent from `.pdata`; supply `--bounds` from Ghidra, or
  recover them by scanning call targets in P3.
* Exports not covered by `.pdata` have `end: null`.
* No direct call/jump edges or indirect-call sites yet (P3).
* Delay imports are not parsed; `tools/pe/delay_imports.py` covers that question
  today.
* Load-config, RTTI, and `.xdata` handler bodies are recorded but not yet
  interpreted (P8).

## Checks

```
python -m tools.linux64 selftest        # synthetic PE32+ image + fixtures + schema
python -m tools.linux64 doctor          # toolchain, Wine layer, pinned upstreams
```

`test_pe64.py` builds a synthetic PE32+ image byte by byte and asserts exact
parse results — ordinal import beside a name import, a zero `RUNTIME_FUNCTION`
slot, a section whose VirtualSize is smaller than SizeOfRawData, a BSS section,
an `ABSOLUTE` relocation that must be skipped, and a TLS callback list. It runs
with no compiler and no fixtures, then adds checks against the real MinGW
fixtures when they are present and prints `SKIP` when they are not.
