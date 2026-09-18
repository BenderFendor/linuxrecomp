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
| `exports` | Name, ordinal, VA, forwarder string, `kind` (`code`/`data`/`forwarder`) and containing section |
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
   `RUNTIME_FUNCTION` per unwinding region. These are merged into function ranges
   first (see the section below), because MSVC splits one function across several
   regions. An external start that lands inside a merged range is reported as a
   split (`recon.notes` = `split_starts`) rather than added as a new function.
2. `ghidra` — ranges from `--bounds`, the CSV written by the repo's existing
   `tools/ghidra/DumpBounds.java` (`start,end` hex, end exclusive). This fills
   what `.pdata` leaves out: both MinGW and MSVC omit leaf functions.
3. `export` — **an export only counts if it lives in executable code.** MSVC
   exports data with decorated names: `??_7CPackage@HLLib@@6B@` is "vftable for
   CPackage", and those live in `.rdata`. Treating every export as a function
   start put 43 vftables into the function list on `HLLib.dll`; a lifter pointed
   at them executes data and produces code that was never in the program. Exports
   are therefore classified as `code`, `data` or `forwarder`, and only `code`
   ones can become functions. Measured on `HLLib.dll`: 668 exports → 625 code,
   43 data, 0 forwarder.
   A `code` export that lands inside an existing range is a split, not a new
   function; one that matches a range's start is used as that range's name.
   Until an end is established, the function's `end` is `null`.
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

## Relation to the upstream PE tools

`tools/pe/pe_analyze.py` remains the repo's general PE analyzer and everything
architecture-neutral still uses it (`catalog.py`, `rsrc.py`, `map_names.py`,
`debug_symbols.py`). Its `struct` fallback — the path taken when `pefile` is
absent — used to walk import thunks in 4-byte steps with a 32-bit ordinal flag.
On a PE32+ image that reads thunk 0's low half (a valid name RVA), then the same
thunk's high half (zero) and stops, reporting exactly one import per DLL.

That defect is fixed in this fork, ported from work already verified against a
189 MB x64 binary where it took the import count from 109 to 3,928, matching
`objdump -p` exactly. On the fixture below the patched analyzer now reports 45
imports from 9 DLLs; `python tools/pe/pe_analyze.py
work/linux64/fixtures/return42.exe` checks that in one command.

`tools/linux64/pe64.py` is not a reimplementation of that fix. Recon needs what
`pe_analyze` does not model: base relocations with decoded kinds, the TLS
directory and its callback array, exports with forwarders, `.pdata` plus decoded
`UNWIND_INFO`, every data directory, and the loader's section mapping rule for
raw tails. Those are what the spec is built from. `pe64.py` also refuses a PE32
image outright rather than half-parsing one.

## C++ RTTI as a second source of function starts

`tools/cpp/rtti.py` reads MSVC RTTI, and in this fork it handles the x64 layout
as well: locator signature reads 1 instead of 0, and every inter-record pointer
is a 4-byte image-relative offset rather than an absolute VA. Getting that wrong
is not a crash — the parser "finds" type descriptors at addresses that hold
something else and names the wrong class.

On a large x64 binary this recovers tens of thousands of classes and vtable
slots. A vtable slot is proof of a function start, including the virtual-only
methods that no CALL site names and `.pdata` may omit.

The two recoveries are checked against each other on `rtti_msvc.exe`, which is
MSVC-ABI on purpose: GCC emits Itanium RTTI, so a MinGW fixture would not
exercise the parser at all. The checks are that every RTTI method address falls
inside executable code, that none falls in the *interior* of a recovered range,
and that at least one coincides with a recovered start. "No interior hits" is
the load-bearing one: a wrongly matched RTTI record produces an interior
address, and an interior address is junk for a lifter.

Ingesting those starts into the spec is P8 work; it would add an `rtti` value to
the function `source` enum.

## MSVC `.pdata` is a region table, not a function table

One MSVC function is often split into several unwinding regions, and each
continuation begins exactly where the previous region ends and carries
`UNW_FLAG_CHAININFO` pointing at the region that holds the function's prologue.
Measured on the project's test binaries, every chained region is address
contiguous with another region (143 of 143 on HLExtract.exe, 210 of 210 on
HLLib.dll). Chains can be longer than two: `0x13D0`, `0x13F1` and `0x1478` on
HLExtract.exe are three regions of one function.

Without merging, those continuations look like tiny functions. HLExtract.exe
reported one 5-byte "function" that is really `add rsp, 0x28; ret`. A lifter
pointed at it produces an epilogue as if it were a function entry, and the real
function gets lifted a second time through its own trace.

`functions.merge_unwind_regions` folds a chained region into the range it
continues. HLExtract.exe goes from 405 regions to 262 functions, HLLib.dll from
917 to 707, and `recon.regions_merged` reports the difference.

Two consequences to keep in mind:

* the merged range is still an *unwind* range, so a function's real extent can
  run past its `end` when the tail has no unwind record. Consumers must follow
  control flow instead of treating `end` as a hard boundary. HLExtract.exe
  covers 90,613 of 96,768 code bytes, so about 6 KB sits outside any region.
* the raw region table stays in the spec's `unwind` array, which is what exception
  handling needs in P8.

## Known gaps (deliberate, tracked in ROADMAP.md)

* Leaf functions are absent from `.pdata`; supply `--bounds` from Ghidra, or
  recover them by scanning call targets in P3.
* Exports not covered by `.pdata` have `end: null`.
* No direct call/jump edges or indirect-call sites yet (P3).
* Delay imports are not parsed; `tools/pe/delay_imports.py` covers that question
  today.
* Load-config and `.xdata` handler bodies are recorded but not yet interpreted
  (P8).
* RTTI-recovered starts are not yet merged into the spec (P8).

## Two things that bite in this reader

**Chained unwind records.** `UNWIND_INFO` with `UNW_FLAG_CHAININFO` carries a
whole `RUNTIME_FUNCTION` (12 bytes) after its codes, not a 4-byte field. In
CPython 3.14 `struct.unpack` requires the buffer to match the format exactly, so
unpacking a 4-byte format out of that 12-byte record raises
`struct.error: unpack requires a buffer of 4 bytes` — which is how `HLExtract.exe`
first broke recon. Read the whole record and use `struct.unpack_from`. The
synthetic image in `test_pe64.py` carries a chained record for this reason.

**Reads never return short slices.** A section header can claim more raw data
than the file holds, and slicing those phantom bytes yields a short buffer that
only fails later, inside `struct.unpack`. `rva_to_offset`/`read_rva` therefore
bound against the file length as well as the section, and return `None` instead
of a partial read. `test_pe64.py` checks the invariant on a truncated image.

## Checks

```
python -m tools.linux64 selftest        # synthetic PE32+ image + fixtures + schema
python -m tools.linux64 doctor          # toolchain, Wine layer, pinned upstreams
python tools/cpp/rtti.py --selftest     # RTTI parser at both pointer widths
python tools/pe/pe_analyze.py work/linux64/fixtures/return42.exe   # 45 imports
```

`test_pe64.py` builds a synthetic PE32+ image byte by byte and asserts exact
parse results — ordinal import beside a name import, a zero `RUNTIME_FUNCTION`
slot, a section whose VirtualSize is smaller than SizeOfRawData, a BSS section,
an `ABSOLUTE` relocation that must be skipped, and a TLS callback list. It runs
with no compiler and no fixtures, then adds checks against the real MinGW
fixtures when they are present and prints `SKIP` when they are not.
