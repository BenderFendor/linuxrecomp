# Trace: linuxrecomp roadmap P2-P9 against HLExtract.exe

Goal: implement every roadmap step in `docs/linux64/ROADMAP.md`, using
`/home/bender/projects/filestorecomp/HLExtract/HLExtract.exe` as the test
program. Status per phase is recorded here as each one lands; the roadmap is the
authority on what each phase requires.

Risk tier: high (a whole recompilation pipeline). Rollback: revert commits on
`main`; nothing outside the fork is modified except build outputs under
`work/linux64/` (gitignored) and `~/.cache`.

## The test target, measured

| | HLExtract.exe | HLLib.dll |
|---|---|---|
| Size | 131,584 B | 327,680 B |
| Format | PE32+ x86-64, console, linker 8.00 (VS2005) | PE32+ x86-64, DLL, linker 8.00 |
| Image base | 0x140000000, fixed (no relocations) | 0x180000000, 837 DIR64 relocations |
| Sections | 5 (`.text` 96,768 code bytes) | 6 (`.text` 204,288 code bytes) |
| Imports | 130 from 2 DLLs (KERNEL32 82, HLLib 48) | 90 from KERNEL32 |
| Exports | 0 | 668 (625 code, 43 data, 0 forwarder) |
| `.pdata` | 405 entries, 60 with language handlers, 90,613 covered bytes | 917 entries, 145 with language handlers, 183,694 covered bytes |
| TLS | none | none |

Cross-checked with `objdump -p`: import rows 130 and 90, exception directories
`0x12FC`/12 = 405 and `0x2AFC`/12 = 917. Both specs validate against
`spec_schema.json` and report zero range problems.

The import profile is what makes this a sane P9 target for a recompiler: 130
imports across two DLLs, one of them our own code — not the 83-DLL, 3,928-import
profile that makes a modern application hopeless.

## TargetRecon: parser defects the target exposed

Both were found by pointing recon at a real binary rather than a fixture.

**1. Chained unwind records crashed recon** (`unwind_info`, HLExtract entry 7,
`unwind_rva 0x1B70C`, `flags` CHAININFO). The record carries a full 12-byte
`RUNTIME_FUNCTION` after its codes, but the parser unpacked a 4-byte field from
those 12 bytes. CPython 3.14 made `struct.unpack` exact-size — `unpack('<I', 12
bytes)` raises `struct.error: unpack requires a buffer of 4 bytes`, while
`unpack('<I', 4 bytes)` is fine and `unpack_from` tolerates a longer buffer.
Verified in isolation:

```
python 3.14.7
unpack('<I', 4 bytes):  OK -> (67305985,)
unpack('<I', 5 bytes):  struct.error: unpack requires a buffer of 4 bytes
unpack_from('<I', 12 bytes, 0):  OK
```

Fixed with `struct.unpack_from`, and the synthetic image now contains a chained
record so the path is covered without needing the target. Logged as a papercut.

**2. Exported data was treated as code.** `recover_functions` accepted every
non-forwarder export as a function start, which produced 43 bogus functions in
`.rdata`/`.data` on HLLib.dll and made recon report 43 range problems. The
export names say what they are: `??_7CPackage@HLLib@@6B@`, `??_7CMapping@...` —
MSVC vftable symbols. Executing them is the "invented functions" defect class
the upstream `score_recovery.py` warns about. Fixed by classifying exports as
`code`/`data`/`forwarder` from the section they live in and admitting only
`code` exports as function starts; a `code` export inside an existing range is
now a split (or a name for that range) instead of a duplicate range. HLLib.dll
before/after: 43 problems → 0, and 1,200 functions → 1,157 (917 `.pdata` + 240
code exports still outside `.pdata`).

`exports[].kind` and `exports[].section` are now part of the spec contract, and
`recon.export_kinds` reports the split.

**3. Reads could return short slices.** `rva_to_offset` bounded against the
section's `raw_size` but not the file length, so a header claiming more raw data
than the file holds produced a short buffer that only failed later inside
`struct.unpack` — the same confusing shape as defect 1. Now bounded against both,
with a truncated-image test asserting every read is either `None` or exactly the
requested size.

## Verification so far

| Command | Result |
|---|---|
| `python -m tools.linux64 selftest` | schema, synthetic, fixtures, rtti fixture all ok |
| `recon HLExtract.exe` | 405 functions, 130 imports, 0 problems |
| `recon HLLib.dll` | 1,157 functions, 668 exports (625/43), 0 problems |
| `objdump -p` on both | import rows and exception directory sizes match recon |

## Next

P2: build Remill against a compatible LLVM, lift one function from
`program.json`, execute it, and compare against a reference execution.
