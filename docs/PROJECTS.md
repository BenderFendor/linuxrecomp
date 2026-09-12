# Project Index

**Why each tool in here exists, and which project bled to produce it.**

This is a provenance ledger, not a status board. Statuses and function counts
move every week and rot in a document; they live in the
[README table](../README.md#the-projects-that-built-this) and nowhere else.
What does not rot is *why* a tool works the way it does, and that is what is
written down here.

Read it when a tool surprises you. Nearly every strange-looking branch in this
repo is a scar from one specific binary, and the entry below names it.

---

## Tool -> origin, at a glance

| Tool | Came from | Because |
|------|-----------|---------|
| `disasm/disasm32.py` | X-Wing Alliance | Capstone recursive descent over a whole PE |
| `disasm32.find_branch_targets` E9 seeding | Trespasser | A linker map proved 7,331 real functions were reached only by `jmp rel32` |
| `disasm/decode16.py`, `disasm/analyze.py` | Civilization | No 16-bit decoder existed that understood MSC 5.x overlays |
| `disasm/largemodel16.py` | DinoPark Tycoon | Borland large model: 3,609 of 3,611 far calls resolved |
| `disasm/fpu_decode.py` | El-Fish | x87 in a 16-bit NE image, mixed into the code stream |
| `disasm/callgraph.py` | Soldier of Fortune | "Who calls this" without booting Ghidra |
| `disasm/score_recovery.py` | Trespasser | A recovered catalog is worthless until scored against symbols |
| `lift/lift32.py` | X-Wing Alliance | The core x86-32 -> C lifter |
| `lift/lift32_cpu.py` | Encarta 97 | A reentrant CPU struct, because MFC re-enters lifted code |
| `lift/lift16.py` | Civilization | 16-bit segmented lifting with a DOS runtime under it |
| `lift/recover.py` | Crimson Skies, Trespasser | Alternate entry points and jmp-thunk chains IDA never lists |
| `lift/difftest.py`, `difftest16.py` | Fury³ | A wrong carry flag broke a menu transition deterministically |
| `lift/translator.py`, `generate.py` | X-Wing Alliance | Pipeline orchestration and a fast linear-sweep fallback |
| `pe/pe_analyze.py` | Soldier of Fortune + Heavy Metal | Two half-analysers merged into one |
| `pe/pe_analyze.py` VirtualSize=0 path | Nocturne | Watcom linker 2.18 writes 0 in every section header |
| `pe/stdcall_argc.py` | Fury³ / Hellbender | Hand-typed stack-purge tables drift; derive them from the SDK |
| `pe/extract_imports.py` | Soldier of Fortune | Six modules, one shared Win32 surface to shim |
| `pe/catalog.py` | Black & White | Cataloguing a whole install tree before picking a target |
| `ne/*` | El-Fish, Microsoft Bob, Catz | The 16-bit New Executable front end and Win16 PASCAL purge table |
| `classify/*` | Gunman Chronicles | 78% of a GoldSrc game is the SDK; find the other 13% |
| `cpp/*` | Black & White | Mangling, demangling and vtable parsing across MSVC and Metrowerks |
| `drm/safedisc_dump.py`, `inject_and_run.c` | X-Wing Alliance, Black & White | SafeDisc v1 and v2+ |
| `assets/isextract.py` | Soldier of Fortune | InstallShield, including multi-volume |
| `assets/extract_wise.py` | Operation Neptune | Wise installer overlays |
| `assets/bin2iso.js`, `extract_cab.sh` | Black & White | BIN/CUE and InstallShield CAB |
| `formats/*` | Encarta 97 | FIF, FTC, M20/MVB, SPAM, DAT, string tables |
| `ghidra/*` | Gunman Chronicles, Black & White | Headless decompile, bounds, stats, xrefs |
| `ida/*` | Crimson Skies, Recoil, MechWarrior 3, POD | IDA follows vtables; the call-graph scan does not |
| `runtime/recomp16/` | Civilization, DinoPark | A whole DOS machine: CPU, INTs, VGA, SDL2 |
| `runtime/recomp32/` | X-Wing Alliance | Global-register model, dispatch, VEH |
| `runtime/recomp32/image_loader.c` | Fury³, Nocturne | Map the original image at its real VA; clamp the section copy |
| `runtime/recomp32/crash_report.c` | Crimson Skies | Every project was writing the same reporter |
| `runtime/recomp32_cpu/`, `runtime/hybrid/` | Encarta 97 | The lifted <-> real boundary |
| `runtime/compat/win32_compat.h` | Soldier of Fortune | 275 Win32 APIs sorted into keep/shim/SDL2/stub |

---

## Sid Meier's Civilization (1991)

**Repo**: [sp00nznet/civ](https://github.com/sp00nznet/civ) ·
**Original**: `CIV.EXE` (305 KB, 16-bit MZ) + 23 overlay modules, Microsoft C 5.x

The oldest binary in the collection, and the reason the entire 16-bit half of
this repo exists: `decode16.py`, `analyze.py`, `lift16.py` and the whole of
`runtime/recomp16/`.

**Notable**: 16-bit segmented memory with overlay loading through INT 3Fh.
Required simulating a complete DOS environment including a Mode 13h
framebuffer. Nothing about this is reusable from a 32-bit toolchain, which is
why the 16-bit path is a parallel pipeline rather than a special case of the
32-bit one.

---

## Operation Neptune (1991, Win32 re-release 1998)

**Repo**: [sp00nznet/operationneptune](https://github.com/sp00nznet/operationneptune) ·
**Original**: `ONWIN32.EXE`, Borland-compiled PE32, unpacked

**Contributed**: `assets/extract_wise.py`.

**Notable**: The re-release **ships its own linker map**. That is the rarest
thing in this line of work -- real ground truth for function starts, names and
sizes -- and it is why this project is the calibration target for
`disasm/score_recovery.py`. If a change to function recovery does not hold up
here, it does not hold up. Also the only Borland CRT in the collection, which
starts up nothing like MSVC's.

---

## DinoPark Tycoon (1993)

**Repo**: [sp00nznet/dinopark](https://github.com/sp00nznet/dinopark) ·
**Original**: 16-bit DOS, Borland large model

**Contributed**: `disasm/largemodel16.py`.

**Notable**: Large model means far calls everywhere and no clean code/data
boundary. `largemodel16.py` completes the call graph across segments and finds
that boundary; measured 3,609 of 3,611 far calls resolved. `tools/lift_full.py`
in that repo is the reference driver for `lift16.Lifter` -- start there rather
than from scratch.

---

## El-Fish (1993)

**Repo**: [sp00nznet/elfish](https://github.com/sp00nznet/elfish) ·
**Original**: 16-bit NE + TSXLIB DOS extender

**Contributed**: the first version of the `ne/` front end, `disasm/fpu_decode.py`.

**Notable**: 121 segments, and x87 mixed directly into the instruction stream,
which is what forced a separate FPU decoder rather than a few extra table
entries. `tools/ne_lift.py` there is the reference driver for lifting a
segmented NE image.

---

## Fury³ (1995) and Hellbender (1996)

**Repos**: [sp00nznet/fury3](https://github.com/sp00nznet/fury3), hellbender (private) ·
**Engine**: Terminal Reality voxel engine, Win32/MSVC

**Contributed**: `pe/stdcall_argc.py`, `runtime/recomp32/image_loader.c`, the
carry-flag model in `lift32.py`, and the case list in `lift/difftest.py`.

**Notable**: The same engine twice is the cheapest possible regression test for
a lifter -- anything that works on Fury³ and fails on Hellbender is a tool bug,
not a game quirk. The `sbb r, r` note in `difftest.py` is from here: the
"precise" carry variant *deterministically* broke the new-game -> briefing
transition, which is how the CF model got settled by measurement rather than
argument.

---

## Catz (1996)

**Repo**: [sp00nznet/catz-recomp](https://github.com/sp00nznet/catz-recomp) ·
**Original**: 16-bit NE engine DLL (PF Magic)

**Notable**: Lifting a *DLL* rather than an EXE, in NE format, where the host
process is real and only the engine is recompiled. Forced `lift16.py` to
support a per-project symbol prefix, because the generated names collided with
the previous project's.

---

## Microsoft Encarta 97 Encyclopedia (1996)

**Repo**: [sp00nznet/encarta](https://github.com/sp00nznet/encarta) ·
**Original**: `ENC97.EXE` + 5 DLLs + 6 legacy 16-bit components + 14 `.M20` files, MFC 4.0 / MSVC 4.x

**Contributed**: all of `formats/`, `runtime/hybrid/`,
`runtime/recomp32_cpu/`, `lift/lift32_cpu.py`, and `docs/HYBRID.md`.

**Notable**: Not a game, which is the point -- the approach works on any kind
of application. It is also the project that forced the **real -> lifted**
direction of the hybrid boundary to exist. An MFC app is mostly framework
calling back into application code; without that direction, "the recompiled app
runs" would have meant the entry point runs and MFC does everything else.
`DECO_32.DLL` is a third-party Iterated Systems fractal codec, fully recompiled
and byte-exact with no DLL present.

---

## Grand Theft Auto (1997)

**Repo**: [sp00nznet/gta](https://github.com/sp00nznet/gta) ·
**Engine**: DMA "Race'n'Chase"

**Notable**: The handler table starts at `0x4B4AD1` -- an *odd* address, inside
a packed struct array. That single fact is why
`disasm32.find_data_code_pointers` scans every byte offset instead of only
aligned ones. An aligned-only scan misses the table entirely and the functions
in it surface at runtime as unresolved indirect calls.

---

## POD Gold (1997)

**Repo**: [sp00nznet/pod-recomp](https://github.com/sp00nznet/pod-recomp) ·
**Engine**: Ubi Soft MMX software rasteriser

**Contributed**: the MMX instruction coverage in `lift32.py`, the MMX register
aliasing in `runtime/recomp32/recomp_types.h`, and the self-modified-immediate
handling.

**Notable**: A hand-written MMX inner loop that rewrites its own immediates at
runtime. The lifter cannot treat an immediate as a constant when the code
writes to it, and `recomp_types.h` documents exactly where MMX and x87 alias --
POD never interleaves them, which is the only reason the simple model holds.

---

## X-Wing Alliance (1999)

**Repo**: [sp00nznet/xwa](https://github.com/sp00nznet/xwa) ·
**Original**: `xwingalliance.exe`, MSVC, SafeDisc v1, fixed base `0x00400000`

**Contributed**: `disasm/disasm32.py`, `lift/lift32.py`, `lift/translator.py`,
`lift/generate.py`, `drm/safedisc_dump.py`, `runtime/recomp32/`, both
`templates/`.

**Notable**: This project produced the core automated pipeline; most of the
32-bit toolchain is its descendant. SafeDisc decryption needed a custom memory
dumper because static unwrapping was not viable.

---

## Zipper GOS: Recoil (1999), MechWarrior 3 (1999), Crimson Skies (2000)

**Repos**: [sp00nznet/crimsonskies](https://github.com/sp00nznet/crimsonskies);
recoil and mw3 private ·
**Engine**: Zipper Interactive GOS, three generations

**Contributed**: `tools/ida/`, `lift/recover.py`,
`runtime/recomp32/crash_report.c`.

**Notable**: Function discovery here was bootstrapped with **IDA Pro** rather
than a call-graph scan, because GOS is vtable-heavy and a scan that only
follows CALLs never reaches a virtual method. That is what `tools/ida/` is for.
Three games on one engine also made it obvious that every project was
hand-rolling the same crash reporter, so it moved into `runtime/`.

---

## Soldier of Fortune (2000)

**Repo**: [sp00nznet/sof](https://github.com/sp00nznet/sof) ·
**Engine**: Quake II (heavily modified) + GHOUL ·
**Original**: `SoF.exe` + `gamex86.dll` + `ref_gl.dll` + `player.dll` + 3 sound DLLs, MSVC 6.0

**Contributed**: `pe/pe_analyze.py` (merged with Heavy Metal's),
`pe/extract_imports.py`, `assets/isextract.py`, `runtime/compat/win32_compat.h`.

**Notable**: Non-standard image bases (0x20M, 0x30M, 0x40M, 0x50M), Winsock
imported **by ordinal**, and a `GetRefAPI` calling convention that differs from
stock Quake II. Seven modules sharing one Win32 surface is why
`extract_imports.py` prints a cross-module summary rather than one table per
file.

---

## Gunman Chronicles (2000)

**Repo**: [sp00nznet/gunman](https://github.com/sp00nznet/gunman) ·
**Engine**: GoldSrc

**Contributed**: all of `classify/`, `ghidra/DecompileAll.java`,
`ghidra/ExportFunctions.java`.

**Notable**: 78% of the binary is the Half-Life SDK. Only 499 of 3,990
functions need real RE work -- but you have to *prove* which 499, which is the
entire job of the four-pass classifier: names, string references, call-graph
propagation, then address clustering (functions from one source file compile
adjacent).

---

## Heavy Metal: FAKK2 (2000)

**Repo**: [sp00nznet/heavymetal](https://github.com/sp00nznet/heavymetal) ·
**Engine**: id Tech 3 + Ritual UberTools

**Contributed**: `pe/pe_analyze.py` (merged), `assets/pk3_inspect.py`.

**Notable**: A copy-on-write `str` class exported by all three binaries, 50
symbols -- the critical ABI bridge, and the kind of thing that has to be found
before anything links.

---

## Black & White (2001)

**Repo**: [sp00nznet/bw](https://github.com/sp00nznet/bw) ·
**Engine**: Lionhead custom, MSVC 6.0, SafeDisc

**Contributed**: all of `cpp/`, `ghidra/GhidraStats.java`,
`drm/inject_and_run.c`, `assets/bin2iso.js`, `assets/extract_cab.sh`,
`pe/catalog.py`.

**Notable**: The most C++-heavy project here. Seven-level class hierarchy
(`Base` -> `GameThing` -> `Object` -> `Mobile` -> `Living`...), and a
`CreatureMental` struct of 135 KB. Required a full mangling/demangling
toolchain in both directions and across two compilers.

---

## Jurassic Park: Trespasser (1998)

**Repo**: private ·
**Original**: `setup\tpassp6.exe`, the Pentium Pro/II build. Plain MSVC 6.0 PE32, no DRM.

**Contributed**: `disasm/score_recovery.py`, the E9 tail-call seeding in
`disasm32.find_branch_targets`, and [CONSOLIDATION.md](CONSOLIDATION.md).

**Notable**: This project's only contribution so far is *measurement*, and it
has been worth more than most features. Scoring `disasm32.py` against a linker
map found it missing **7,331 functions** that IDA found -- 89% of them reached
by `jmp rel32` and nothing else, 95% C++ mangled names, 61% eight bytes or
smaller: optimised `__thiscall` accessors with no recognisable prologue. Four
lines of fix recovered 6,550 of them. Nobody had scored the disassembler
before, so nobody knew.

---

## Nocturne (1999)

**Repo**: private ·
**Engine**: Terminal Reality, Watcom C/C++32

**Contributed**: the `VirtualSize == 0` tolerance in `pe/pe_analyze.py`, and
the clamped section copy in `runtime/recomp32/image_loader.c`.

**Notable**: Watcom linker 2.18 writes `VirtualSize = 0` in **every** section
header. Every PE tool that trusts that field silently produces empty sections.
Watcom also gives the loader a 42 MB image, which is where the unclamped
section copy was found -- it had been reading past the end of the file on
anything large enough to notice.

---

## Rise of Legends (2006)

**Repo**: private ·
**Engine**: Big Huge Games rts2, MSVC 7.1

**Notable**: The stress test. 13.25 MB, 19.2 million instructions, **25,513
functions reachable only through vtables**, and no RTTI to lean on. Everything
else the toolchain has been proven on is smaller, older, or both. It is the
strongest argument for porting a real vtable scanner from xboxrecomp: a
function recovery pass that cannot follow a vtable misses most of this binary.

---

## The Fallout forks (1997, 1998)

**Repos**: [fallout1-re](https://github.com/sp00nznet/fallout1-re),
[fallout2-re](https://github.com/sp00nznet/fallout2-re) ·
**Upstream**: alexbatalov's reverse-engineered source

Not recompilations -- forks of completed RE work, kept here because they answer
the "what is this *for*" question. Once the code exists, a 1997 DOS game gets a
web port, a multiplayer server and a Docker stack. That is the payoff the rest
of the repo is working towards.
