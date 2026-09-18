# Upstream reuse map

What we take from each project, and what we deliberately do not. Revisions here
should be rare and deliberate; `upstreams.lock.toml` holds the pinned revisions.

## sp00nznet/pcrecomp — fork base

Keep:

* project organisation and pipeline philosophy;
* PE import/section/catalog tooling that works for PE32+ (verified: `catalog.py`,
  `rsrc.py`, `pe_analyze.py` section/header reporting);
* Ghidra and IDA helper scripts — `tools/ghidra/DumpBounds.java` is the function
  bounds source used by `recon --bounds`;
* the differential-testing approach and `--selftest` convention;
* image-loader / dispatch / crash-reporting patterns from `runtime/recomp32`;
* the Win32 compatibility-layer pattern, now realised with Wine instead of
  hand-written shims;
* the generated-code publishing discipline (`tools/audit_repo.py`).

Do not take: `tools/pe/pe_analyze.py`'s import walk for PE64. It is a 32-bit
walker and reports one import per DLL on a PE32+ image (see `RECON.md`).

## Wine — the Win32 API layer (required)

Take directly: Wine's DLL implementations, through winelib.

* `winegcc` / `winebuild` build the runtime host module that imports them;
* import libraries (`libkernel32.a`, `libuser32.a`, `libd3d11.a`, `libd3dx9.a`,
  `libxaudio2_8.a`, …) are the link-time surface;
* 622 PE DLLs in `/usr/lib/wine/x86_64-windows` are the implementations.

Verified on wine-11.15 by `scripts/check-winelib.sh`: Win32 calls reach Wine from
native code, a plain native ELF library can stand in for lifted guest code in the
same process, and Wine can call back into native functions.

Do not take: Wine's loader as a way to run the guest program, and Wine's
instruction emulation as an execution path. Both are explicitly out of scope —
see `WINE.md`. Also do not vendor Wine into the tree: it is consumed as an
installed toolchain, not as a submodule (LGPL boundaries in `LICENSES.md`).

## lifting-bits/remill — required CPU semantics

Use directly as the AMD64 instruction semantics and lifting library.

Take: architecture selection (`amd64`, `amd64_avx`), `TraceLifter`, the explicit
`State`/`Memory` model, the `remill-lift` example program shape, and the x86
differential tester. Do not rewrite the x86-64 instruction set.

## lifting-bits/anvill — optional, process-separated

Builds higher-quality whole-program LLVM on top of Remill, but its main branch
consumes protobuf specs from a Ghidra plugin that is not open source, and it is
AGPL-3.0. Use it as a reference and, later, as an optional backend reached by
writing a `program.json` → Anvill protobuf converter. Never link it into the MIT
core.

## lifting-bits/rellic — optional readable C

`.bc` → structured C, for reading difficult functions. Never part of the
execution path: compiling decompiled C back into the program is not a supported
route here.

## revng/revng — optional reference backend

Second opinion on the same PE64 target: control flow, data layout, traces. GPLv2
as a whole, so it stays an external process.

## DXVK

Two distinct roles, both current in `doitsujin/dxvk`:

* drop-in replacement for Wine's `d3d8`/`d3d9`/`d3d10core`/`d3d11`/`dxgi` DLLs
  through native DLL overrides (upstream README);
* DXVK Native: no Wine at all, WSI backend chosen with `DXVK_WSI_DRIVER`
  (`SDL3`, `SDL2`, `GLFW`), requiring wine 10.0+ and mingw-w64 to build.

Default is Wine's own D3D; DXVK is the escape hatch when that is not enough.
`misyltoad/dxvk-native` is kept only as historical reference — it has not moved
since 2022.

## FNA-XNA/FAudio — optional

XAudio2, X3DAudio, XAPO and XACT3 reimplementation, zlib, SDL3 3.2+ backend,
exporting a C API (`FAudio_*`). Wine's own `xaudio2_0`…`xaudio2_9` DLLs are the
default for XAudio2 imports; FAudio is the alternative when a target needs
behaviour or a version Wine does not provide, and using it means writing the
thunk from the guest's COM-shaped calls to `FAudio_*`.

## Ghidra — analysis source, already in the repo

`tools/ghidra/DumpBounds.java` writes `start,end` hex rows (end exclusive) for
every function. `recon --bounds` consumes that CSV as `source: ghidra`, which is
what fills the leaf functions `.pdata` omits. Verified with Ghidra 12.1.2
headless; `doctor` finds `analyzeHeadless` at `/opt/ghidra/support/analyzeHeadless`.
