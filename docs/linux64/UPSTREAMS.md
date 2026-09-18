# Upstream reuse map

What we take from each project, and what we deliberately do not. Revisions here
should be rare and deliberate; `upstreams.lock.toml` holds the pinned revisions.

## sp00nznet/pcrecomp — fork base

Keep:

* project organisation and pipeline philosophy;
* PE import/section/catalog tooling — verified on PE32+ after the x64 analysis
  port, below;
* Ghidra and IDA helper scripts — `tools/ghidra/DumpBounds.java` is the function
  bounds source used by `recon --bounds`;
* the differential-testing approach and `--selftest` convention;
* image-loader / dispatch / crash-reporting patterns from `runtime/recomp32`;
* the Win32 compatibility-layer pattern, now realised with Wine instead of
  hand-written shims;
* the generated-code publishing discipline (`tools/audit_repo.py`).

### x64 analysis port (applied here)

Two upstream defects were found and fixed while evaluating this toolchain
against a 189 MB x64 binary, and this fork carries the fixes:

* `tools/pe/pe_analyze.py` walked import thunks at 4-byte stride with a 32-bit
  ordinal flag. On PE32+ that reports one import per DLL: 109 instead of 3,928
  on that binary, and 9 instead of 45 on this repo's fixture. Now
  pointer-sized, verified against `objdump -p`.
* `tools/cpp/rtti.py` refused the PE32+ RTTI layout. Now parses both widths
  (locator signature 0/1, absolute VA vs. 4-byte image-relative field), which
  took a large x64 target from 0 to 15,981 classes and 50,561 virtual methods,
  with 80.5% of vtable slots landing exactly on `.pdata` starts and none landing
  inside a known function.

Both are `--selftest`-covered (`rtti.py` builds its synthetic image at both
widths), and recon's fixture checks keep the import fix honest. The 16-bit and
32-bit paths are unchanged by either.

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
