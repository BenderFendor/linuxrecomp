# Bring-up roadmap

Rule: the smallest executable that proves the next boundary. Do not start a full
game while the preceding boundary is untested. Every milestone lists a check that
can be run and that fails loudly.

Last revised: 2026-09-18 (after P0 and P1 were completed, and after the Win32
layer was decided to be Wine's own DLLs — see `WINE.md`).

## P0 — fork + reproducible dependencies — **done**

Acceptance, and the evidence:

* overlay applied to a fork of `sp00nznet/pcrecomp`, upstream history preserved
  (`git log` reaches `534e4b7`, the revision pinned in `upstreams.lock.toml`).
* `python -m tools.linux64 doctor` exits 0 on this machine: git, cmake, clang,
  MinGW-w64, Wine 11.15 with `winegcc`/`winebuild` and PE DLLs, Ghidra 12.1.2
  headless, `llvm-config`/`opt`/`llc`.
* `./scripts/build-win64-fixtures.sh` builds `return42.exe` and `kernel32.exe`.
* upstream self-tests still behave as they did before the fork: 13 pass
  (`pe_analyze`, `catalog`, `rsrc`, `map_names`, `merge_names`, `debug_symbols`,
  `rtti`, `score_recovery`, `isextract`, `audit_repo`, `recomp16` CPU self-test,
  `recomp32_cpu` CPU self-test), 10 blocked by missing optional dependencies
  (`capstone` for the disassemblers and lifters, the Windows SDK x86 tree for
  `stdcall_argc`, MinGW's `intrin.h` for the hybrid self-test), 1 pre-existing
  compile failure in `runtime/recomp32/mmx_selftest.c` (`ptrdiff_t` used without
  including `<stddef.h>`), recorded here as unrelated debt, not fixed.

## P1 — PE64 reconnaissance — **done**

Acceptance, and the evidence:

* identifies PE32+ AMD64 and rejects PE32 with a message naming the 32-bit
  pipeline;
* emits image base, entry point, sections, imports, exports, relocations, TLS,
  data directories, `.pdata` unwind records, and function ranges as guest VAs;
* serialises and schema-validates `work/linux64/program.json` before writing;
* Ghidra headless emits bounds for a fixture and they merge as `source: ghidra`;
* cross-checked against `x86_64-w64-mingw32-objdump` and against the raw
  `.reloc`/`.tls` bytes — numbers in `RECON.md`;
* parses Wine's 450 KB `kernel32.dll` with 2,668 functions and no range problems;
* `python -m tools.linux64 selftest` passes, including a synthetic PE32+ image
  that needs no compiler.

## P2 — one AMD64 function → LLVM → host execution — **done**

Acceptance, and the evidence:

* Remill built against LLVM 22 (the system LLVM; Remill's CI matrix covers 17 to
  22). Its dependencies superbuild needed `ENABLE_SLEIGH=ON`, because Remill's
  own configure requires the sleigh package even for x86 lifting.
* Lift: `python -m tools.linux64 lift HLExtract.exe --function 0x140006D80`
  emits `sub_140006d80.ll` plus a manifest that records the image hash, the byte
  range and the lifter identity.
* Compile and link: `scripts/build-lifted-harness.sh` compiles the IR with clang
  and links it with the project's `__remill_*` runtime and a dispatch table built
  from the manifests.
* Execute: `lifted_harness` builds the guest state the target's ABI expects and
  runs the lifted trace.
* Compare: `python -m tools.linux64 difftest HLExtract.exe` reports 4 of 4 cases
  matched. The cases cover a constant return, arguments that must not change it,
  a memory-reading function whose result depends on a `cmp`/`sete` flag chain in
  both directions, and a guest memory dump that both executors must agree on.

Two functions were lifted and executed: `0x140006D80` (26 bytes, returns 1) and
`0x14000C5F0` (33 bytes, reads a pointer and compares the dword it finds against
`0xC0000005`). Both agree with the reference execution of the same bytes.

Details in `docs/linux64/LIFTING.md`.

## P3 — whole-program direct control flow — **done**

Acceptance, and the evidence:

* **Direct calls and jumps work.** Remill links a direct call as an LLVM call to
  `sub_<address>`, so the callee runs and the caller continues with no dispatch
  layer. Indirect calls and jumps go through `__remill_function_call` and
  `__remill_jump`, which run the target and return, or end the trace for a jump.
  A target with no lift stops the program and reports its address.
* **Closure lifting.** `lift --all --reachable` lifts the recovered functions,
  then every call target they reference, until the set stops growing. On
  HLExtract.exe: 262 recovered functions, 311 lifted, 0 failures, 10.8 seconds.
  All 49 extra addresses are outside every recovered range, so the lifter's
  decoder found functions that `.pdata` never listed.
* **The original data sections are addressable.** The `data_read.exe` fixture
  reads a `.rdata` constant, reads a `.data` global and writes it; four fixed
  cases pass, and a write case asserts the dumped memory equals what was written
  in both executors.
* **Deterministic function-level differential tests.** The sweep runs every
  recovered function on a fixed set of inputs and classifies each case. On
  HLExtract.exe: 2620 cases, 214 comparable, 100% of comparable cases agreed, 0
  mismatches, 2405 reference faults (synthetic inputs a function cannot use), 1
  timeout. Runtime 8.9 seconds.
* Whole-program start: running HLExtract.exe's entry point executes CRT startup
  code until the first import call, then reports `call to unlifted address
  0x1dc00` (a name RVA from an unpopulated IAT). That is the P4 handoff, and the
  report is the input list P4 needs.

The entry-state work belongs to this milestone because the sweep is only
meaningful with it: the reference now zeroes every general register and the flags
and uses the same guest stack at the same address as the harness, which is how a
function that never defines its return register (`0x1400055D0`, whose
zero-argument path is a bare `ret`) stopped looking like a mismatch.

Details in `docs/linux64/LIFTING.md`.

## P4 — imports through the Win32 layer — **blocked**

Target: `kernel32.exe` fixture.

* IAT slots resolve to Wine's exports through the winelib host module;
* callbacks return into lifted code (already proven possible by
  `tests/winelib/callback.c`);
* `Sleep`, `GetTickCount64`, console and file paths work;
* no shim is written for an import that exists in Wine.

Blocked on the host layer, not on imports. A winelib host can load Wine's DLLs and
call into native code, and lifted code has been observed returning correct results
inside a Wine process, but runs are not reproducible: the process dies in the
runtime's `setjmp`/`longjmp` stop path while the runtime's view of its own `Memory`
argument stops matching the caller's. Ruled out by measurement, with probes kept in
`scripts/check-winelib.sh`: Wine's view of guest memory (fixed, `wine_memory.c`),
the thread used for guest execution (pthread and Wine's `CreateThread` both fail),
Wine's asynchronous signals, `stdout` blocking, the stack size, and struct layout
mismatches. The native harness on the same objects is deterministic, so P2/P3
validation does not depend on this. Next executable step and full measurements:
`docs/agents/traces/wine-host-guest-execution.md`.

## P5 — window and input

Target: a lifted PE64 program that creates a window.

* USER32-style calls reach Wine's `user32.dll` from lifted code;
* message loop, keyboard and mouse paths work;
* window procedure callbacks land in lifted code.
* GUI checks cannot run headless; this milestone adds the first probe that needs
  a display (see the note in `WINE.md`).

## P6 — rendering

Target: a tiny D3D11 triangle fixture.

* default path: Wine's `d3d11.dll` + `dxgi.dll` (wined3d → Vulkan/OpenGL);
* alternative path: DXVK's DLLs as drop-in replacements via DLL overrides, or
  DXVK Native (`DXVK_WSI_DRIVER=SDL3`) if Wine's implementation proves
  inadequate for a target;
* acceptance: stable frames, no Wine guest execution, no reimplemented D3D.

## P7 — audio

Target: a tiny tone/buffer fixture.

* default path: Wine's `xaudio2_8.dll`;
* alternative: FAudio behind a thunk from the guest's XAudio2 calls to the
  `FAudio_*` API;
* acceptance: voice creation, buffer submission, and a callback into lifted code.

## P8 — C++/MSVC hard cases

Added as a real target demands them: `.pdata`/`.xdata` handler bodies,
adjustor thunks, TLS callbacks, SEH/C++ exception strategy, delay imports, COM
boundaries, indirect calls and function pointers.

Two pieces are already in the tree rather than pending:

* **x64 RTTI recovery.** `tools/cpp/rtti.py` handles the PE32+ layout, and the
  fork checks it against recon on `rtti_msvc.exe`: no recovered method may land
  in the interior of a recovered range. Verified on a large x64 binary as well,
  where 80.5% of vtable slots landed exactly on `.pdata` starts and none landed
  inside a known function.
* **`.pdata`/`.xdata` reading.** Recon records every `RUNTIME_FUNCTION` with
  decoded `UNWIND_INFO` (prolog size, code slots, frame register, handler VA,
  chain). Interpreting handler bodies is the remaining work.

Still open: ingesting RTTI starts into the spec (adds an `rtti` value to the
function `source` enum) and consuming them, e.g. through the Ghidra
`SeedFunctions.java` path that was built for exactly that on a large x64 target.

## P9 — first real game

Pick a legally usable, unprotected PE64 target with modest imports before MKX,
Injustice or DBFZ. Acceptance is incremental: process bootstrap → window →
renderer init → audio → first interactive frame.

## Scale: measured on Photoshop.exe

`docs/linux64/SCALE.md` records what the pipeline costs on the largest target so
far (198 MB, 325,924 functions): 61 s of reconversion with no problems, about 31 s
per function to lift, seconds to build a harness and run a lifted function, and a
differential match against the reference executor on the image entrypoint.

The number that shapes the plan is the lifting cost: 325,924 functions at 31 s each
is about 113 days of single-core work, so lifting is lazy and driven by what
execution reaches, not by what reconversion finds. That is why P4 (imports) and the
Wine host it depends on come first: without them a real function cannot get past
its first external call.

## Later optimization

Only after correctness: direct LLVM call lowering, removing unnecessary CPU-state
loads and stores, recovering selected signatures, `ms_abi` host functions where
they simplify a boundary, LTO/PGO, and native replacements for hot shims.
