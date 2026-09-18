# linux64 architecture

Add a PE32+/AMD64 → native Linux path to this toolchain while reusing mature
projects for the hard parts. Two rules shape everything below:

1. **Wine is a library here, not an emulator.** The Windows API comes from
   Wine's own DLLs, linked through winelib; the guest program is recompiled to
   native code and never executed by Wine's loader. See `WINE.md`.
2. **One project-owned spec.** Reconnaissance emits `program.json`
   (`RECON.md`), and every backend consumes that, so a backend can be replaced
   without redesigning the pipeline and a reconnaissance fix cannot break a
   backend's expectations.

## Component map

```
tools/linux64/          reconnaissance and spec (P1, done)
  pe64.py               PE32+ reader: headers, sections, imports, exports,
                        relocations, TLS, .pdata + UNWIND_INFO
  functions.py          function ranges: .pdata, external bounds, exports
  spec.py               builds and validates the program document
  schema_check.py       JSON Schema subset validator (enforces the contract)
  spec_schema.json      the contract itself
  recon.py              CLI: image -> work/linux64/program.json
  doctor.py             toolchain / Wine layer / pinned upstream checks
  test_pe64.py          synthetic image + fixture checks
  backends/             backend contract (Remill, optional external tools)
runtime/linux64/        runtime for recompiled targets (P2+)
tests/fixtures/win64/   PE64 fixtures cross-compiled by scripts/
tests/winelib/          probes proving the Win32 layer strategy
scripts/                bootstrap, fixture build, winelib check
```

## Pipeline

```
Windows PE32+ / AMD64
        |
        v
  recon (tools/linux64)          P1  -- done
        |
        v
  linuxrecomp-spec-v1 program.json
        |
        v
  Remill-based whole-program lifter        P2/P3
        |
        v
  LLVM bitcode  -->  LLVM codegen  -->  native ELF
        |                                   |
        |                                   v
        |                            runtime/linux64
        |                            image map, dispatch, imports,
        |                            CPU state, TLS, crash reports
        |                                   |
        +--> Rellic (readable C, optional)   |
        +--> rev.ng (second opinion, optional)
                                             v
                                   Win32 API: Wine DLLs (winelib)
                                   GPU: Wine d3d11/wined3d, or DXVK
                                   Audio: Wine xaudio2_8, or FAudio
```

## The guest interface

Early correctness beats early beauty. The first lifted functions have the
explicit-state shape Remill already produces:

```c
Memory *sub_140123450(State *cpu, uint64_t pc, Memory *memory);
```

A guest `CALL 0x140123450` becomes a dispatcher lookup on the guest VA. That is
uglier than a native C++ signature and much easier to be correct about: it needs
no type recovery, no MSVC C++ ABI reconstruction, no exception model, and no
guesses about indirect calls. Direct-call lowering, register promotion, and ABI
recovery are optimizations taken later, once something boots
(`ROADMAP.md` → "Later optimization").

## Runtime responsibilities

* map the PE image and initialise data at the original guest VAs;
* apply base relocations if the preferred base cannot be reserved — one explicit
  policy, never a silent mix of raw and rebased addresses;
* bootstrap CPU state, stack and TLS, including TLS callbacks;
* dispatch guest VA → lifted function;
* resolve IAT slots to Wine's exports (or to a shim, when a shim is justified);
* keep callbacks from the Win32 layer back into lifted code working;
* report a crash with both the guest PC and a host backtrace.

## ABI

Phase 1 needs no recovered native signatures. Internal guest calls stay in CPU
state. At the Win32 boundary, generated thunks carry the Microsoft x64 calling
convention; clang's `ms_abi` attribute makes a boundary function callable from
both sides when that is simpler than a hand-written thunk. This is an
interoperability tool, not a correctness dependency.

## Validation layers

1. Instruction-level: Remill's own differential tests.
2. Function-level: lifted function vs. a reference execution for leaf functions.
3. Whole-program: guest PC traces, import call sequences, memory checkpoints,
   and rendered/audio smoke tests.
4. Environment-level: `scripts/check-winelib.sh` (Win32 layer) and
   `python -m tools.linux64 selftest` (recon), both re-runnable at any time.

## Non-goals

* reimplementing kernel32, user32, d3d11, xaudio2, or the CRT;
* compiling decompiled C back into the program as the execution path;
* linking AGPL (Anvill) or GPL (rev.ng) code into this MIT tree — they stay
  process-separated;
* committing lifted code derived from proprietary binaries.
