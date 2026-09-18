# linuxrecomp Linux64 extension

Recompile Windows PE32+/AMD64 programs into native Linux executables, reusing
existing projects for the hard parts. This directory's overlay sits on top of the
pcrecomp fork; the 16/32-bit paths are untouched.

```
Windows PE32+ (AMD64)
        |
        v
recon (tools/linux64)                    P1, done
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
        |                        runtime/linux64 (image map, dispatch,
        |                        imports, CPU state, TLS, crash reports)
        |                                   |
        +--> Rellic (optional readable C)   v
        +--> rev.ng (optional 2nd opinion)  Win32 API: Wine's DLLs (winelib)
                                            GPU: Wine d3d11, or DXVK
                                            Audio: Wine xaudio2_8, or FAudio
```

## Design rules

1. Fork pcrecomp; keep its 16/32-bit paths intact.
2. Add PE64/AMD64 as a parallel pipeline, not a rewrite.
3. Reuse `tools/pe` for anything architecture-neutral, and use Ghidra headless
   for function discovery (`DumpBounds.java` → `recon --bounds`).
4. Use Remill for AMD64 semantics. Rellic is inspection only; Anvill and rev.ng
   stay external because of their licenses.
5. Take the Win32 API from Wine's DLLs through winelib. Do not reimplement
   kernel32/user32/d3d11/xaudio2, and do not run the guest through Wine either.
6. Start in explicit CPU-state mode: no C++ type recovery or native signatures
   are needed to get the first programs running.
7. Every milestone has a differential or round-trip check before the next,
   larger target.

## First commands

```bash
python -m tools.linux64 doctor                 # toolchain, Wine layer, upstreams
./scripts/build-win64-fixtures.sh              # PE64 test images
python -m tools.linux64 recon work/linux64/fixtures/return42.exe
python -m tools.linux64 selftest               # parser, spec, fixture, Wrapper and difftest checks
./scripts/check-winelib.sh                     # proves the Win32 layer strategy

# Lift and run code (P2)
python -m tools.linux64 lift TARGET.exe --function 0x140006D80
./scripts/build-lifted-harness.sh TARGET.exe
python -m tools.linux64 difftest TARGET.exe    # lifted vs the real CPU
```

Optional heavy analysis backends:

```bash
./scripts/bootstrap-linux64.sh --analysis
```

Details: `docs/linux64/RECON.md` (the spec), `docs/linux64/LIFTING.md` (lifting
and the differential tests), `docs/linux64/WINE.md` (the Win32 layer),
`docs/linux64/ROADMAP.md` (bring-up order and status).
