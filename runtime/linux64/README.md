# Linux64 runtime

Shared runtime for recompiled AMD64 Windows targets.

Two pieces exist today, both built by `scripts/build-runtime-linux64.sh` into
`work/linux64/bin`:

* `image_pe64.{c,h}` maps a PE32+ image at its preferred base with the sections
  protected according to their characteristics. The preferred base or nothing:
  relocating is a deliberate non-goal, because mixing raw guest addresses with
  rebased host addresses is what produces plausible-looking wrong behaviour. Base
  relocations are therefore irrelevant to this design; they exist to support
  rebasing, and we never rebase.
* `refexec.c` calls one function from a mapped image on the real CPU. The guest's
  `.text` is already x86-64, so a differential test needs no emulator: the CPU
  running the original bytes is the oracle. Arguments go in through the Microsoft
  x64 convention using `ms_abi`, and `--poke ADDR=HEXBYTES` and `--dump ADDR:LEN`
  set up and inspect guest memory.

```
./scripts/build-runtime-linux64.sh
work/linux64/bin/refexec IMAGE FUNCTION_VA [a b c d] [--poke ADDR=HEX] [--dump ADDR:LEN]
```

Planned modules (P3 onward in `docs/linux64/ROADMAP.md`):

```
cpu/         CPU state bootstrap (Remill State/Memory), stack setup
dispatch/    guest VA -> lifted function, generated from the backend symbol map
imports/     IAT slot resolution; thunks at the Win32 boundary
tls/         guest TLS block, index, and TLS callbacks
platform/    POSIX/SDL3 services the Win32 layer does not provide
crash/       guest PC + host backtrace reports
wine/        winelib host module: the only piece built with winegcc, because it
             imports Wine's DLLs (kernel32, user32, d3d11, xaudio2_8, ...)
```

## Rules

* Guest code must not include Wine headers and must not be built with `winegcc`.
  It is plain native ELF with `sub_<guest_va>` symbols; only `wine/` crosses the
  boundary. `tests/winelib/` proves that shape links and runs.
* Do not create a generic Win32 reimplementation. Add a shim only when a fixture
  or a real target proves Wine's implementation is wrong for it, and record why
  in the same commit.
* Preserve guest addresses instead of translating pointers aggressively; early
  correctness comes from the guest seeing the addresses it was linked for.
* Every module needs a way to be checked without a full program: the recon side
  has `python -m tools.linux64 selftest`, the Win32 side has
  `scripts/check-winelib.sh`. Keep that property as modules are added.
