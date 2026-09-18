# Linux64 runtime

Shared runtime for recompiled AMD64 Windows targets. Nothing here exists yet;
this is the intended decomposition (P2 onward in `docs/linux64/ROADMAP.md`).

```
image/       map/copy PE sections, keep guest virtual addresses, apply the one
             documented relocation policy if the preferred base is unavailable
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
