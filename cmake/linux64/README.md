# Build integration

Keep third-party checkouts under `.deps/src` and builds under `.deps/build` so the
fork stays clean. `.deps/` and `work/linux64/` are gitignored.

Toolchain split (this is the important part):

| Piece | Built with | Why |
|---|---|---|
| `tools/linux64/*` | python3, stdlib only | reconnaissance must run anywhere, with no build step |
| runtime host module | `winegcc` | it is the piece that imports Wine's DLLs |
| recompiled guest code | `clang`/`gcc` | native ELF, no Wine headers, no winelib |
| lifter tool + Remill | clang, CMake | Remill's LLVM version constraint is handled explicitly, not hidden in a script |

Linkage policy:

* Wine: link its import libraries (`-lkernel32`, `-luser32`, `-ld3d11`, …) from
  the host module. Do not vendor Wine; see `docs/linux64/WINE.md`.
* Remill: linked into the lifter tool, not into the final target runtime unless
  emitted IR needs its support library.
* DXVK: drop-in DLLs in the Wine environment, or DXVK Native as a rendering
  backend. Not linked into this tree.
* FAudio: optional dependency of a shim layer, never a hard requirement.
* Anvill / rev.ng / Rellic: executable tools discovered at run time; never
  vendored into the core build (`docs/linux64/LICENSES.md`).

`python -m tools.linux64 doctor` reports which of these are present before a
build is attempted, and `scripts/check-winelib.sh` proves the winelib half works
on the installed Wine.
