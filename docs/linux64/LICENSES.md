# License boundary notes

Engineering boundaries, not legal advice. When a boundary changes, change it
here in the same commit.

The tree is MIT (`LICENSE`, inherited from the pcrecomp fork). Keep it that way
where practical.

| Component | License | How it is used here | Boundary |
|---|---|---|---|
| pcrecomp | MIT | fork base | Core tree |
| Wine | LGPL-2.1-or-later | Win32 API DLLs, linked through winelib | Dynamically linked, not vendored; see below |
| Remill | Apache-2.0 | linked into the lifter tool | Notices required |
| Rellic | Apache-2.0 | optional executable | process-separated |
| DXVK / DXVK Native | zlib | drop-in DLLs or native rendering backend | notices retained |
| FAudio | zlib | optional XAudio2 implementation | notices retained |
| Anvill | AGPL-3.0 | optional external backend | never linked into the MIT core |
| rev.ng | GPL-2.0 (whole) | external comparison backend | separate process |

## Wine specifically

Wine is the first dependency in this tree that is not permissive, so the boundary
is stated explicitly:

* the runtime **links** Wine's libraries and DLLs; nothing from Wine is copied
  into this repository, and Wine is not a submodule;
* linking is dynamic (winelib import libraries resolving to Wine's modules at
  run time), which is the case LGPL expects. Static linking of Wine code would
  additionally require shipping what LGPL-2.1 §6 asks for — object files or a
  mechanism for the user to relink — so do not do it casually;
* code that is ours stays ours: `tools/linux64/*` and the lifted guest code
  contain no Wine source and do not include Wine headers, which is why guest code
  is built by clang and only the host module is built by `winegcc`;
* if the project ever needs to ship a single statically linked binary, that
  decision changes the project's licensing obligations and must be taken
  deliberately, not as a build tweak.

## Generated code

Lifted code derived from a proprietary binary is a derivative work of that
binary. Do not commit it, and do not commit game assets — the same rule the
upstream projects follow. `tools/audit_repo.py` checks for generated output in
the tree; `work/linux64/` and `.deps/` are gitignored for this reason.

Third-party checkouts under `.deps/` are build inputs and keep their own license
files.
