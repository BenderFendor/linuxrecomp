# Tests and probes

Two kinds of checkable thing live here, both runnable without a full target.

`fixtures/win64/` — PE32+/AMD64 programs cross-compiled by
`scripts/build-win64-fixtures.sh` with `x86_64-w64-mingw32-gcc` into
`work/linux64/fixtures/`. They are inputs to reconnaissance and, from P2 onward,
to the lifter. `return42.exe` has one exported function and a known return
value; `kernel32.exe` imports `GetTickCount64`/`Sleep`.

`winelib/` — the probes that prove the Win32 API strategy: winegcc-built code is
native ELF, Win32 calls reach Wine's DLLs, a plain native ELF library stands in
for lifted guest code in the same process, and Wine can call back into native
code. Built and run by `scripts/check-winelib.sh`.

Fixture binaries are build outputs, not repository contents: `.gitignore` keeps
`*.exe` out of the tree, and original binaries are never committed.

Run everything:

```bash
./scripts/build-win64-fixtures.sh
python -m tools.linux64 selftest
./scripts/check-winelib.sh
```

The parser checks in `../tools/linux64/test_pe64.py` also build a synthetic PE32+
image in memory, so `python -m tools.linux64 selftest` is meaningful even before
any fixture is compiled. Fixture-dependent assertions report SKIP when the
fixtures are absent rather than passing quietly.
