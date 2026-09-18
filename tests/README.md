# Tests and probes

Two kinds of checkable thing live here, both runnable without a full target.

`fixtures/win64/` — PE32+/AMD64 programs cross-compiled by
`scripts/build-win64-fixtures.sh` into `work/linux64/fixtures/`. They are inputs
to reconnaissance and, from P2 onward, to the lifter. `return42.exe` has one
exported function and a known return value; `kernel32.exe` imports
`GetTickCount64`/`Sleep`; `data_read.exe` reads a `.rdata` constant, reads and
writes a `.data` global, and exports that global so a test can find its address
in the image rather than hard-coding one; `rtti_msvc.exe` carries MSVC-ABI x64
RTTI records and is built with `clang --target=x86_64-pc-windows-msvc` plus
`lld-link` rather than MinGW, because GCC emits Itanium RTTI and would not
exercise the parser that `tools/cpp/rtti.py` runs.

`winelib/` — the probes that prove the Win32 API strategy: winegcc-built code is
native ELF, Win32 calls reach Wine's DLLs, a plain native ELF library stands in
for lifted guest code in the same process, Wine can call back into native code,
guest memory is memory Wine knows about (`memory_visibility.c` checks that a plain
`mmap` region shows up as `MEM_FREE` while the loader's `pe_reserve` shows up as
`MEM_COMMIT`), and the ordering rules of a winelib module hold
(`startup_order.c`: Win32 calls work from an ELF constructor, Unix stdio still
works after them). Built and run by `scripts/check-winelib.sh`.

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
