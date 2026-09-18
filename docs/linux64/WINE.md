# The Win32 layer: Wine's DLLs, no Wine execution

`linuxrecomp` does not reimplement kernel32, user32, gdi32, d3d11 or xaudio2, and
it does not run the guest program on Wine either. It takes Wine's Win32
implementations as libraries and keeps the recompiled program as our own native
code.

Run `./scripts/check-winelib.sh` to verify every claim on this page on the
current machine. It builds and runs five probes and prints one line per check.

## What is actually used

Three separate things come from the installed Wine:

| Piece | Where it is | What it gives us |
|---|---|---|
| `winegcc`, `winebuild` | `/usr/bin` | Link a native module against Wine's DLLs (winelib) |
| Import libraries | `/usr/lib/wine/x86_64-unix/libkernel32.a`, `libuser32.a`, `libd3d11.a`, `libd3dx9.a`, `libxaudio2_8.a`, … | Link-time surface for every DLL Wine ships |
| PE DLLs | `/usr/lib/wine/x86_64-windows/*.dll` (622 of them) | The implementations, loaded in-process |

Measured on 2026-09-18 with wine-11.15, all probes passing:

```
winelib code is native ELF (win32_api.exe.so)      -> ELF 64-bit LSB shared object, x86-64
native main symbol exported from the winelib module -> nm -D shows ' T main'
win32 API calls reach Wine (pid/tid)               -> win32 api: pid=... tid=... tick_ok=1
link native library into a winelib host            -> clang-built liblifted.so links in
dispatched call into native code returns 42        -> dispatched=42
Wine thread body ran native code three times       -> callback: hits=3 wait=0 exit=0x1234
```

## What "no Wine execution" means precisely

`winegcc` output is not what it looks like. For `probe.c` it writes two files:

* `probe.exe` — a 700-byte **POSIX shell script** that `exec`s `wine probe.exe.so`
* `probe.exe.so` — an **ELF 64-bit shared object** holding the actual code

`nm -D --defined-only probe.exe.so` lists `main` in section `.text` as a normal
ELF symbol. So the code we write is compiled by clang/gcc into native x86-64 ELF
and runs as native x86-64. Wine's loader maps it and Wine's DLLs provide the
Windows API. No instruction is emulated and no guest bytecode is interpreted.

What we never do:

* never map the guest PE image as a Wine module, and never call its entry point
  through Wine's loader;
* never hand the guest's instruction stream to Wine or to any other x86
  interpreter as the execution path;
* never expect Wine's loader to relocate or protect guest memory. Guest memory is
  ours to map (see `docs/linux64/ARCHITECTURE.md`), and Wine only ever sees the
  pointers we pass to it.

## The linkage model

```
   recompiled guest code            Win32 API layer
   ----------------------           ---------------
   plain clang/gcc                  winegcc (winelib)
   native ELF .so                   Win32 import libs + Wine PE DLLs
        |                                 |
        +------------- linked into -------+
                        |
                  runtime host module
```

* Guest code stays free of Wine. It is built by clang, emits `sub_<guest_va>`
  symbols, and reaches Win32 only through the import thunks the dispatcher
  generates. `tests/winelib/lifted.c` is the stand-in used to prove that shape
  links and runs.
* The runtime host module is built with `winegcc` because it is the piece that
  imports Wine's DLLs. One module crossing the boundary is enough; making every
  recompiled function a Wine module would couple all of it to the Wine toolchain
  for no benefit.
* Calls work in both directions. Guest → Win32 is an ordinary call through the
  import table. Win32 → guest (window procedures, thread bodies, timers, COM
  entry points, TLS callbacks) is a function pointer into native code, verified
  with `CreateThread`.

## Hosting guest code in a Wine process

Guest code is native ELF and its memory comes from the host, so the host layer
owns the two things Wine is opinionated about: where guest memory lives, and which
thread runs the guest. Both were measured on wine-11.15; `scripts/check-winelib.sh`
covers them.

**Guest memory must come from Wine's allocator.** A range obtained with a plain
`mmap` is not in Wine's view of the address space, so `VirtualQuery` reports it as
free and Wine can hand the same addresses to its own allocator afterwards.
`runtime/linux64/wine_memory.c` installs Wine's `VirtualAlloc`, `VirtualFree` and
`VirtualProtect` as the loader's memory backend for the winelib build, and
`tests/winelib/memory_visibility.c` checks the difference:

```
memory: mmap region state=65536        MEM_FREE   -- Wine believes it is free
memory: pe_reserve region state=4096   MEM_COMMIT -- Wine knows it is ours
memory: second reservation at the same base=(nil)
memory: PASS
```

**Guest code runs on a thread Wine created, with Wine's signals blocked.**
`runtime/linux64/host_guest.c` and `host_guest_wine.c` are the two hosts; the
winelib one calls `CreateThread` with the requested stack size, because Wine has to
own the stack it hands out. A `pthread` is not a safe home for guest code: Wine
does not know the thread, its process-wide handlers assume a Wine thread context,
and a signal delivered to it ends in `siglongjmp` from a corrupt frame. A
`CreateThread` thread is known to Wine, so `SIGQUIT` and `SIGUSR1` (how Wine
suspends and notifies threads) are blocked for its lifetime: Wine cannot unwind a
thread whose frames are not Windows frames.

**Lifted code now runs in a Wine process.** The obstacle was not Wine's memory or
Wine's threads: it was `setjmp`. The runtime stops a trace by jumping out of it, and
in a winelib build the link binds `setjmp` to Wine's PE-side `_setjmp` stub
(`nm` shows a local `_setjmp` at a fixed offset plus `__imp__setjmp`), which writes
a Windows-shaped jump buffer into what the runtime had sized as glibc's `jmp_buf`.
The symptom was a crash inside that stub, at whichever address the buffer happened
to live, which is why it looked like memory corruption and followed the block
around. The runtime now uses clang's built-in jump buffer, saved and restored
inline with a layout the compiler owns, and nothing outside the translation unit
can disagree about it.

Measured after the fix, same harness, same lifted functions:

```
fixture, native harness   result=0x1234abcd   5/5
fixture, winelib harness  result=0x1234abcd   10/10
HLExtract.exe 0x140001250 native  result=0x7f9e04bfedc1  stop call at 0x1d4ce
HLExtract.exe 0x140001250 winelib result=0x7ffffe8bedc1  stop call at 0x1d4ce
```

The two flavours agree on the stop and on the result, up to the stack addresses
that the harness's own documentation says are not comparable between executors.

While the defect was live, the thread choice was measured too, and both a `pthread`
and a Wine `CreateThread` failed the same way; the thread conclusions in
`runtime/linux64/host_guest.h` are weaker than they read, because the same defect
was behind both.

## Adding a Win32 API

1. Recon lists it (`program.json` → `imports`); pick the DLL that exports it.
2. Prefer Wine's implementation: add the import library (`-lkernel32`,
   `-luser32`, …) and dispatch the IAT slot to the real symbol.
3. Only when Wine's version is wrong for a target do you add a shim, and then it
   is a deliberate, documented deviation rather than a default.

`tools/linux64/doctor.py` reports the Wine pieces it can find, and
`runtime/linux64/README.md` lists where the host module's parts live.

## Constraints to keep in mind

* **Licensing.** Wine is LGPL-2.1-or-later. Dynamic linking (what winelib does
  here) is the safe boundary; see `docs/linux64/LICENSES.md`.
* **Version coupling.** Behaviour and the available DLL set change between Wine
  releases. `upstreams.lock.toml` records the verified version; re-run
  `scripts/check-winelib.sh` after a Wine upgrade before believing a failure is
  in our code. A Wine upgrade can also change `wine --version` output and DLL
  counts, so pin the version you validate against.
* **Wine prints noise.** Probes in this repo run with `WINEDEBUG=-all`; without
  it Wine's debug channels drown real output. GPU-less CI boxes also emit
  `libEGL warning:` lines from any GPU-touching path.
* **No GUI in the probe set yet.** The current probes avoid windows so they run
  headless. Window/input verification arrives with P5 in
  `docs/linux64/ROADMAP.md`.
* **Wine's DLLs are PE files.** Linking to them is not the same as linking a
  plain `.so`; anything that depends on Wine's own state (heap, TEB, SEH) only
  works inside the host module, which is exactly where such code belongs.
* **stdout can block.** In a winelib module the first write to stdout can block
  indefinitely while stderr keeps working, so the lifted harness reports on
  stderr (`runtime/linux64/lifted_harness.cpp`).
