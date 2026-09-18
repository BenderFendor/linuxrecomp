# Wine host: running lifted guest code inside a Wine process

Slug: `wine-host-guest-execution`. Risk tier: high (runtime host boundary).
Status: **blocked, documented**; native path unaffected and verified.

## Goal / done criteria

Make the winelib host run a lifted function reproducibly, so P4 (imports through
the Win32 layer) can be built on it. Done means: the winelib harness reports the
same result as the native harness for the same image and VA, run after run, and
`scripts/check-winelib.sh` covers the host rules that make it work.

Not done: the winelib harness still dies during guest execution, measured 10/10
identical failures at the last checkpoint, and after each partial fix the failure
moved rather than disappeared. The native harness on the same objects, same lifted
code and same image is 5/5, and the fixture differential suite is 4/4 + 4/4.

## What was verified along the way (keep these)

| Fact | Evidence |
|---|---|
| Wine reports a plain `mmap` region as `MEM_FREE` and will hand the same addresses out again | `tests/winelib/memory_visibility.c`: `mmap region state=65536`, then `second reservation at the same base=(nil)` after `pe_reserve` |
| Guest memory through `VirtualAlloc` is Wine-tracked | same probe: `pe_reserve region state=4096` (`MEM_COMMIT`) |
| Win32 calls work from an ELF constructor; `VirtualAlloc` works at a fixed base from `main` | `tests/winelib/startup_order.c`, asserted by `scripts/check-winelib.sh` |
| Unix `stderr` and `stdout` both keep working after Win32 calls in a module's `main` | same probe, `main: stderr write worked`, `main: stdout write worked` |
| The first `stdout` write in the *harness* blocks while `stderr` gets through | harness hung with a completed run until the report moved to stderr |
| Remill's prologue needs a big stack: a winelib `main` runs on a 1 MiB PE stack with ~400 bytes left at that point | `report_stack_region` output: `1040384 bytes, 1039984 bytes below the frame` |
| Wine never remaps the block the runtime reserves | `WINEDEBUG=+virtual`: one `NtAllocateVirtualMemory` for `0x600000000000`, `dump_view ... (valloc)`, no free |

## The failure, as far as it is pinned down

Inside the guest dispatch the process dies with `SIGSEGV at addr=0` whose RIP is
libc's `__longjmp` (`libc+0x3e453`) and whose RSP is non-canonical, e.g.
`rsp=0xd98fafef87bb925d`. Progress markers place the death after the marker that
precedes `lifted_run_dispatched` and before the one after it, i.e. inside guest
execution.

Instrumentation that isolates it:

* `halt()` logs `reason=error`, `read of unmapped guest address 0x2feff8`
  (the guest stack top the harness had just mapped and handed over).
* The runtime's view of its own `Memory` argument at that moment
  (`image=0x140001580 stack=0x7f... base=0x7f... size=0x7f...`) does not match the
  harness's view of the same object address one step earlier
  (`image=0x7ffffe20f678 stack=0x200000 base=0x200000 size=0x100000`).
* `sizeof(Memory)=32` and offsets `0,8,16,24` from both translation units, so the
  layouts agree.
* A watchdog thread polling the object's first word never sees it change, which
  contradicts the runtime's dump at the same address.

The contradiction between the last two points is the thread to pull: the runtime
is not reading the object at the address its own log prints. That points at the
boundary between the lifted objects (compiled from IR carrying the *windows*
triple, `-Wno-override-module`) and the runtime, not at Wine's memory handling,
which is why the remaining work is a calling-convention/layout audit rather than
another Wine probe.

## Ruled out, with how

| Hypothesis | How it was ruled out |
|---|---|
| Guest stack too small | 64 MiB thread stack, ~4.7 KB used at dispatch |
| Wine's thread suspension signals | Blocked `SIGQUIT`/`SIGUSR1`/`SIGUSR2` for the thread's life; failure unchanged |
| A `pthread` is unsafe because Wine does not know it | Replaced with Wine `CreateThread`; failure changed shape (`siglongjmp` -> `__longjmp` with garbage RSP) but persisted |
| Raw `mmap` guest memory clobbered by Wine | Fixed with the `VirtualAlloc` backend; failure persisted |
| The `Memory` object overwritten by Wine | `+virtual` shows no remap; watchdog sees no change |
| Struct layout mismatch between translation units | Same size and offsets from both |
| Our own `setjmp`/`longjmp` buffer corrupt | Logged `saved_rip`/`saved_rsp` are sane at `halt()` |
| Main-thread PE stack too small for the state objects | `sizeof(State)=3504`, `sizeof(Memory)=32`; moved off the stack anyway |
| Wine's SEH machinery needs an altstack to report our faults | Added `SA_ONSTACK` + `sigaltstack`; that only made the fault *reportable*, it did not remove it |

## Files changed

* `runtime/linux64/image_pe64.{c,h}` - memory backend indirection (`pe_memory_ops`,
  `pe_set_memory_ops`, `pe_reserve`, `pe_release`, `pe_protect`).
* `runtime/linux64/wine_memory.c` - Wine's allocator as the backend for winelib.
* `runtime/linux64/host_guest.{c,h}`, `host_guest_wine.c` - host-owned guest
  execution thread; Wine-owned thread with Wine's signals blocked.
* `runtime/linux64/lifted_harness.cpp` - guest state from the host allocator,
  report on stderr, threads through the host layer.
* `scripts/build-lifted-harness.sh` - builds both flavours; winelib links through
  `wineg++`.
* `scripts/check-winelib.sh`, `tests/winelib/memory_visibility.c`,
  `tests/winelib/startup_order.c` - the host rules above, checked.
* `docs/linux64/WINE.md`, `docs/linux64/ARCHITECTURE.md`, `docs/linux64/ROADMAP.md`,
  `runtime/linux64/README.md`, `tests/README.md`.

## Commands and verification

```bash
python -m tools.linux64 selftest                 # 4/4 + 4/4 differential cases
./scripts/check-winelib.sh                       # 24 checks, all ok
./scripts/build-lifted-harness.sh work/linux64/fixtures/data_read.exe
work/linux64/bin/lifted_harness-data_read.exe work/linux64/fixtures/data_read.exe 0x140001580
# -> result=0x1234abcd result_dec=305441741, exit 0    (5/5 runs)
```

Real binary, same harness:

```bash
./scripts/build-lifted-harness.sh /home/bender/projects/filestorecomp/HLExtract/HLExtract.exe
work/linux64/bin/lifted_harness-HLExtract.exe .../HLExtract.exe 0x140001250
# -> result=0x2fedc1, stop call
```

The winelib flavour of the same harness fails, which is the blocker:

```bash
WINEDEBUG=-all work/linux64/bin/lifted_harness-data_read.winelib \
  work/linux64/fixtures/data_read.exe 0x140001580
# -> exit 139
```

## Next executable step

Audit the boundary between the lifted IR and the runtime. Concretely: dump the IR
declarations of the `__remill_*` functions the fixture calls
(`rg "declare.*__remill" work/linux64/lift/*/*/*.ll`), compare their parameter
lists and calling conventions against `lifted_runtime.cpp`, and write a two-line
probe that receives `(State *, uint64_t, Memory *)` from lifted code and prints the
three pointers from inside the callee. If the callee sees a different third
argument than the caller passed, the remaining work is an ABI fix in the runtime,
not a Wine investigation. If the arguments are identical, the next measurement is
a hardware watchpoint on the `Memory` object's first word using a debugger that
works on this host (the system `gdb` is broken here: `libboost_regex.so.1.91.0`
is missing).

## Rollback

The native path is unchanged in behaviour: `host_guest.c` (pthread) and the
default `mmap` backend are what the native harness uses, and `check-winelib.sh`
verifies the Wine-side rules independently. Removing the winelib harness build
step from `scripts/build-lifted-harness.sh` leaves P0-P3 exactly as they were.
