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

## Follow-up: the writer, identified

The IR/runtime boundary turned out to be clean, so the next instrument was a guard:
give the `Memory` descriptor its own page and mark it read-only after setup, which
turns any writer into a reportable fault. Results:

* native, guarded: still passes (`result=0x1234abcd`), so nothing writes the
  descriptor in a plain process;
* winelib, guarded: faults with `address=<descriptor page>`, every run.

The faulting instruction is the answer. Bytes around the RIP:

```
e8 23 f7 ff ff      call rel32
48 89 c1            mov %rax,%rcx
e8 bb 59 02 00      call rel32          <- #rcx is the descriptor page
0f 1f 00
48 89 11            mov %rdx,(%rcx)
48 89 59 08         mov %rbx,0x8(%rcx)
48 8d 44 24 08      lea 0x8(%rsp),%rax
48 89 41 10         mov %rax,0x10(%rcx)
48 89 69 18         mov %rbp,0x18(%rcx)
```

That is a `setjmp`/context-save routine: it stores registers and the caller's RSP
into `*rcx`. The caller obtained `rcx` from the return value of the call two
instructions earlier. So some Wine code allocates (or computes) a context slot and
captures into it, and that slot is the block the runtime reserved, at whichever
address it was placed: `0x100000`, `0x300000000000`, and a host-chosen
`0x7ffffe8c0000` all fault with the same writer RIP. Letting Wine pick the address
(`VirtualAlloc(NULL, ...)`) did not change it, so the pointer is not coming from
Wine's allocator handing out a range the runtime took.

The writer lives in a file-backed executable mapping with no pathname in
`/proc/self/maps` (device `00:1c`, unlinked), i.e. a Wine PE-side DLL. Guarding the
page then makes Wine's own `/usr/lib/wine/x86_64-unix/ntdll.so` fault at
`mov 0x8(%rax),%ebx` with `rax=0`, which is Wine's exception path running without
the state it expects, not a fault in our code.

## Measurements that narrow it further

* **The allocator is not the cause.** Backing the runtime's blocks with Wine's
  process heap (`HeapAlloc`) instead of `VirtualAlloc` produces the same writer
  RIP at the same kind of address. That experiment was reverted; the backend stays
  on `VirtualAlloc`.
* **The address is not the cause.** `0x100000` (fixed), `0x300000000000` (fixed
  high) and a host-chosen address from `VirtualAlloc(NULL, ...)` all fault with
  the same writer RIP.
* **The guard has to be page-aligned to be trusted.** With a heap-allocated,
  unaligned block the guard covered a second page and our own
  `memset(&state, 0, sizeof(state))` tripped it. The harness now aligns the
  descriptor's page and puts `State` on the next one, and the native run passes
  even guarded (5/5).
* **At the fault, RSP is on a different stack** (the guest thread's), and the
  return address at RSP is in a `0x7f...` (Unix/ELF) module, while the writing
  callee is in a `0x6fffff...` Wine PE DLL. So a Unix-side module called a
  PE-side context save with the runtime's block as the destination.

## Next executable step

Log `&context.jump` from `trace_once` next to the descriptor's address in the same
run. If they are equal, the `StopContext` of our own stop path is the buffer being
written, which points at a stack/target mix-up in how the guest thread enters
`lifted_run_dispatched`. If they differ, resolve the caller return address at RSP
(the crash handler already resolves the faulting RIP against `/proc/self/maps`, so
reuse that path) and name the Wine function that supplied the pointer.

`LINUXRECOMP_GUARD_MEMORY=1` turns on the descriptor guard, and the crash handler
prints the faulting RIP with its mapping, the bytes around the instruction, and the
top of the stack.

## Rollback

The native path is unchanged in behaviour: `host_guest.c` (pthread) and the
default `mmap` backend are what the native harness uses, and `check-winelib.sh`
verifies the Wine-side rules independently. Removing the winelib harness build
step from `scripts/build-lifted-harness.sh` leaves P0-P3 exactly as they were.
