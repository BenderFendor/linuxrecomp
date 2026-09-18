# Wine host: running lifted guest code inside a Wine process

Slug: `wine-host-guest-execution`. Risk tier: high (runtime host boundary).
Status: **resolved**. Root cause: `setjmp` in a winelib build binds to Wine's
PE-side `_setjmp` stub, whose jump-buffer layout is not glibc's. The runtime now uses
clang's built-in jump buffer. Winelib and native harnesses agree on the fixture and
on HLExtract functions.

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

## Resolution

Logging `&context.jump` from `trace_once` next to the fault was the measurement that
ended it:

```
trace: memory descriptor guarded read-only at 0x7ffffe8c0000
context: jump=0x7f74253bfce0 size=200
lifted: fault 11 at rip=0x6fffffbb0f78 address=0 rsp=0x7f74253bfcd8
```

`rsp` sits 8 bytes below `&context.jump`: the faulting code is the callee of our own
`setjmp` call, and that callee is a Wine PE DLL, not glibc. The link says the rest:

```
nm --defined-only lifted_harness-*.winelib.so | grep jmp
  000000000003a378 d __imp__setjmp
  0000000000016448 t _setjmp
objdump -d ... | grep -B2 "call.*setjmp"
  179b6:  call   16448 <_setjmp>
```

So the winelib link resolved `setjmp` to Wine's PE-side `_setjmp` stub, which stores
a Windows-shaped jump buffer through `%rcx`, while this file had sized the buffer as
glibc's `jmp_buf` (200 bytes). Every previous symptom follows from that: the writer
is a store into the buffer at whatever address the buffer has, which is why it moved
with the block, why the address did not matter, why the allocator did not matter, and
why the reference to a "context save" fit the instruction bytes so exactly.

Fix: `StopContext` holds clang's built-in jump buffer, and `trace_once`/`halt` use
`__builtin_setjmp`/`__builtin_longjmp`. The compiler emits the save and the restore
inline, with a layout it owns, so no host can substitute a different implementation.

Verified after the fix:

```
fixture  native   5/5    result=0x1234abcd
fixture  winelib 10/10   result=0x1234abcd
HLExtract.exe 0x140001250  native  result=0x7f9e04bfedc1  stop call at 0x1d4ce
HLExtract.exe 0x140001250  winelib result=0x7ffffe8bedc1  stop call at 0x1d4ce
HLExtract.exe 0x140001000  both stop call at 0x1d436
python -m tools.linux64 selftest   4/4 + 4/4
scripts/check-winelib.sh           24 checks ok
```

The two flavours agree on stops and on results, differing only in stack addresses,
which the harness documentation already excludes from comparisons.

## Instruments kept

`LINUXRECOMP_GUARD_MEMORY=1` marks the memory descriptor read-only, which turns any
writer into a fault with a location. The crash handler prints the faulting RIP with
its mapping, the bytes around the instruction, and the top of the stack, and that is
what identified the stub.

## Rollback

The native path is unchanged in behaviour: `host_guest.c` (pthread) and the
default `mmap` backend are what the native harness uses, and `check-winelib.sh`
verifies the Wine-side rules independently. Removing the winelib harness build
step from `scripts/build-lifted-harness.sh` leaves P0-P3 exactly as they were.


## Follow-up: the end-to-end run's frame accounting

HLExtract's program run (entry 0x140005310) now maps the image, binds 130 imports, makes
96 Wine calls, and enters 71 lifted functions, then ends with a top-level return. What it
does not do is reach `main`: the real program prints its banner and usage and exits 2.

Three runtime defects were found on the way, all in frame handling, and all fixed:

1. `call_import` did not record the return address the import's own `ret` would use, so a
   tail jump into an import propagated whatever `g_stop_pc` held.
2. A consumed return (a callee returning into its caller's lifted code) left its address
   in `g_stop_pc`, where a later frame could report it as its own.
3. A tail jump into an import popped the caller's return address, and then the caller
   popped it again. Only a call pushes, so only a call should pop.

Direct calls between lifted functions were also invisible: Remill links them by symbol, so
they never reach the dispatcher. The build now renames each lifted definition and emits a
wrapper under the original name, which is what turned a count of 3 functions into 71, and
what let the stop state and the guest stack be checked per direct call.

The measurement that matters now: the harness reports the guest stack pointer at entry
and when the run finishes, and `trace_once` reports any function that returns with a
stack other than its entry plus 8.

```
trace: stack: entry rsp 0x7ffffe8deff8 final rsp 0x7ffffe8def38 delta -192
dispatch: stack leak: sub_140005070 at 0x140005070 entry rsp 0x7ffffe8deff8 final rsp 0x7ffffe8def38 delta -192
```

The program's own run ends 192 bytes (24 slots) below where it started, and the startup
is where it is first visible, because everything under it is a direct call inside its
trace. Correct guest code cannot do that, so 24 pops are missing in the emulation. The
places the runtime touches the guest's RSP are `call_import` (one pop, for a call) and the
lifted code's own push/pop at call and ret; the next step is to log the guest RSP at every
import call and every ret together with the instruction that caused it, and find the 24
transitions where the stack moves without a matching restore.


## Follow-up: where the program's startup stops

The banner HLExtract prints is referenced by code at `0x14000111c`, inside
`sub_140001000` (range `0x1000..0x15fe`). That function is not among the 25 distinct
functions the run enters, so **`main` never ran**: the program's own startup returns
before reaching it.

The last imports the run makes are `GetProcAddress` twice, `EnterCriticalSection` and a
tail jump, then the top-level return. `GetStartupInfoA` and `GetCommandLineA` are never
called, and neither is anything from an initialiser table, so the divergence is inside
the CRT's startup between `__scrt_initialize_crt` (which does call `FlsAlloc`,
`EnterCriticalSection` and `HeapCreate`, all present in the trace) and `_initterm`.

Two measurements point at the same thing: the guest stack ends 184 bytes below where it
started, and the shadow stack reports returns whose stack pointer is one slot above the
frame on top. A startup that walks a table (initialisers, load-config entries, or its own
SEH frames) and gets a frame or a table bound wrong would both return early and leave the
stack short.

Next: instrument `_initterm`'s table walk - the guest addresses it reads and the entries
it calls - rather than the frames, since that is now where the run stops rather than where
it breaks.


## The startup's shape, and why it returns early

`sub_140005070` (672 bytes, the function that runs after the 18-byte entry stub) is MSVC's
common startup. Disassembling it shows what it actually does:

```
140005083: call QWORD PTR [rip+0x1414f]   ; 0x1400191d8
140005094: call QWORD PTR [rip+0x14136]   ; 0x1400191d0
1400050a0: jne  0x1400050ce                ; branch on the result
1400050ab: call 0x14000b240                ; failure path:
1400050b5: call 0x14000b000                ;   report, clean up,
1400050bf: call 0x1400085c0                ;   and leave
1400050c9: jmp  0x1400052d6
```

Two things follow. The startup checks the result of nearly every import it makes and jumps
to a three-call failure path ending in a jump to the function's exit; and the same shape
repeats for each of the IAT slots it uses (0x1400191c0, 0x1400191c8, 0x1400191d0,
0x1400191d8). An import that returns something the check rejects therefore ends the whole
run before `main`, which is exactly what is observed.

Corroborating evidence from the initialiser tables: scanning `.rdata` for runs of code
pointers finds two, at rva 0x19438 (4 entries) and 0x1a360 (3 entries). Only one entry,
0x140003ee0, is ever called in the run; the other five are never reached, and `_initterm`
itself is not among the 25 functions entered. So the startup diverts before the
initialisers run.

Next: resolve the four IAT slots above to import names and compare each returned value
against what the startup's check expects. That is the concrete, bounded question now.
