# Lifting and running lifted code

Milestone P2. This page describes what a lifted function is, what the runtime
owes it, and how the differential tests use it.

## What a lifted function is

`python -m tools.linux64 lift IMAGE --function 0x140006D80` reads the function's
bytes out of the image, hands them to Remill, and writes under
`work/linux64/lift/<name>/`:

* `sub_<va>.ll`, LLVM IR for the trace
* `sub_<va>.manifest.json`, the inputs and tool identity, validated against
  `lift_manifest_schema.json`

The IR keeps Remill's explicit CPU-state shape:

```llvm
define ptr @sub_140006d80(ptr noalias %state, i64 %program_counter, ptr noalias %memory)
```

No types are recovered, no Microsoft ABI is reconstructed, and no assumption is
made about what the function means. A `call` inside the trace becomes a call to
`__remill_function_call` with the target address, which is where P3's dispatcher
plugs in.

## What the runtime owes it

Remill emits declarations for `__remill_*` and leaves the implementations to the
consumer. `runtime/linux64/lifted_runtime.cpp` is that consumer:

| symbol | what this runtime does |
|---|---|
| `__remill_read_memory_{8,16,32,64,f32,f64}` | read guest memory, halt when unmapped |
| `__remill_write_memory_{8,16,32,64,f32,f64}` | write guest memory, halt when unmapped |
| `__remill_function_return` | stop the trace, record the return address |
| `__remill_function_call` | stop the trace, record the call target (P3 dispatches it) |
| `__remill_jump` | stop the trace, record the jump target (out of the lifted bytes) |
| `__remill_error`, `__remill_missing_block` | stop the trace and report |
| `__remill_flag_computation_{carry,zero,sign,overflow}` | return the result operand; the arithmetic lives in the lifted code |
| `__remill_compare_{eq,neq,slt,sle,sgt,sge,ult,ule,ugt,uge}` | same |
| `__remill_undefined_{8,16,32,64,f32,f64}` | zero, reported when `--report-undefined` is set |
| `__remill_sync_hyper_call`, `__remill_async_hyper_call` | stop the trace and report the call |

Two decisions there are deliberate. Unmapped access halts instead of returning
zero, because a silent zero hides a missing memory model behind a wrong answer.
Control flow that leaves the lifted bytes halts and records its target instead of
guessing, because the dispatcher does not exist yet at P2 and guessing would
manufacture results.

## Memory model

Guest memory is:

* the image mapped at its preferred base (`runtime/linux64/image_pe64.c`), which
  is what lets code and data references resolve as the guest was linked for;
* a 1 MiB stack region the runtime owns at `0x200000`, with `RSP` set to
  `stack_top - 8` so the ABI's expectation of a return address at `[rsp]` holds
  and `push`/`sub rsp` stay inside the region.

Anything else is unmapped and halts with the address in the report. Heap, extra
mappings and TLS arrive when a target needs them.

## How calls and jumps work

Remill's model turns out to be simpler than a hand-written dispatcher, and
knowing which is which matters:

* **A direct call is an LLVM call.** The trace declares the target as
  `sub_<address>` and calls it, because Remill assumes the whole program will be
  linked. The callee's `ret` calls `__remill_function_return` and then returns
  from the LLVM function, so the caller's lifted code simply continues. There is
  no dispatch overhead and no bookkeeping to get wrong.
* **An indirect call or jump goes through the runtime.** `__remill_function_call`
  and `__remill_jump` run the target's lifted function and return, for a call, or
  end the current trace with the target's outcome, for a jump, since a jump does
  not come back.
* **A target with no lift stops the program** and reports the address. That is how
  an import announces itself before P4 implements it, and the report names the
  address so the list of imports a target needs can be read straight off a run.

That model means the useful work at this stage is not a dispatcher but **closure**:
a direct call to a function nobody lifted is an undefined symbol at link time.
`lift --all --reachable` therefore lifts the recovered functions, reads the
`sub_<address>` symbols the lifted code refers to, lifts those, and repeats until
the set stops growing. On HLExtract.exe that takes 262 recovered functions to 311
lifted, and all 49 extra addresses are **outside every recovered range**: they are
functions that `.pdata` never listed, found by the lifter's own decoder following
direct calls. The byte ranges for those come from the next known start (recorded
as `length_source: next-function`), so their *starts* are evidence and their
*ends* are a bound.

The build still generates a stub for any referenced address that has no lift, so a
link failure never hides a program that would have run; the stub stops the program
with the address instead.

## Entry state has to be identical for a comparison to mean anything

Both executors must hand the function the same world, or a difference in results
says nothing about the lift:

* the same image mapped at the same base, with the same pokes;
* the same guest stack, at the same address, with the entry RSP at 8 mod 16 as the
  Microsoft ABI expects (a misaligned entry makes an aligned SSE spill fault in
  the reference and quietly succeed in the lifted code);
* the same register state: arguments in RCX/RDX/R8/R9 and **everything else zero**,
  because the lifted harness starts from a zeroed `State`;
* the same flags, cleared.

The register rule was not there at first, and the sweep caught what it cost:
HLExtract's `0x1400055D0` has a zero-argument path that is a bare `ret`, so it
never defines RAX. The reference returned whatever the harness had left in RAX,
which was the function pointer; the lifted run returned 0. Both are "undefined",
so the only way to agree is to start from the same undefined state.

One value cannot match: the return-address slot holds a real host address in the
reference and a zero in the harness. A function that reads its own return address
would see that difference, and none of the ones tested do.

## Differential testing

```bash
python -m tools.linux64 difftest IMAGE                        # fixed cases
python -m tools.linux64 difftest IMAGE --sweep                 # every function
python -m tools.linux64 difftest IMAGE --sweep --limit 60      # a slice
```

Fixed cases state what they expect of the reference as well as comparing the two
runs, so a case that is set up wrong fails as a case and not as a lifter.

The sweep runs every recovered function against a deterministic set of inputs:
no arguments, zeros, small integers, seeded small values, and pointer arguments
into a scratch area in `.data` (zeroed, and once with every slot pointing back at
the scratch so a second-level dereference stays mapped). Results are classified
rather than flattened into one number:

| status | meaning |
|---|---|
| `matched` | both executors returned the same value, and any dumped memory agreed |
| `mismatch` | they disagreed, which is a lifter or runtime defect |
| `blocked` | the lifted run stopped at an import or an unlifted address, which is a known gap |
| `reference-fault` | the function faulted on synthetic inputs, so there is nothing to compare |
| `timeout` | it did not terminate on those inputs |

The honest summary is the comparison rate, not the raw total. On HLExtract.exe the
sweep reports 2620 cases over all 262 functions: 214 comparable, **100% of
comparable cases agreed**, 2405 reference faults and 1 timeout. The faults are the
limit of input synthesis without type information, not a verdict on the lift.

## Data sections

`data_read.exe` in `tests/fixtures/win64` exists because "data is addressable at
guest addresses" needs a test and not an argument. It exports a `.rdata` constant
reader, a `.data` global reader and a writer, and exports the global itself so the
test reads the address out of the image instead of hard-coding it. The four cases
check the constant value, the initial global, and that a write lands (the dumped
memory must equal what was written, in both executors).

## Running it

```bash
./scripts/build-lifted-harness.sh IMAGE       # generates a dispatch table, then links
work/linux64/bin/lifted_harness-IMAGE IMAGE FUNCTION_VA [a b c d] [--poke ADDR=HEX] [--dump ADDR:LEN]
```

One harness per image, named after it, because it links that image's lifted
functions by address: using a harness built for one binary against another would
be silently wrong. The build only takes manifests whose recorded image hash
matches, for the same reason.

The harness prints the same report format as the reference executor, so one parser
(`tools/linux64/refexec.py`) reads both:

```
lifted: image=... base=0x140000000 section=.text symbol=sub_140006d80 va=0x140006d80 args=0x0,... result=0x1 result_dec=1
lifted: stop returned at 0 (return to 0)
lifted: entered=1 deepest=1 missing=0
```

`--report-undefined` prints a line whenever the lifted code reads a value Remill
could not determine, which is how an incomplete lift announces itself instead of
quietly returning a plausible number.

## Known limits

* without type information most functions cannot be given inputs that satisfy
  them, so the sweep compares a fraction of what it runs. Recovering signatures,
  or reusing arguments seen at call sites, is what would change that;
* flags are zero at entry and the sweep never varies them, so a function that
  reads flags before writing them is compared from one state only;
* no x87 or 128-bit memory access (`__remill_read_memory_f80`, `f128`), no I/O
  ports, and floating point exceptions are not modelled: the FPU rounding mode is
  recorded and reported back, and nothing is ever raised;
* atomics are modelled as single-threaded compare-exchange and no-op fences, so a
  target with real guest threads needs work here;
* imports resolve to nothing yet, which is P4; until then a program stops at its
  first import call and reports the address;
* the stack region is fixed at 1 MiB at 0x200000 and the heap does not exist;
* lifts are per image hash: lift again after changing the target.
