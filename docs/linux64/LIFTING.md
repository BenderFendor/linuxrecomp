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

## Running it

```bash
./scripts/build-lifted-harness.sh IMAGE       # generates a dispatch table, then links
work/linux64/bin/lifted_harness IMAGE FUNCTION_VA [a b c d] [--poke ADDR=HEX] [--dump ADDR:LEN]
```

The harness builds a dispatch table from the lift manifests, and only from
manifests whose recorded image hash matches the image it is built for. Mixing
functions lifted from two different builds of a binary would be a correctness
hole that nothing else would catch.

The harness prints the same report format as the reference executor, so one
parser (`tools/linux64/refexec.py`) reads both:

```
lifted: image=... base=0x140000000 section=.text symbol=sub_140006d80 va=0x140006d80 args=0x0,... result=0x1 result_dec=1
lifted: stop returned at 0 (return to 0)
```

`--report-undefined` prints a line whenever the lifted code reads a value Remill
could not determine, which is how an incomplete lift announces itself instead of
quietly returning a plausible number.

## Differential testing

```bash
python -m tools.linux64 difftest IMAGE
python -m tools.linux64 difftest IMAGE --case compares-pointed-dword-match
```

Each case runs the same function twice: as original bytes on the real CPU
(`refexec`) and as lifted code (`lifted_harness`). Cases are fixed rather than
random so a failure is reproducible.

Compared: the return value, requested guest memory, and that the lifted trace
stopped by returning rather than hitting an unmodelled boundary. A case may state
an expected reference result, which catches a case that was set up wrong rather
than a lifter that is wrong: that check is what caught a bad pointer in the P2
case list.

Not compared: stack contents. The reference runs the guest function on the host
stack, the lifted harness gives it a guest stack, so stack addresses differ by
construction. Image memory is comparable and is what the cases read.

## Known limits at P2

* one function at a time: calls, cross-function jumps and returns into other
  functions stop the trace and wait for P3's dispatcher;
* flags are zero at entry, so a function that reads flags before setting them is
  not covered yet;
* no x87 or 128-bit memory access (`__remill_read_memory_f80`, `f128`), no
  atomics, no I/O ports, no hyper calls beyond halting;
* lifts are per image hash: lift again after changing the target.
