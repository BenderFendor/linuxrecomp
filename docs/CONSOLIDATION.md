# pcrecomp and xboxrecomp should share a spine

Written after the Trespasser audit found a defect in `disasm32.py` that
`xboxrecomp` had already solved. The first half is the assessment; the
[port queue](#the-port-queue) at the bottom is the plan of record.

The original Xbox is x86-32 with an NV2A bolted on. Strip the XBE loader, the
kernel shims and the GPU, and what is left is a static recompiler for the same
instruction set, the same compiler (MSVC), the same calling conventions and the
same C++ ABI as every binary in this repo. Two toolboxes solving one problem,
and only one of them has been scoring itself.

## How this came up

The trespasser project (private) scored
`disasm32.py` against a linker map — real ground truth — and found it missing
7,331 functions that IDA found. The cause was that `find_call_targets` seeded
only `call rel32` (E8) and never `jmp rel32` (E9), so any method reached only
by a tail call stayed invisible.

`xboxrecomp/tools/disasm/xrefs.py` already seeds calls, `jmp rel32`, conditional
jumps, memory references *and* address-taken immediates. It had been right about
this the whole time.

Worse, while fixing it I nearly widened pcrecomp's
`abs(target - start_va) < 0x100000` guard, which would have been a bug — that
guard distinguishes internal control flow from a tail call, and widening it
merges tail-called functions into their callers. `xboxrecomp/tools/disasm/
functions.py` bounds functions by **section end** and uses `0x100000` only as a
fallback when the section end is unknown. It separates the two concerns
correctly; we conflate them.

Two toolboxes, the same architecture, one of them quietly better. Nobody was
comparing them.

## What each has

Both target x86-32 static recompilation. Lines of tooling code:

| xboxrecomp | | pcrecomp | |
|---|---:|---|---:|
| `recomp` (lifter/codegen) | 9,819 | `lift` | 5,118 |
| `disasm` | 4,613 | `disasm` | 2,857 |
| **`conformance`** | 2,532 | — | |
| **`func_id`** | 2,406 | `classify` | 1,600 |
| `xbe_parser` *(Xbox)* | 1,155 | `pe` | 1,590 |
| **`ghidra_naming`** | 952 | `ghidra` | 541 |
| **`fusion`** | 902 | — | |
| `kernel_audit` *(Xbox)* | 711 | — | |
| **`symbols`** | 617 | — | |
| **`abi_analysis`** | 544 | — | |
| `xmv` *(Xbox)* | 512 | — | |
| **`debug_symbols`** | 511 | — | |
| **`split`** | 482 | — | |
| `xiso` *(Xbox)* | 404 | — | |
| **`rtti`** | 351 | — | |
| **`seed_from_log`** | 157 | — | |
| — | | `ne` (16-bit NE) | 1,756 |
| — | | `assets` | 960 |
| — | | `cpp` | 541 |
| — | | `ida` | 436 |
| — | | `drm` | 320 |
| **total** | **25,668** | **total** | **15,719** |

Roughly **2,800 lines of xboxrecomp is genuinely Xbox-specific** (`xbe_parser`,
`xiso`, `xmv`, `kernel_audit`). Nearly everything else is portable x86 work.

## What flows which way

**xboxrecomp → pcrecomp.** About 9,400 lines of portable tooling pcrecomp
simply does not have:

- **`conformance` (2,532 lines).** A generated-C-versus-hardware harness. Its
  comments show it already pins the x87 control word to PC=53 so the model and
  the hardware round identically, isolating genuine lifter bugs from precision
  noise. pcrecomp has `lift/difftest.py` (lifted C vs Unicorn), which is the
  same idea at a fraction of the maturity. This is the single most valuable
  item on the list — the Trespasser scorecard has been hand-rolling validation
  that partly exists here.
- **`func_id` (2,406).** `vtable_scanner`, `imm_scanner`, `crt_identifier`,
  `stub_classifier`, `clustering`. Directly relevant: pcrecomp's unaligned
  data-pointer scan accepts any four bytes that look like a code address, and a
  real vtable scanner -- runs of consecutive code pointers, not isolated hits --
  is the principled replacement for it.
- **`rtti` (351).** Trespasser hand-rolled RTTI extraction in its own
  `tools/recon.py` because pcrecomp had none. This already exists.
- **`disasm` improvements.** E9 seeding is now ported (see below). Section-end
  function bounding is not, and should be.
- **`symbols`, `debug_symbols`, `abi_analysis`, `ghidra_naming`, `fusion`,
  `split`, `seed_from_log`** — all portable, all absent from pcrecomp.

**pcrecomp → xboxrecomp.** Less bulk, but real:

- **`ne` (1,756).** 16-bit New Executable support. Irrelevant to Xbox, so this
  one stays put.
- **`pe` (1,590).** Full PE analysis, delay imports, protection detection.
  xboxrecomp parses XBEs; if it ever wants to look at a Windows binary
  alongside (an Xbox title's PC port, say) this is the piece.
- **`ida` (436).** xboxrecomp has Ghidra scripts but no IDA path.
- **`drm` (320)** and **`assets` (960).** SafeDisc dumping, InstallShield/Wise
  extraction — PC-era problems Xbox does not have, but the Trespasser and
  Quake-family work depends on them.
- **The Quake-family classification experience** (`classify`, 1,600) overlaps
  `func_id` and the better parts of each should merge rather than one winning.

## The honest counter-argument

Merging two working toolchains is a real cost and a real risk. Thirty-odd
projects depend on pcrecomp as it stands; the Xbox projects depend on
xboxrecomp. A big-bang consolidation would put all of them in the blast radius
at once for a benefit that is mostly "less duplication later".

So the recommendation is deliberately narrow:

1. **Port individual modules, measured, one at a time.** The E9 seeding fix was
   done this way — measured against ground truth before and after, output
   compared, ~4 lines. That is the template, and the port queue below follows it.
2. **Start with the disassembler, not the big modules.** The first instinct was
   to take `conformance` and `func_id` first, because Trespasser needs both. That
   is backwards: every downstream tool consumes the function catalog, so until
   the catalog is trustworthy every measurement below it is noisy. Fix what
   produces the catalog first — items 0 to 3 — then the modules that consume
   it. Scoring the catalog first is what turned up item 0, which was not on the
   list at all and turned out to be 87% of the measured error.
3. **Do not attempt a shared repo yet.** Prove the modules transplant cleanly
   first. A `pcrecomp-core` extraction is a conversation for after three or
   four successful ports, not before.
4. **Keep the Xbox-specific 2,800 lines where they are.** They are not
   candidates for anything.


## What the first measurement found

Before porting anything, the queue below was scored against ground truth. It
changed the order, and it changed what item 1 even is. The method:

- **Reference**: `trespass.map` — a linker map from a source build of
  Trespasser, so it is symbol-derived truth rather than another tool's opinion.
  34,159 distinct function starts. The map carries no end addresses, so IDA's
  ranges over an md5-identical copy of the same binary were merged onto its
  starts (92.3% coverage) to make the split/invented breakdown possible.
- **Candidate**: the stored `oracle_functions.json`, restricted to the truth's
  own VA range so the two populations are comparable.

```
  true positives      26,808
  false positives      7,981
      split            7,364  (inside a known function)
      invented           617  (outside every known function)
  false negatives      7,351

  precision   77.06%    recall 78.48%    F1 77.76%
```

**Splits are 92% of the error, and invented is 617 — not the 2,905 this
document claimed.** That number came from a different measurement and does not
reproduce against the map. Item 1 as originally written was aimed at the small
half of the problem.

Four things were then checked, because "7,364 splits" has several possible
causes and they need different fixes:

| Question | Answer |
|---|---|
| Are the splits real functions the map simply omits? | **No.** 0 of 7,364 are IDA function starts either, and IDA agrees with the map almost perfectly — of 31,512 IDA starts in range, exactly 1 is not a map start. Both authorities say no function starts there. |
| Are they tiny stubs, or real bodies? | **Real bodies.** 5,890 of 7,364 decode to more than 20 instructions. |
| Which scan produces them? | Not the seed scans. 28 come from the `55 8B EC` prologue scan, 362 from the `E8` scan, 547 from the `E9` scan — and **6,427 from none of them.** |
| So where do they come from? | The fixpoint in `find_functions`, from the branch that promotes a jump landing inside another function's body into a function of its own. |

That branch is deliberate, and its comment says so: a shared epilogue or a
switch arm reached from elsewhere "has no label in the jumping function, so the
lifter tail-dispatches to it; make it a real entry point or that dispatch is
unresolved at runtime."

So the dominant finding is not a recovery defect. **It is a category error in
the catalog format.** The disassembler knows perfectly well that these are not
function starts — it creates them precisely because they are *not*, and the
lifter needs a dispatchable body at an address in the middle of something else.
It then writes them into the catalog in a field that says "function", and every
consumer, the scorecard included, has no way to tell the two apart.

Measuring that as 77% precision measures a design decision. The disassembler was
never claiming a function starts at those 6,427 addresses.

xboxrecomp already draws this distinction — `_build_alias_entries` and
`_pass_seed_aliases` record such an address as an alias of its containing
function, with `detection_method="tail_jump_alias"` and `has_prologue=False`,
bounded by the containing function's end. That is the thing worth taking, and
it is a field, not a redesign.

### What changed as a result

1. **`entry_kind` on every catalog entry** — `"start"` where we believe a
   function begins, `"alias"` where we do not and are only making an address
   dispatchable. Set by the branch that creates them, emitted in the JSON.
2. **`score_recovery.py` holds aliases out of precision** and reports them on
   their own line, split by whether they land inside a known function (expected)
   or outside every one (suspect — a body pointing at nothing). An alias landing
   exactly on a reference start is counted separately again, because that is a
   real function demoted, and a demoted start is not reported as found.
3. **`probes_as_function_body` still lands**, because 617 invented functions are
   still 617 functions' worth of decoded garbage, and the probe is ~40 lines and
   carries its own self-test. It is just no longer item 1.

The rest of the queue keeps its order. The lesson is the one this repo keeps
re-learning: the number a tool reports about itself is not a measurement, and
the first real measurement usually reorders the work.

## The port queue

Ordered by (what it fixes) / (what it costs), not by size. Each item names the
source file, the defect it closes, and **how to know it worked** -- because the
whole reason this document exists is that nobody was measuring.

The rule for every item: port it, measure it with `disasm/score_recovery.py`
against a reference catalog before and after, and keep the diff small enough to
read. The E9 fix was four lines and recovered 6,550 functions. That ratio is
the target, not the exception.

---

### 0. Function start vs. alias entry · ~30 lines · **done**

**Source**: `xboxrecomp/tools/disasm/functions.py` --
`_build_alias_entries`, `_pass_seed_aliases`, and the `detection_method` field
carried on every `Function`.

**The defect.** `disasm32.find_functions` promotes a branch landing inside
another function's body into a function of its own, deliberately: the lifter
tail-dispatches to that address and needs a body there. It then writes the
result into the catalog in a field that says "function", identical to a real
function start. Nothing downstream can tell a genuine start from an address we
only made dispatchable.

Measured: **6,427 of 7,364 false positives were aliases** -- 87% of the reported
error, and the disassembler was never claiming a function started there.

**The fix.** `Function.entry_kind`, `"start"` or `"alias"`, set where the
aliases are created and emitted in the JSON. `score_recovery.py` holds aliases
out of precision, and reports them separately split by whether they land inside
a known function (expected) or outside every one (suspect). An alias landing on
a reference start is counted again on its own line: that is a real function
demoted, and a demoted start will not be reported as found.

The overlap between an alias body and its containing function stays. That is
the same trade xboxrecomp makes, and for the same reason its docstring gives:
the alternative is a stub that returns immediately, silently skipping the
epilogue and leaking the caller's frame.

**Verify**: precision against the map, with aliases excluded, versus the 77.06%
baseline. Plus `score_recovery.py --selftest`, which now asserts that an alias
inside a known function does not touch precision.

---

### 1. Candidate validation -- `engine.probes_as_*` · ~40 lines · **done**

**Source**: `xboxrecomp/tools/disasm/engine.py` -- `probes_as_function_body`,
`probes_as_prologue`, `probes_as_constant_stub`, `probes_as_vcall_thunk`,
`probes_as_returning_body`.

**The defect.** `disasm32.find_data_code_pointers` scans every byte offset of
every data section for a value in the code range and calls each hit a function.
Unaligned on purpose -- GTA1's handler table starts at `0x4B4AD1` and an
aligned-only scan misses it entirely -- but the price is that any four bytes
that happen to look like a code address become a function.
`find_branch_targets` has the same shape: a linear `E8`/`E9` byte scan that
cannot tell an opcode from the middle of an immediate.

**Scale, measured rather than assumed.** Against the map this is **617 invented
function starts**, not the 2,905 an earlier draft of this document claimed --
that figure came from a different measurement and does not reproduce here. 617
is still 617 functions' worth of decoded garbage, and the fix is about forty
lines, so it lands. It is simply not the largest thing wrong.

The comment in `find_data_code_pointers` says "false positives just become dead
functions -- harmless". That is true for the *build* and false for everything
else: it poisons the precision number, buries real misses in noise, and spends
codegen on garbage.

**The fix.** xboxrecomp does not guess harder, it *corroborates*. Before
accepting a candidate, decode forward from it and require the stream to reach a
`ret` or a tail jump without hitting bytes that will not decode. Data almost
never does; code almost always does. Read that docstring -- it records why
alignment was tried first and abandoned (a real MSVC function start is only
aligned when the linker had a reason to pad it) and why the instruction cap has
to be generous (one real function runs 537 instructions before its first `ret`,
and a cap of 512 rejected it).

The probe is deliberately *read-only*: it follows instructions the sweep already
decoded where they exist and decodes the rest without recording them, so running
it never changes what the sweep produced.

**Verify**: re-score Trespasser. The invented count should fall with recall
unchanged. If recall moves at all, the probe is too strict. The probe also
prints what it rejected, so its effect is visible without a second full run.
`disasm32.py --selftest` covers the decision boundaries: a prologue reaching
`ret` passes, a tail `jmp` passes, undecodable bytes fail, a clean decode that
runs off the section end without a terminator fails.

---

### 2. Jump-table resync -- `engine.resync_jump_tables` · ~60 lines

**Source**: `xboxrecomp/tools/disasm/engine.py:229`, plus `functions._table_after`
and the `jump_tables` bookkeeping inside `_find_function_end`.

**The defect.** MSVC parks a switch's jump table *inline*, on the fall-through
path, immediately after the dispatching `jmp dword ptr [reg*4 + disp]`. Any
linear scan over that region decodes code pointers as instructions and comes out
the far side out of phase.

`disasm32.py` partly dodges this by accident -- `disassemble_function` treats the
indirect jump as a terminator and reaches the post-table code through the switch
arms, so the epilogue usually survives. But **`find_branch_targets` does not**.
It is a raw byte scan, it walks straight through every table in the image, and
every `E8`/`E9` byte sitting inside a code pointer becomes a fake call target.
Tables are a significant share of the invented functions in item 1.

**The fix.** Measure each table (entries must point inside the *same* section,
which is what bounds the walk), record the range as data, and have both the byte
scans and the function-end walk step over it rather than through it.

Note the war story in that docstring: `memcpy` and `memmove` each carry a
tail-copy table, the desync ate their `pop esi / pop edi`, and a C++
static-initialiser loop using esi as cursor and edi as limit had both clobbered
by its own callees and stopped after 8% of the constructor list. "Silently loses
registers inside the CRT" is the failure mode, and it does not look like a
disassembler bug from where you find it.

**Verify**: count tables resynced on a switch-heavy binary, and confirm no
instruction outside a table range is deleted.

---

### 3. Section-end function bounding · ~15 lines

**Source**: `xboxrecomp/tools/disasm/functions.py:973` (`_find_function_end`).

**The defect.** `disasm32.py` uses `abs(target - start_va) < 0x100000` to decide
whether a branch target is internal control flow or a tail call, and takes
`max(block.end)` as the function end. Two different questions answered with one
constant.

xboxrecomp separates them. The upper bound is **the section end, or the next
known function start**, whichever is lower; `0x100000` survives only as the
fallback when the section end is unknown. It then tracks `max_target` -- the
highest branch target that must be inside the function -- and refuses to stop at
a `ret` until it has decoded *past* it, because MSVC routinely emits
`jmp <backward>` and parks a conditional branch's target after it.

**Do not** simply widen pcrecomp's `0x100000`. That was nearly done while fixing
the E9 bug, and it would have merged every tail-called function into its caller.

**Verify**: function sizes against a linker map. Ends should stop overshooting
into the next function and stop truncating at out-of-line tails.

---

### 4. `seed_from_log` · 157 lines · **cheapest win on the list**

**Source**: `xboxrecomp/tools/seed_from_log/`.

The `recomp32` runtime already prints `ITAIL/ICALL: unresolved VA ...` when
dispatch misses. Today a human reads those out of a console and hand-edits a
seed list; several projects carry one. This feeds the log straight back into the
next codegen pass.

Static analysis cannot see where a vtable call goes, or a thread entry point
that is only ever *pushed* as an argument and never called. The Xbox note on the
latter applies verbatim to Win32: the thread never starts, the process exits
cleanly after a couple of API calls, and it reads as a successful run rather
than as zero progress.

Needs a `CreateThread`-shaped equivalent of the `PsCreateSystemThreadEx` case
and a change to the log-line regex. Little else.

---

### 5. `rtti` · 351 lines

**Source**: `xboxrecomp/tools/rtti/rtti.py`.

MSVC 32-bit RTTI, with plain VAs and none of the image-relative indirection x64
uses -- which is exactly the layout in every C++ PC binary here. Where a build
left RTTI on, it yields every polymorphic class name, every vtable (the
CompleteObjectLocator sits at `vtable[-1]`), every virtual method address, and
the full inheritance chain.

Those method addresses are **proof of function entry points**, which is why this
runs *before* disassembly rather than after: they are seeds that cannot be
wrong, unlike anything the byte scans produce.

Trespasser hand-rolled RTTI extraction in its own `tools/recon.py` because
pcrecomp had none. Black & White's seven-level hierarchy is the other obvious
customer. The port needs only the `XbeFile` reader swapped for a PE one.

---

### 6. `func_id/vtable_scanner` · 325 lines

**Source**: `xboxrecomp/tools/func_id/vtable_scanner.py`.

The principled version of item 1's unaligned pointer scan: look for **runs of
three or more consecutive code pointers** in `.rdata`/`.data` rather than
isolated hits. A run is a vtable; an isolated hit is usually noise. It also finds
the `this`-adjusting thunks that live between `ret`s and are reachable only
through a vtable ICALL -- precisely the functions the detector misses.

Rise of Legends is the argument: **25,513 functions reachable only through
vtables, and no RTTI** to lean on. A recovery pass that cannot follow a vtable
misses most of that binary, and item 5 returns nothing there.

Runs after RTTI, which supersedes it wherever RTTI exists.

---

### 7. `symbols/map_names` · 263 lines · worth more on PC than on Xbox

**Source**: `xboxrecomp/tools/symbols/map_names.py`.

Two modes, and the second is the interesting one.

`resolve` parses an MSVC linker MAP into `{va: name}`. Two binaries here ship
their own map -- **Operation Neptune** and **Trespasser** -- and both currently
use it only as a scorecard, never as a symbol source.

`port` carries *library* names from a binary that has a map onto one that does
not, by matching library code byte-for-byte. Measured on Xbox: a donor built
against a different SDK version still named 657 functions in the target; where
two donors overlapped they agreed 99.1% of the time; and the union of donors
beat either alone, 735 versus 504.

On PC this is worth more than on Xbox, because the shared-library surface is
bigger and better documented. One MSVC 6 binary with a map names the CRT in
every other MSVC 6 binary in the collection. The MFC 4.0 surface in Encarta, the
Borland CRT in Operation Neptune, the Watcom runtime in Nocturne -- each is a
donor for the next project that hits the same toolchain.

The section:offset reasoning in that file is Xbox-specific (imagebld discards
`Rva+Base` when it emits the XBE). On a plain PE, `Rva+Base` is usable directly
and the port gets *simpler*.

---

### 8. `debug_symbols` · 256 lines

**Source**: `xboxrecomp/tools/debug_symbols/recover.py`.

Debug builds keep their asserts, and each assert bakes `__FILE__` into the
binary as a string referenced from the function containing it. Two passes --
direct attribution by string xref, then interpolation across unattributed runs
whose endpoints agree on the same file -- map function addresses back to their
original source files.

Emits `{address: name}`, the same shape the naming merge already consumes.

Applies to any assert-heavy or debug PE build. Worth checking which discs in the
collection shipped one; historically several did by accident.

---

### 9. `conformance` · 2,532 lines · the big one, assess before porting

**Source**: `xboxrecomp/tools/conformance/` -- of which `cases.py` (442) and
`harness.py` (329) are the portable core, and `xbe_run.py` (670) is not.

Same idea as `lift/difftest.py`, considerably further along. Snippets are written
as **MSVC inline-assembly text**, so the assembler picks the encoding rather than
us; the same bytes then run natively and lifted, and the results are compared.
Three kinds:

| kind | inputs | compared |
|------|--------|----------|
| `gpr` | `(eax, ecx)` uint32 pairs | `eax` |
| `fpu` | two doubles in a scratch buffer | x87 **stack depth** and every live `st(i)`, plus `eax` |
| `sse` | two 4-float tuples | all eight XMM registers as raw bytes, plus `eax` |

The depth comparison is what `difftest.py` does not do, and it is the point: a
handler that pops the wrong number of times is a whole bug class, and the *value*
alone never shows it. That class desynced Halo's camera maths. POD and Fury3 are
the local binaries with enough x87 to care.

It also pins the x87 control word to **PC=53** so the model -- which holds the
stack as C `double` -- and the hardware round identically. Without that,
add/sub/mul/div/sqrt disagree in the last place for reasons that have nothing to
do with lifting, and every real bug is buried in precision noise.

**Assess first**: port the harness, or lift `cases.py` plus the control-word
discipline into `difftest.py`? The second is probably right -- `difftest.py`
already runs lifted C against Unicorn, which is the harder half.

---

### 10. `abi_analysis` · 544 lines · and `split` · 482 lines

`abi_analysis` infers calling convention, parameter count, return hint and frame
type per function. `pe/stdcall_argc.py` derives purge counts from SDK headers,
which is exact but only covers imports; this covers *internal* functions, where
nothing declares anything.

`split` emits one `.s` per function with the original bytes as `db` and the
mnemonics as comments, so an undecompiled function still assembles to the
original encoding -- the oracle a matching decomp is built on. x86 cannot
round-trip mnemonics through an assembler the way MIPS can (`mov eax, ecx` has
two encodings and which one MSVC picked is not recoverable), which is why the
bytes are data and the listing rides alongside as a comment. pcrecomp has no
decomp mode at all; this is what one would start from.

Neither is urgent. Both are listed so they are not re-invented.

---

### 11. Tests

`xboxrecomp/tools/disasm/` ships six test files -- `test_cc_boundary`,
`test_decode_at`, `test_function_end`, `test_gap_prologue`, `test_imm_refs`,
`test_vcall_thunk`. `pcrecomp/tools/disasm/` ships none; the only executable
checks in this repo are two `--selftest` flags and three C self-tests under
`runtime/`.

Port the tests *with* each item above rather than as a batch. A ported heuristic
without its test is a heuristic nobody can safely change later.

---

## What is not on the list

**Not candidates, deliberately:**

- `xbe_parser`, `xiso`, `xmv`, `kernel_audit` (~2,800 lines) -- genuinely
  Xbox-specific. They stay where they are.
- `fusion` and `ghidra_naming` -- assessed later; `fusion` is tied to a corpus
  we do not have.
- pcrecomp's `ne/` (1,756 lines) -- 16-bit New Executable support. Irrelevant to
  Xbox, stays put.

**Flowing the other way (pcrecomp -> xboxrecomp):** `pe/` (1,605) if xboxrecomp
ever wants to look at a title's PC port alongside the XBE; `ida/` (436), since
xboxrecomp has a Ghidra path and no IDA one; `drm/` (320) and `assets/` (924),
which solve PC-era problems Xbox does not have. The Quake-family classification
experience in `classify/` (1,600) overlaps `func_id`, and the better parts of
each should merge rather than one winning.

---

## Status

- [x] `disasm32.find_branch_targets` -- E9 tail-call seeding, ported from the
      behaviour in `xboxrecomp/tools/disasm/xrefs.py`. Measured on an 8.8 MB
      binary with a linker map: recovers 6,550 of 7,331 missed functions.
- [x] 0. `entry_kind` -- function start vs. alias entry, with the scorer
      taught to stop counting a design decision as a defect. 87% of the
      measured "false positives" were this.
- [x] 1. `probes_as_*` candidate validation -- `probes_as_function_body`,
      gating the data-pointer scan, with a self-test.
- [ ] 2. `resync_jump_tables`
- [ ] 3. Section-end function bounding
- [ ] 4. `seed_from_log`
- [ ] 5. `rtti`
- [ ] 6. `func_id/vtable_scanner`
- [ ] 7. `symbols/map_names`
- [ ] 8. `debug_symbols`
- [ ] 9. `conformance` -- assess against `lift/difftest.py` first
- [ ] 10. `abi_analysis`, `split`
- [ ] 11. Disassembler tests, ported alongside each item

**Still not a shared repo.** A `pcrecomp-core` extraction is a conversation for
after items 1-6 have landed and held, not before.
