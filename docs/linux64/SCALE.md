# What the pipeline costs at Photoshop scale

`Photoshop.exe` (2025) is the largest target this project has been pointed at:
198,464,944 bytes, image base `0x140000000`, 208,236,544 bytes of image. Every
number here is measured on this machine (Ryzen 5 3600, wine-11.15, Remill
`remill-lift-22`), not estimated. Re-run with the commands in each section.

## Reconversion: 61 seconds, no problems

```bash
time python3 -m tools.linux64 recon "/home/bender/projects/linuxphotoshop/Adobe Photoshop 2025/Photoshop.exe" \
  --out work/linux64/photoshop.json
```

| Result | Value |
|---|---|
| Wall time | 61 s |
| Imports | 3,928, from 83 DLLs |
| Exports | 1,583 (1,507 code, 76 data) |
| Functions | 325,924 (590 from exports, 325,334 from `.pdata`) |
| Code covered | 119,305,711 bytes; 590 functions with unknown end |
| `.pdata` entries | 381,718, 56,384 continuations merged, 143,443 with language handlers |
| Relocations | 642,458 (`dir64`) |
| Delay imports | present (directory size 640, non-zero) |
| TLS | 3 callbacks |
| Problems | none |
| Spec size | 190 MB of JSON |

The import and DLL counts match the figures verified for this binary earlier
(`~/Documents/ai-memory-vault/linuxphotoshop/notes/pcrecomp-x64-analysis-tools-2026-09-18.md`:
3,928 imports from 83 DLLs), which is the useful part: independent tooling, same
answer, on a binary where a single miscount would be easy to miss.

## Lifting: about 31 seconds per function, and that is the wall

```bash
python3 -m tools.linux64 lift "$PS" --function 0x1426A8C90 --out work/linux64/photoshop-lift
```

Three single-function lifts took 31.2 s, 31.4 s and 31.7 s. Almost all of it is
per-invocation cost: loading a 198 MB image and starting Remill, not the size of
the function. `--all --limit N --jobs 6` runs the same work in one invocation and
was still working after ten minutes for six functions.

Extrapolating the measured 31 s per function over the 325,924 recovered functions
gives about 113 days of single-core work, or roughly 19 days at six-way
parallelism. Whole-program lifting at this scale is therefore not a viable plan,
and no amount of tuning changes the order of magnitude: the strategy has to be
lazy. Lift what the program actually reaches, close the call graph over that set
(`--reachable`), and let the program's own execution decide the bill.

## Building and running: seconds, and a clean stop

```bash
./scripts/build-lifted-harness.sh "$PS" work/linux64/photoshop-lift work/linux64/bin
work/linux64/bin/lifted_harness-Photoshop.exe "$PS" 0x1426A8C90
```

The harness builds in 2 s for two lifted functions (311 functions on the much
smaller `HLExtract.exe` take 19 s). The image maps at its preferred base, all 642
thousand relocations are deliberately not applied (this project never rebases),
and the run takes 1 s.

| Function | Lifted | Reference executor |
|---|---|---|
| `0x1426A8C90`, the image entrypoint | `result=0`, `stop returned at 0`, `entered=1 deepest=1 missing=0` | `result=0` |
| `0x140001000`, first `.pdata` function | `stop call at 0xa98a96a (call to unlifted address ...)`, `missing=1` | faults: `signal 11 at rip=0xa98a96a` |

The entrypoint matches the reference executor, which is the differential check
working on a real 198 MB binary rather than a fixture.

The second row is the more interesting one. Both paths reach the same computed
call target `0xa98a96a`; the reference executor can only die there, while the
lifted harness stops and *names* the address. At this scale that reporting is what
turns an unexplained crash into the next instruction for the pipeline, and it is
the difference between a five-second diagnosis and a debugging session.

## What this does not establish

* Two functions are not a sample of 325,924. What is measured is the pipeline's
  cost per function and its behaviour on individual functions, not its coverage of
  Photoshop.
* No Win32 import is served yet. The lifted path has no IAT resolution, so a
  function that calls `kernel32` stops exactly like a function that calls an
  unlifted internal target, and `P4` is where that changes.
* A function that wanders into uninitialised state stops early or faults. The
  harness sets up the Microsoft x64 argument registers and a stack region and
  nothing else, so arguments that are pointers, or globals the loader has not
  initialised, are not meaningful inputs.
* The reference executor is only usable for functions that do not call anything
  interesting, which at this scale means almost none of them.

## Where this leaves the roadmap

Reconversion at scale is settled: 61 s, no problems, and it agrees with an
independent analysis of the same binary. Execution at scale works but is bounded
by lifting cost, so the plan that follows is:

1. resolve imports (`P4`) so real functions can get past their first external
   call, which is also the point where the Wine host has to work;
2. lift lazily, driven by what execution reaches, with the differential harness as
   the check on each newly lifted function;
3. treat 325,924 as the budget ceiling, not the workload.
