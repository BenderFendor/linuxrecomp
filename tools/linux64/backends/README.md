# Backend contract

Backends consume a `linuxrecomp-spec-v1` document (see
[`../docs/linux64/RECON.md`](../../docs/linux64/RECON.md) and
[`spec_schema.json`](../spec_schema.json)) and produce LLVM bitcode plus a
machine-readable map from guest virtual addresses to emitted symbols. The map is
what the runtime dispatcher is built from, so a backend that lifts functions but
cannot name their symbols is not usable yet.

Requirements on a backend:

* addresses in, addresses out. The spec's addresses are guest VAs; the emitted
  symbol map must be keyed the same way, so nothing downstream re-derives an
  image base.
* a function with `end: null` in the spec has an unknown extent. Lifting it
  requires either a supplied bound or an explicit bail-out; do not guess an end
  from the next function's start.
* `source` (`pdata`, `ghidra`, `export`, `entrypoint`) is provenance, not
  priority. Consumers may not silently drop a source.

Primary backend: Remill, linked directly into the MIT-licensed lifter tool.
Optional, process-separated backends: Anvill (AGPL-3.0) reached through a
`program.json` → protobuf converter, and rev.ng (GPL-2.0) as a comparison
backend. Rellic is not a lifter; it consumes bitcode and emits readable C for
inspection.

None of the optional backends may end up linked into this tree — see
[`../../docs/linux64/LICENSES.md`](../../docs/linux64/LICENSES.md).
