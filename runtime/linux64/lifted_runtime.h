/* Runtime for executing Remill-lifted code.
 *
 * Remill emits each lifted trace in explicit CPU-state form:
 *
 *     Memory *sub_<guest_va>(State *state, addr_t pc, Memory *memory);
 *
 * and leaves the `__remill_*` functions for the consumer to implement. This
 * header is the project's implementation of that contract: the guest memory
 * model, the register file, and the control-flow boundary used to stop a trace.
 *
 * The lifted IR declares its state type as the x86_64 layout from
 * `remill/Arch/X86/Runtime/State.h`, so the harness compiles against Remill's own
 * header rather than a private copy of the layout.
 */
#ifndef LINUXRECOMP_LIFTED_RUNTIME_H
#define LINUXRECOMP_LIFTED_RUNTIME_H

#include <cstdint>

#include "image_pe64.h"

#include <remill/Arch/X86/Runtime/State.h>

/* Guest memory is the image mapped at its own base, plus a stack region the
 * runtime owns. Everything the lifted code touches goes through an address in
 * this space: the guest sees the addresses it was linked for. */
struct Memory {
    pe_image *image;
    uint8_t *stack;
    uint64_t stack_base;
    uint64_t stack_size;
};

/* Resolve a guest address to a host pointer, or nullptr when unmapped. */
uint8_t *guest_ptr(Memory *memory, uint64_t address, uint64_t length);

/* Where the trace stopped, for the caller to report. */
enum class StopReason {
    kReturned,
    kError,
    kFunctionCall,
    kJump,
    kMissingDispatch,
};

extern "C" {
StopReason lifted_stop_reason(void);
uint64_t lifted_stop_pc(void);
const char *lifted_stop_detail(void);
const char *lifted_stop_reason_name(StopReason reason);
}

/* Report reads of values Remill could not determine, instead of silently
 * treating them as zero. */
void lifted_report_undefined(bool enabled);

/* Print every guest memory access. For diagnosing an unexplained fault, where
 * the last access before it is the useful clue. */
void lifted_set_memory_trace(bool enabled);

/* Print each trace boundary: entry, finish and halt. For locating a fault that
 * the host cannot report. */
void lifted_set_dispatch_trace(bool enabled);

/* Dispatch table: guest VA to lifted function. Generated per build from the
 * lift manifests, so a build cannot silently reference a function nobody
 * lifted. */
typedef Memory *(*lifted_function)(State *, uint64_t, Memory *);

struct LiftedEntry {
    uint64_t va;
    lifted_function function;
    const char *name;
};

const LiftedEntry *lifted_lookup(uint64_t va);
const LiftedEntry *lifted_entry(size_t index);
size_t lifted_entry_count(void);

/* Run a lifted function until it returns or hits a boundary the runtime does
 * not model yet. */
StopReason lifted_run(lifted_function function, State *state, uint64_t pc,
                      Memory *memory);

/* Run the program at *va* with dispatch: a call or jump to another lifted
 * function continues there instead of stopping the trace. Returns when control
 * reaches an address that is not a lifted function, or when the trace errors. */
StopReason lifted_run_dispatched(uint64_t va, State *state, Memory *memory);

/* Observability for a dispatched run. */
uint64_t lifted_functions_entered(void);
uint64_t lifted_deepest_dispatch(void);
size_t lifted_missing_target_count(void);
uint64_t lifted_missing_target(size_t index);
/* Reads and discards the counters, so each run reports its own numbers. */
void lifted_reset_stats(void);

/* Target of the generated stubs for call targets that were never lifted. */
Memory *lifted_missing_function(State *state, uint64_t pc, Memory *memory);

#endif /* LINUXRECOMP_LIFTED_RUNTIME_H */
