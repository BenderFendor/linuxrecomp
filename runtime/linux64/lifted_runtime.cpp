/* The `__remill_*` runtime that Remill's lifted code calls into.
 *
 * Remill emits traces that take (State *, pc, Memory *) and leaves every memory
 * access, flag computation and control-flow boundary to the consumer. This file
 * is that consumer for the linuxrecomp runtime.
 *
 * Three decisions worth knowing about:
 *
 * 1. Guest memory is the image mapped at its own base plus a stack region the
 *    runtime allocates. A read or write outside both halts the trace and reports
 *    the address, because "the lifted code touched memory we do not model" is a
 *    fact a caller needs, not something to paper over with a zero.
 *
 * 2. A call to another lifted function runs that function and resumes the caller,
 *    which is what a call means. A jump does the same but ends the current trace,
 *    because a jump does not come back. Anything else stops the trace and reports
 *    the address it could not continue at, which is how imports announce
 *    themselves before P4 implements them.
 *
 * 3. Each trace has its own stop context on the C stack, so a called function
 *    unwinds to itself and not to its caller.
 */
#include "lifted_runtime.h"

#include <cstdarg>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "guest_heap.h"

namespace {

/* One execution context per active trace. A called function runs inside the
 * caller's trace, so the context is a stack: `halt` always unwinds to the
 * innermost trace, which is the one that hit the boundary.
 *
 * The buffer is clang's built-in jump buffer, not `jmp_buf`. `setjmp` is a libc
 * symbol, and a host can supply a different implementation of it with a different
 * buffer layout: in a winelib build the link binds `setjmp` to Wine's PE-side
 * `_setjmp` stub, which writes a Windows-shaped buffer into what this file sized
 * as glibc's `jmp_buf`. Measured on wine-11.15 as a crash inside that stub. The
 * built-in emits the save and the restore inline, with a layout the compiler owns,
 * so nothing outside this translation unit can disagree about it. */
struct StopContext {
    void *jump[5];
    StopContext *previous;
};

StopContext *g_current = nullptr;

const char *reason_name(StopReason reason);
void trace_dispatch(const char *format, ...);

/* DLL and function names compare the way the loader's do. */
bool ascii_equal_ignore_case(const char *left, const char *right) {
    while (*left && *right) {
        char a = *left++;
        char b = *right++;
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return *left == '\0' && *right == '\0';
}
StopReason g_reason = StopReason::kReturned;
uint64_t g_stop_pc = 0;
char g_detail[256];

/* Dispatch statistics, reset per dispatched run. */
uint64_t g_functions_entered = 0;
uint64_t g_deepest_dispatch = 0;
uint64_t g_depth = 0;
constexpr uint64_t kMaxDispatchDepth = 4096;
constexpr size_t kMaxMissing = 64;
uint64_t g_missing_targets[kMaxMissing];
size_t g_missing_count = 0;

/* Remill marks values it cannot know (uninitialised registers, undefined
 * instruction results). This runtime answers zero and reports them when asked,
 * rather than pretending the value was defined. */
bool g_report_undefined = false;

/* Imports the host bound for this image, if any. Mutable: a program can obtain a
 * callable host address at run time, and the dispatcher has to know it. */
import_table *g_imports = nullptr;

/* Some imports cannot be handed straight to the host.
 *
 * Wine's HeapAlloc returns host memory, and a recompiled program that writes
 * through that pointer is writing outside the address space this runtime
 * describes: the first HLExtract run to reach it stopped with "write of unmapped
 * guest address 0x7ffffe231460", a host pointer. The fix is not to change what
 * these functions mean but where the memory is, so the guest allocates from the
 * guest heap and the pointer it gets back is one it can use. The same applies to
 * the imports that return pointers to host strings or host structures.
 *
 * This table is the one place a Win32 entry is not Wine's, and every entry is here
 * for a reason a target demonstrated: the guest cannot address host memory. */
typedef uint64_t (*thunk_function)(State *state, const uint64_t *arguments, Memory *memory);

/* The value GetProcessHeap returns is opaque to the guest; it only has to be
 * consistent between the calls that use it. */
constexpr uint64_t kGuestProcessHeap = 0x1000;

uint64_t thunk_process_heap(State *, const uint64_t *, Memory *) { return kGuestProcessHeap; }

uint64_t thunk_heap_alloc(State *, const uint64_t *arguments, Memory *) {
    /* HeapAlloc(heap, flags, bytes) */
    return guest_heap_alloc(arguments[2]);
}

uint64_t thunk_heap_realloc(State *, const uint64_t *arguments, Memory *) {
    /* HeapReAlloc(heap, flags, memory, bytes) */
    return guest_heap_realloc(arguments[2], arguments[3]);
}

uint64_t thunk_heap_free(State *, const uint64_t *arguments, Memory *) {
    /* HeapFree(heap, flags, memory) */
    return guest_heap_free(arguments[2]) ? 1 : 0;
}

uint64_t thunk_heap_size(State *, const uint64_t *arguments, Memory *) {
    /* HeapSize(heap, flags, memory) */
    return guest_heap_size_of(arguments[2]);
}

uint64_t thunk_virtual_alloc(State *, const uint64_t *arguments, Memory *) {
    /* VirtualAlloc(address, size, type, protect). An explicit address would have to
     * be a range the memory model knows about, so for now only the "anywhere" form
     * is served; the rest fails the way an allocation failure does, which the
     * program is expected to handle. */
    if (arguments[0] != 0) {
        trace_dispatch("virtual alloc at %#llx is not served", (unsigned long long)arguments[0]);
        return 0;
    }
    return guest_heap_alloc(arguments[1]);
}

uint64_t thunk_get_proc_address(State *, const uint64_t *arguments, Memory *) {
    /* GetProcAddress(module, name). The program then calls what it got, so the
     * address has to be one the dispatcher can route: register it as it is found. */
    const char *name = (const char *)(uintptr_t)arguments[1];
    void *resolved = host_get_proc_address(arguments[0], name);
    if (!resolved) {
        return 0;
    }
    uintptr_t value = (uintptr_t)name;
    const char *label = value < 0x10000 ? "ordering" : name;
    imports_register(g_imports, (uint64_t)(uintptr_t)resolved, "run-time", label);
    return (uint64_t)(uintptr_t)resolved;
}

uint64_t thunk_virtual_free(State *, const uint64_t *arguments, Memory *) {
    /* VirtualFree(address, size, type) */
    return guest_heap_free(arguments[0]) ? 1 : 0;
}

struct ImportThunk {
    const char *dll;
    const char *name;
    thunk_function function;
};

const ImportThunk kImportThunks[] = {
    { "KERNEL32.dll", "GetProcessHeap", thunk_process_heap },
    { "KERNEL32.dll", "HeapAlloc", thunk_heap_alloc },
    { "KERNEL32.dll", "HeapReAlloc", thunk_heap_realloc },
    { "KERNEL32.dll", "HeapFree", thunk_heap_free },
    { "KERNEL32.dll", "HeapSize", thunk_heap_size },
    { "KERNEL32.dll", "VirtualAlloc", thunk_virtual_alloc },
    { "KERNEL32.dll", "VirtualFree", thunk_virtual_free },
    { "KERNEL32.dll", "GetProcAddress", thunk_get_proc_address },
};

const thunk_function find_thunk(const import_entry *import) {
    for (const ImportThunk &thunk : kImportThunks) {
        if (ascii_equal_ignore_case(thunk.dll, import->dll) &&
            ascii_equal_ignore_case(thunk.name, import->name)) {
            return thunk.function;
        }
    }
    return nullptr;
}

/* Call a host import the way its own ABI expects.
 *
 * The guest convention is the Microsoft x64 one: four arguments in RCX, RDX, R8
 * and R9, further arguments on the guest stack above the return address, and the
 * result in RAX. A Win32 import is called with that same convention, so the
 * function pointer types carry ms_abi; calling through a SysV pointer into a Win32
 * function works by luck rather than by contract, and stops working as soon as
 * the callee spills its register arguments into the home area its ABI gives it.
 *
 * Eight arguments are always passed. A callee reads only the arguments it declares,
 * so extra ones are harmless, and they are read from the guest's own stack, which is
 * exactly where a real call would have left them.
 */
#define IMPORT_ARGS 8

uint64_t call_host_import(uint64_t address, const uint64_t *arguments) {
    typedef uint64_t(__attribute__((ms_abi)) * function_pointer)(uint64_t, uint64_t, uint64_t,
                                                                 uint64_t, uint64_t, uint64_t,
                                                                 uint64_t, uint64_t);
    function_pointer function = (function_pointer)(uintptr_t)address;
    return function(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                    arguments[5], arguments[6], arguments[7]);
}

Memory *halt(StopReason reason, uint64_t pc, const char *detail) {
    trace_dispatch("halt %s at %#" PRIx64 " (%s)", reason_name(reason), pc,
                   detail ? detail : "");
    g_reason = reason;
    g_stop_pc = pc;
    std::snprintf(g_detail, sizeof(g_detail), "%s", detail ? detail : "");
    if (g_current) {
        __builtin_longjmp(g_current->jump, 1);
    }
    std::fprintf(stderr, "lifted runtime: %s at pc=%#llx (%s) outside a trace\n",
                 detail ? detail : "halt", (unsigned long long)pc,
                 g_detail[0] ? g_detail : "");
    std::abort();
}

/* Run one lifted trace until a boundary. The context is stack-local so nested
 * execution through the dispatcher unwinds to the right trace. */
StopReason trace_once(lifted_function function, State *state, uint64_t pc,
                      Memory *memory) {
    trace_dispatch("trace %p at %#" PRIx64, (void *)function, pc);
    StopContext context;
    context.previous = g_current;
    g_current = &context;
    g_reason = StopReason::kReturned;
    g_stop_pc = 0;
    g_detail[0] = '\0';
    if (__builtin_setjmp(context.jump) == 0) {
        function(state, pc, memory);
    }
    trace_dispatch("trace %p finished with %s", (void *)function, reason_name(g_reason));
    g_current = context.previous;
    return g_reason;
}

const char *reason_name(StopReason reason) {
    switch (reason) {
        case StopReason::kReturned: return "returned";
        case StopReason::kError: return "error";
        case StopReason::kFunctionCall: return "call";
        case StopReason::kJump: return "jump";
        case StopReason::kMissingDispatch: return "missing-dispatch";
        case StopReason::kMissingBlock: return "missing-block";
    }
    return "unknown";
}

/* The lifted function whose range contains *address*, when the address is not
 * itself a lifted entry. Lifted entries come from .pdata and cover their functions
 * contiguously, so an address between two entries belongs to the earlier one. */
const LiftedEntry *lifted_containing(uint64_t address) {
    const LiftedEntry *previous = nullptr;
    for (size_t i = 0; i < lifted_entry_count(); i++) {
        const LiftedEntry *entry = lifted_entry(i);
        if (entry->va == address) {
            return nullptr;
        }
        if (entry->va > address) {
            return previous;
        }
        previous = entry;
    }
    return nullptr;
}

void record_missing(uint64_t target) {
    for (size_t i = 0; i < g_missing_count; i++) {
        if (g_missing_targets[i] == target) {
            return;
        }
    }
    if (g_missing_count < kMaxMissing) {
        g_missing_targets[g_missing_count++] = target;
    }
}

/* Execute the lifted function at *va*. At the top level a return into another
 * lifted function continues the program there; inside a called function the
 * return belongs to the caller's own trace, which resumes by itself, so the loop
 * does not chase it. */
StopReason dispatch_from(uint64_t va, State *state, Memory *memory) {
    const LiftedEntry *entry = lifted_lookup(va);
    if (!entry) {
        record_missing(va);
        g_reason = StopReason::kMissingDispatch;
        g_stop_pc = va;
        std::snprintf(g_detail, sizeof(g_detail), "no lifted function for %#" PRIx64, va);
        return StopReason::kMissingDispatch;
    }
    if (g_depth >= kMaxDispatchDepth) {
        g_reason = StopReason::kError;
        g_stop_pc = va;
        std::snprintf(g_detail, sizeof(g_detail),
                      "dispatch depth %" PRIu64 " exceeded at %#" PRIx64,
                      kMaxDispatchDepth, va);
        return StopReason::kError;
    }

    const bool top_level = (g_depth == 0);
    g_depth++;
    if (g_depth > g_deepest_dispatch) {
        g_deepest_dispatch = g_depth;
    }

    g_functions_entered++;
    StopReason reason = trace_once(entry->function, state, va, memory);
    if (top_level) {
        while (reason == StopReason::kReturned) {
            const LiftedEntry *next = lifted_lookup(g_stop_pc);
            if (!next) {
                /* A return to an address that is not lifted is not the program
                 * finishing: it is the next address to lift. Reporting it as
                 * "returned" and leaving it there is how a run ends silently, and a
                 * driver cannot continue from a silence. Returning to 0 is the one
                 * case that really is the end. */
                if (g_stop_pc != 0) {
                    record_missing(g_stop_pc);
                    std::snprintf(g_detail, sizeof(g_detail),
                                  "return to unlifted address %#" PRIx64, g_stop_pc);
                    reason = StopReason::kMissingDispatch;
                }
                break;
            }
            entry = next;
            va = g_stop_pc;
            g_functions_entered++;
            reason = trace_once(entry->function, state, va, memory);
        }
    }
    g_depth--;
    return reason;
}

uint8_t *mapped(Memory *memory, uint64_t address, uint64_t length) {
    return guest_ptr(memory, address, length);
}

/* Guest memory tracing, off unless the caller asks. When lifted code faults in a
 * way the host cannot report (Wine converts an access violation into a PE
 * exception and takes its own path), the last memory access is the useful clue. */
bool g_trace_memory = false;
bool g_trace_dispatch = false;

void trace_dispatch(const char *format, ...) {
    if (!g_trace_dispatch) {
        return;
    }
    va_list args;
    va_start(args, format);
    std::fputs("dispatch: ", stderr);
    std::vfprintf(stderr, format, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
    va_end(args);
}

template <typename T>
T read_value(Memory *memory, uint64_t address) {
    if (g_trace_memory) {
        std::fprintf(stderr, "mem: read %zu at %#" PRIx64 "\n", sizeof(T), address);
    }
    uint8_t *pointer = mapped(memory, address, sizeof(T));
    if (!pointer) {
        char detail[128];
        std::snprintf(detail, sizeof(detail), "read of unmapped guest address %#" PRIx64
                      " (%zu bytes)", address, sizeof(T));
        halt(StopReason::kError, address, detail);
    }
    T value;
    std::memcpy(&value, pointer, sizeof(T));
    return value;
}

template <typename T>
Memory *write_value(Memory *memory, uint64_t address, T value) {
    if (g_trace_memory) {
        std::fprintf(stderr, "mem: write %zu at %#" PRIx64 " = %#" PRIx64 "\n",
                     sizeof(T), address, (uint64_t)value);
    }
    uint8_t *pointer = mapped(memory, address, sizeof(T));
    if (!pointer) {
        char detail[128];
        std::snprintf(detail, sizeof(detail), "write of unmapped guest address %#" PRIx64
                      " (%zu bytes)", address, sizeof(T));
        halt(StopReason::kError, address, detail);
    }
    std::memcpy(pointer, &value, sizeof(T));
    return memory;
}

/* Copy the current detail before halting: halt writes into the same buffer. */
Memory *propagate(StopReason reason, uint64_t pc) {
    char detail[256];
    std::snprintf(detail, sizeof(detail), "%s", g_detail);
    return halt(reason, pc, detail);
}

/* Remill lowers an atomic compare-exchange to a call into the runtime. The
 * contract is the usual one: on success the store happens and `expected` is left
 * alone, and on failure `expected` receives the observed value, which is how the
 * lifted code learns what was there and sets its flags.
 *
 * The execution model is single-threaded, so there is no contention to model: an
 * exchange either matches immediately or reports what it saw. */
template <typename T>
Memory *compare_exchange(Memory *memory, uint64_t address, T *expected, T desired) {
    T observed = read_value<T>(memory, address);
    if (observed == *expected) {
        write_value<T>(memory, address, desired);
    } else {
        *expected = observed;
    }
    return memory;
}



}  // namespace

uint8_t *guest_ptr(Memory *memory, uint64_t address, uint64_t length) {
    if (!memory) {
        return nullptr;
    }
    uint8_t *image_pointer = static_cast<uint8_t *>(pe_ptr(memory->image, address));
    if (image_pointer) {
        uint64_t offset = address - memory->image->image_base;
        if (offset + length <= memory->image->size_of_image) {
            return image_pointer;
        }
    }
    if (address >= memory->stack_base &&
        address + length <= memory->stack_base + memory->stack_size) {
        return memory->stack + (address - memory->stack_base);
    }
    if (memory->heap_base && address >= memory->heap_base &&
        address + length <= memory->heap_base + memory->heap_size) {
        return (uint8_t *)(uintptr_t)address;
    }
    return nullptr;
}

StopReason lifted_run(lifted_function function, State *state, uint64_t pc,
                      Memory *memory) {
    lifted_reset_stats();
    return trace_once(function, state, pc, memory);
}

StopReason lifted_run_dispatched(uint64_t va, State *state, Memory *memory) {
    lifted_reset_stats();
    return dispatch_from(va, state, memory);
}

void lifted_report_undefined(bool enabled) { g_report_undefined = enabled; }

void lifted_set_imports(import_table *table) {
    g_imports = table;
}

size_t lifted_import_count(void) {
    return g_imports ? g_imports->count : 0;
}

void lifted_set_memory_trace(bool enabled) { g_trace_memory = enabled; }

void lifted_set_dispatch_trace(bool enabled) { g_trace_dispatch = enabled; }

void lifted_reset_stats(void) {
    g_functions_entered = 0;
    g_deepest_dispatch = 0;
    g_depth = 0;
    g_missing_count = 0;
}

uint64_t lifted_functions_entered(void) { return g_functions_entered; }
uint64_t lifted_deepest_dispatch(void) { return g_deepest_dispatch; }

size_t lifted_missing_target_count(void) { return g_missing_count; }

uint64_t lifted_missing_target(size_t index) {
    return index < g_missing_count ? g_missing_targets[index] : 0;
}

extern "C" {

/* Declared here, where the dispatcher that uses it lives, so it has the same
 * linkage as its definition. */
Memory *call_import(State *state, const import_entry *import, Memory *memory);

StopReason lifted_stop_reason(void) { return g_reason; }
uint64_t lifted_stop_pc(void) { return g_stop_pc; }
const char *lifted_stop_detail(void) { return g_detail; }
const char *lifted_stop_reason_name(StopReason reason) { return reason_name(reason); }

/* --- memory ------------------------------------------------------------- */

uint8_t __remill_read_memory_8(Memory *memory, uint64_t address) {
    return read_value<uint8_t>(memory, address);
}
uint16_t __remill_read_memory_16(Memory *memory, uint64_t address) {
    return read_value<uint16_t>(memory, address);
}
uint32_t __remill_read_memory_32(Memory *memory, uint64_t address) {
    return read_value<uint32_t>(memory, address);
}
uint64_t __remill_read_memory_64(Memory *memory, uint64_t address) {
    return read_value<uint64_t>(memory, address);
}
float __remill_read_memory_f32(Memory *memory, uint64_t address) {
    return read_value<float>(memory, address);
}
double __remill_read_memory_f64(Memory *memory, uint64_t address) {
    return read_value<double>(memory, address);
}

Memory *__remill_write_memory_8(Memory *memory, uint64_t address, uint8_t value) {
    return write_value<uint8_t>(memory, address, value);
}
Memory *__remill_write_memory_16(Memory *memory, uint64_t address, uint16_t value) {
    return write_value<uint16_t>(memory, address, value);
}
Memory *__remill_write_memory_32(Memory *memory, uint64_t address, uint32_t value) {
    return write_value<uint32_t>(memory, address, value);
}
Memory *__remill_write_memory_64(Memory *memory, uint64_t address, uint64_t value) {
    return write_value<uint64_t>(memory, address, value);
}
Memory *__remill_write_memory_f32(Memory *memory, uint64_t address, float value) {
    return write_value<float>(memory, address, value);
}
Memory *__remill_write_memory_f64(Memory *memory, uint64_t address, double value) {
    return write_value<double>(memory, address, value);
}

/* --- undefined values ---------------------------------------------------- */

static void undefined_value(const char *width) {
    if (g_report_undefined) {
        std::fprintf(stderr, "lifted runtime: undefined value read (%s)\n", width);
    }
}

uint8_t __remill_undefined_8(void) { undefined_value("8"); return 0; }
uint16_t __remill_undefined_16(void) { undefined_value("16"); return 0; }
uint32_t __remill_undefined_32(void) { undefined_value("32"); return 0; }
uint64_t __remill_undefined_64(void) { undefined_value("64"); return 0; }
float __remill_undefined_f32(void) { undefined_value("f32"); return 0.0f; }
double __remill_undefined_f64(void) { undefined_value("f64"); return 0.0; }

/* --- flags --------------------------------------------------------------- */

/* Remill computes flags through intrinsics that receive the operation's result
 * and its operands. The first argument is the value the flag is derived from, so
 * the identity is correct here and the arithmetic lives in the lifted code. */
bool __remill_flag_computation_carry(bool result, ...) { return result; }
bool __remill_flag_computation_zero(bool result, ...) { return result; }
bool __remill_flag_computation_sign(bool result, ...) { return result; }
bool __remill_flag_computation_overflow(bool result, ...) { return result; }

bool __remill_compare_eq(bool result) { return result; }
bool __remill_compare_neq(bool result) { return result; }
bool __remill_compare_slt(bool result) { return result; }
bool __remill_compare_sle(bool result) { return result; }
bool __remill_compare_sgt(bool result) { return result; }
bool __remill_compare_sge(bool result) { return result; }
bool __remill_compare_ult(bool result) { return result; }
bool __remill_compare_ule(bool result) { return result; }
bool __remill_compare_ugt(bool result) { return result; }
bool __remill_compare_uge(bool result) { return result; }

/* --- control flow -------------------------------------------------------- */

/* Remill's trace calls this at a `ret` and then returns from the LLVM function
 * itself, so this records where control went and returns normally: a direct call
 * chain resolves through the linker, and the caller's lifted code continues on
 * its own. Halting here would abandon callers that are still running. */
/* Call one bound import and leave the guest in the state a real call would.
 *
 * The lifted `call` has already pushed the return address on the guest stack, so
 * the import's own `ret` is emulated by popping it. The result goes to RAX, which is
 * where the Microsoft x64 convention returns an integer or a pointer. */
Memory *call_import(State *state, const import_entry *import, Memory *memory) {
    uint64_t arguments[IMPORT_ARGS];
    arguments[0] = state->gpr.rcx.qword;
    arguments[1] = state->gpr.rdx.qword;
    arguments[2] = state->gpr.r8.qword;
    arguments[3] = state->gpr.r9.qword;

    const uint64_t stack_pointer = state->gpr.rsp.qword;
    for (int i = 4; i < IMPORT_ARGS; i++) {
        /* Above the return address: [rsp+8] is the fifth argument. */
        uint8_t *slot = guest_ptr(memory, stack_pointer + 8 * (i - 3), 8);
        if (!slot) {
            arguments[i] = 0;
            continue;
        }
        uint64_t value = 0;
        std::memcpy(&value, slot, sizeof(value));
        arguments[i] = value;
    }

    if (const thunk_function thunk = find_thunk(import)) {
        const uint64_t thunked = thunk(state, arguments, memory);
        state->gpr.rax.qword = thunked;
        state->gpr.rsp.qword = state->gpr.rsp.qword + 8;
        trace_dispatch("thunk %s returned %#llx", import->name, (unsigned long long)thunked);
        return memory;
    }

    trace_dispatch("import %s!%s%u at %p arg0=%#llx arg1=%#llx", import->dll,
                   import->by_ordinal ? "#" : "", import->by_ordinal ? import->ordinal : 0,
                   (void *)(uintptr_t)import->host_address,
                   (unsigned long long)arguments[0], (unsigned long long)arguments[1]);

    const uint64_t result = call_host_import(import->host_address, arguments);

    state->gpr.rax.qword = result;
    state->gpr.rsp.qword = stack_pointer + 8; /* the callee's ret */
    trace_dispatch("import %s returned %#llx", import->name[0] ? import->name : import->dll,
                   (unsigned long long)result);
    return memory;
}

Memory *__remill_function_return(State &, uint64_t address, Memory *memory) {
    g_reason = StopReason::kReturned;
    g_stop_pc = address;
    std::snprintf(g_detail, sizeof(g_detail), "return to %#" PRIx64, address);
    return memory;
}

Memory *__remill_function_call(State &state, uint64_t target, Memory *memory) {
    if (const import_entry *import = imports_find_host(g_imports, target)) {
        return call_import(&state, import, memory);
    }
    if (!lifted_lookup(target)) {
        record_missing(target);
        char detail[96];
        std::snprintf(detail, sizeof(detail), "call to unlifted address %#" PRIx64,
                      target);
        return halt(StopReason::kFunctionCall, target, detail);
    }
    StopReason reason = dispatch_from(target, &state, memory);
    if (reason == StopReason::kReturned) {
        return memory;             /* the callee returned; the caller continues */
    }
    return propagate(reason, g_stop_pc);
}

Memory *__remill_jump(State &state, uint64_t target, Memory *memory) {
    /* A tail jump into an import: the thunk pattern `jmp qword ptr [IAT]`. The
     * import's return is this frame's return, and the return address the caller
     * pushed is still on the guest stack, which call_import pops. */
    if (const import_entry *import = imports_find_host(g_imports, target)) {
        call_import(&state, import, memory);
        return propagate(StopReason::kReturned, g_stop_pc);
    }
    if (!lifted_lookup(target)) {
        record_missing(target);
        char detail[96];
        std::snprintf(detail, sizeof(detail), "jump to unlifted address %#" PRIx64,
                      target);
        return halt(StopReason::kJump, target, detail);
    }
    StopReason reason = dispatch_from(target, &state, memory);
    if (reason == StopReason::kReturned) {
        /* A tail jump: the target's return is this frame's return. */
        return propagate(StopReason::kReturned, g_stop_pc);
    }
    return propagate(reason, g_stop_pc);
}

Memory *__remill_error(State &, uint64_t address, Memory *) {
    return halt(StopReason::kError, address, "remill error");
}

Memory *__remill_missing_block(State &state, uint64_t address, Memory *memory) {
    /* Remill calls this when control leaves the region it lifted for one function:
     * an indirect jump or a tail call out of the function. That is ordinary
     * cross-function control flow, so continue at the target when it is lifted
     * somewhere else. The case that cannot be continued is a jump into the middle
     * of a lifted function, and it is reported as its own reason so the address can
     * be lifted on its own instead of being mistaken for a missing function. */
    if (lifted_lookup(address)) {
        StopReason reason = dispatch_from(address, &state, memory);
        if (reason == StopReason::kReturned) {
            return propagate(StopReason::kReturned, g_stop_pc);
        }
        return propagate(reason, g_stop_pc);
    }
    if (const LiftedEntry *container = lifted_containing(address)) {
        char detail[128];
        std::snprintf(detail, sizeof(detail),
                      "jump into the middle of %s (interior block %#" PRIx64 ")",
                      container->name, address);
        return halt(StopReason::kMissingBlock, address, detail);
    }
    record_missing(address);
    char detail[96];
    std::snprintf(detail, sizeof(detail), "jump to unlifted address %#" PRIx64, address);
    return halt(StopReason::kMissingBlock, address, detail);
}

/* --- compare and exchange ------------------------------------------------ */

/* The implementation lives with the other memory helpers, above the extern "C"
 * block: a function template cannot have C linkage. See `compare_exchange`. */

Memory *__remill_compare_exchange_memory_8(Memory *memory, uint64_t address,
                                          uint8_t *expected, uint8_t desired) {
    return compare_exchange<uint8_t>(memory, address, expected, desired);
}
Memory *__remill_compare_exchange_memory_16(Memory *memory, uint64_t address,
                                            uint16_t *expected, uint16_t desired) {
    return compare_exchange<uint16_t>(memory, address, expected, desired);
}
Memory *__remill_compare_exchange_memory_32(Memory *memory, uint64_t address,
                                            uint32_t *expected, uint32_t desired) {
    return compare_exchange<uint32_t>(memory, address, expected, desired);
}
Memory *__remill_compare_exchange_memory_64(Memory *memory, uint64_t address,
                                            uint64_t *expected, uint64_t desired) {
    return compare_exchange<uint64_t>(memory, address, expected, desired);
}

/* --- x87 and SSE control ------------------------------------------------ */

/* Remill asks the runtime for the FPU control word state. The runtime keeps one
 * value and reports it back, which is enough for code that saves, changes and
 * restores the control word (what a CRT's _controlfp wrapper does) and honest
 * about what is missing: no floating point exception is ever raised, so
 * __remill_fpu_exception_test always answers that nothing is pending. A target
 * that depends on FP exceptions will need the real thing. */
static int32_t g_fpu_rounding = 0;   /* round to nearest, the x86 reset default */

int32_t __remill_fpu_exception_test(int32_t read_mask) {
    (void)read_mask;
    return 0;
}

void __remill_fpu_exception_clear(int32_t clear_mask) { (void)clear_mask; }
void __remill_fpu_exception_raise(int32_t except_mask) { (void)except_mask; }

void __remill_fpu_set_rounding(int32_t round_mode) { g_fpu_rounding = round_mode; }
int32_t __remill_fpu_get_rounding(void) { return g_fpu_rounding; }

/* --- atomics ------------------------------------------------------------- */

/* Remill brackets atomic instruction sequences with these. The execution model
 * here is single-threaded, so they just pass memory through. When guest threads
 * arrive, this is where a real memory-ordering strategy goes, and until then the
 * limitation belongs in the docs rather than in a silent optimisation. */
Memory *__remill_atomic_begin(Memory *memory) { return memory; }
Memory *__remill_atomic_end(Memory *memory) { return memory; }

/* --- hyper calls --------------------------------------------------------- */

Memory *__remill_sync_hyper_call(State &, Memory *, uint32_t kind) {
    char detail[64];
    std::snprintf(detail, sizeof(detail), "sync hyper call %u", kind);
    return halt(StopReason::kError, 0, detail);
}

Memory *__remill_async_hyper_call(State &, uint64_t address, Memory *) {
    char detail[64];
    std::snprintf(detail, sizeof(detail), "async hyper call at %#" PRIx64, address);
    return halt(StopReason::kError, address, detail);
}

}  // extern "C"

/* --- dispatch table ------------------------------------------------------ */

/* Stubs for call targets that have no lift, at file scope so the symbol is
 * external and can satisfy the lifted code's reference. */
#include "lifted_stubs.inc"

namespace {
#include "lifted_symbols.inc"
}

size_t lifted_entry_count(void) {
    return sizeof(kLiftedEntries) / sizeof(kLiftedEntries[0]);
}

/* Called by generated stubs for call targets that were never lifted. A call to
 * one of these stops the program with the address, which is how an unlifted
 * target reports itself instead of failing to link. */
Memory *lifted_missing_function(State *state, uint64_t pc, Memory *memory) {
    (void)state;
    (void)memory;
    record_missing(pc);
    char detail[96];
    std::snprintf(detail, sizeof(detail), "called unlifted function %#" PRIx64, pc);
    return halt(StopReason::kMissingDispatch, pc, detail);
}

const LiftedEntry *lifted_lookup(uint64_t va) {
    for (size_t i = 0; i < lifted_entry_count(); i++) {
        if (kLiftedEntries[i].va == va) {
            return &kLiftedEntries[i];
        }
    }
    return nullptr;
}

const LiftedEntry *lifted_entry(size_t index) {
    return index < lifted_entry_count() ? &kLiftedEntries[index] : nullptr;
}
