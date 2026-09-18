/* The `__remill_*` runtime that Remill's lifted code calls into.
 *
 * Remill emits traces that take (State *, pc, Memory *) and leaves every memory
 * access, flag computation and control-flow boundary to the consumer. This file
 * is that consumer for the linuxrecomp runtime.
 *
 * Two decisions worth knowing about:
 *
 * 1. Guest memory is the image mapped at its own base plus a stack region the
 *    runtime allocates. A read or write outside both halts the trace and reports
 *    the address, because "the lifted code touched memory we do not model" is a
 *    fact a caller needs, not something to paper over with a zero.
 *
 * 2. Control flow that leaves the lifted bytes halts instead of guessing. A
 *    `call`, `jmp` or `ret` out of the traced range records its target and
 *    returns to the caller, which is where the P3 dispatcher plugs in.
 */
#include "lifted_runtime.h"

#include <cinttypes>
#include <csetjmp>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

jmp_buf g_stop_jump;
bool g_stop_armed = false;

StopReason g_reason = StopReason::kReturned;
uint64_t g_stop_pc = 0;
char g_detail[256];

/* Remill marks values it cannot know (uninitialised registers, undefined
 * instruction results). This runtime answers zero and reports them when asked,
 * rather than pretending the value was defined. */
bool g_report_undefined = false;

Memory *halt(StopReason reason, uint64_t pc, const char *detail) {
    g_reason = reason;
    g_stop_pc = pc;
    std::snprintf(g_detail, sizeof(g_detail), "%s", detail ? detail : "");
    if (g_stop_armed) {
        g_stop_armed = false;
        longjmp(g_stop_jump, 1);
    }
    std::fprintf(stderr,
                 "lifted runtime: %s at pc=%#llx%s%s outside a lifted_run call\n",
                 detail ? detail : "halt", (unsigned long long)pc,
                 g_detail[0] ? " (" : "", g_detail[0] ? g_detail : "");
    std::abort();
}

const char *reason_name(StopReason reason) {
    switch (reason) {
        case StopReason::kReturned: return "returned";
        case StopReason::kError: return "error";
        case StopReason::kFunctionCall: return "call";
        case StopReason::kJump: return "jump";
        case StopReason::kMissingDispatch: return "missing-dispatch";
    }
    return "unknown";
}

uint8_t *mapped(Memory *memory, uint64_t address, uint64_t length) {
    uint8_t *pointer = guest_ptr(memory, address, length);
    return pointer;
}

template <typename T>
T read_value(Memory *memory, uint64_t address) {
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
    return nullptr;
}

StopReason lifted_run(lifted_function function, State *state, uint64_t pc,
                      Memory *memory) {
    g_reason = StopReason::kReturned;
    g_stop_pc = 0;
    g_detail[0] = '\0';
    if (setjmp(g_stop_jump) == 0) {
        g_stop_armed = true;
        function(state, pc, memory);
        g_stop_armed = false;
    }
    return g_reason;
}

void lifted_report_undefined(bool enabled) { g_report_undefined = enabled; }

extern "C" {

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
 * and its operands. The result is the value the flag is derived from, so the
 * identity is correct here and the arithmetic that produced it lives in the
 * lifted code. */
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

Memory *__remill_function_return(State &, uint64_t address, Memory *) {
    char detail[64];
    std::snprintf(detail, sizeof(detail), "return to %#" PRIx64, address);
    return halt(StopReason::kReturned, address, detail);
}

Memory *__remill_function_call(State &, uint64_t address, Memory *) {
    char detail[64];
    std::snprintf(detail, sizeof(detail), "call to %#" PRIx64, address);
    return halt(StopReason::kFunctionCall, address, detail);
}

Memory *__remill_jump(State &, uint64_t address, Memory *) {
    char detail[64];
    std::snprintf(detail, sizeof(detail), "jump to %#" PRIx64, address);
    return halt(StopReason::kJump, address, detail);
}

Memory *__remill_error(State &, uint64_t address, Memory *) {
    return halt(StopReason::kError, address, "remill error");
}

Memory *__remill_missing_block(State &, uint64_t address, Memory *) {
    return halt(StopReason::kError, address, "missing lifted block");
}

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

namespace {
#include "lifted_symbols.inc"
}

size_t lifted_entry_count(void) {
    return sizeof(kLiftedEntries) / sizeof(kLiftedEntries[0]);
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
