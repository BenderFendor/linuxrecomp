/* Run a Remill-lifted function under the linuxrecomp runtime.
 *
 * The report goes to stderr, not stdout. In a Wine process the first write to
 * stdout blocks indefinitely (the trace lines on stderr get through), which turns
 * a finished run into a hung one; keeping all harness output on stderr avoids
 * depending on which stream Wine's console layer is willing to write.
 *
 * Same command line and same output format as the reference executor
 * (`runtime/linux64/refexec.c`), so a differential test can drive both and
 * compare the two reports field by field:
 *
 *     lifted_harness IMAGE FUNCTION_VA [a b c d] [--poke ADDR=HEX] [--dump ADDR:LEN]
 *
 * The guest state is built the way the target's ABI expects at a function entry:
 * RCX, RDX, R8 and R9 hold the first four integer arguments and RSP points at a
 * return address on a stack region this runtime owns.
 *
 * Known difference from the reference executor: the reference runs on the host
 * stack, so stack addresses and stack contents are not comparable between the
 * two. Image memory is comparable, which is what the differential tests read.
 */
#include "lifted_runtime.h"
#include "host_guest.h"
#include <cinttypes>
#include <cstdarg>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

namespace {


bool g_trace = false;
bool trace_enabled = false;

uint64_t g_guest_base = 0;
uint64_t g_guest_size = 0;

/* A fault while running lifted code would otherwise leave no trace at all: Wine
 * swallows a Unix SIGSEGV before it reaches a debug channel, and the process just
 * exits 139. Reporting the faulting RIP, the address it touched, and a host
 * backtrace is the difference between a five-second diagnosis and guessing. */
void crash_handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
    uint64_t rip = 0;
#if defined(__x86_64__)
    rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
#endif
    uint64_t rsp = 0;
#if defined(__x86_64__)
    rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
#endif
    const char *where = (g_guest_size && rip >= g_guest_base &&
                         rip < g_guest_base + g_guest_size) ? "in guest code" : "in host code";
    char message[512];
    int length = std::snprintf(message, sizeof(message),
                               "lifted: fault %d at rip=%#" PRIx64 " address=%#" PRIx64
                               " rsp=%#" PRIx64 " (%s)\n",
                               sig, rip, (uint64_t)(uintptr_t)info->si_addr, rsp, where);
    ssize_t ignored = write(STDERR_FILENO, message, (size_t)length);
    (void)ignored;

    /* Name the module the faulting address belongs to. Raw calls only: this runs
     * in a signal handler. */
    {
        int fd = open("/proc/self/maps", O_RDONLY);
        if (fd >= 0) {
            static char maps[512 * 1024];
            ssize_t got = read(fd, maps, sizeof(maps) - 1);
            close(fd);
            if (got > 0) {
                maps[got] = '\0';
                for (char *line = maps; line && *line; ) {
                    char *end = std::strchr(line, '\n');
                    unsigned long long low = 0;
                    unsigned long long high = 0;
                    if (end) {
                        *end = '\0';
                    }
                    if (std::sscanf(line, "%llx-%llx", &low, &high) == 2 && rip >= low &&
                        rip < high) {
                        const char prefix[] = "lifted:   rip is in ";
                        ignored = write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
                        char offset[64];
                        int n = std::snprintf(offset, sizeof(offset), "%s + %#llx :: ",
                                              line, rip - low);
                        ignored = write(STDERR_FILENO, offset, (size_t)n);
                        ignored = write(STDERR_FILENO, "\n", 1);
                        break;
                    }
                    line = end ? end + 1 : nullptr;
                }
            }
        }
    }

    /* Bytes around the faulting instruction: in a host-side fault, what the
     * writer is doing is the whole diagnosis. This is what identified a
     * context-save routine being handed the runtime's memory descriptor as its
     * destination (see docs/agents/traces/wine-host-guest-execution.md). */
    if (rip >= 16) {
        const unsigned char *code = (const unsigned char *)(uintptr_t)(rip - 16);
        static const char digits[] = "0123456789abcdef";
        char dump[3 * 48 + 8];
        int n = 0;
        dump[n++] = 'l';
        dump[n++] = ':';
        dump[n++] = ' ';
        for (int i = 0; i < 48; i++) {
            unsigned char byte = code[i];
            dump[n++] = digits[byte >> 4];
            dump[n++] = digits[byte & 0xf];
            dump[n++] = (i == 15) ? '|' : ' ';
        }
        dump[n++] = '\n';
        ignored = write(STDERR_FILENO, dump, (size_t)n);
        (void)ignored;
    }

    /* Return addresses at the faulting stack pointer name the caller. */
    if (rsp) {
        const uint64_t *stack_words = (const uint64_t *)(uintptr_t)rsp;
        static const char digits[] = "0123456789abcdef";
        char out[256];
        int n = 0;
        out[n++] = 's';
        out[n++] = ':';
        for (int i = 0; i < 6; i++) {
            out[n++] = ' ';
            uint64_t value = stack_words[i];
            char hex[17];
            for (int d = 0; d < 16; d++) {
                hex[d] = digits[(value >> ((15 - d) * 4)) & 0xf];
            }
            for (int d = 0; d < 16; d++) {
                out[n++] = hex[d];
            }
        }
        out[n++] = '\n';
        ignored = write(STDERR_FILENO, out, (size_t)n);
        (void)ignored;

    }

    void *frames[32];
    int count = backtrace(frames, 32);
    backtrace_symbols_fd(frames, count, STDERR_FILENO);
    _exit(3);
}

/* Which /proc/self/maps entry holds *address*, and how much room is left below
 * it. Under Wine the code runs on a PE stack that is not the pthread stack, and
 * its size is what an immediate crash tends to be about. */
void trace(const char *format, ...);


/* Guest execution runs on a thread with its own large stack.
 *
 * Wine runs a winelib module's `main` on the PE stack it allocated for the
 * module, which is 1 MiB by default, and by the time our lifted code's prologue
 * runs its allocas there are only a few hundred bytes of that stack left. The
 * result is an immediate access violation inside the first lifted function, which
 * took a while to identify because it looks nothing like a stack problem.
 *
 * The guest's own stack is a separate region this runtime owns, so the host stack
 * here only holds the trace machinery: remaining C++ frames, the dispatch
 * recursion, and one frame per nested call. 64 MiB removes the question.
 */
constexpr size_t kExecutionStackSize = 64u * 1024 * 1024;

struct ExecutionJob {
    const LiftedEntry *entry;
    uint64_t entry_va;
    State *state;
    Memory *memory;
    StopReason reason   = StopReason::kReturned;
    uint64_t result     = 0;
    uint64_t entered    = 0;
    uint64_t deepest    = 0;
    size_t missing      = 0;
};


void *run_guest(void *argument) {
    auto *job = static_cast<ExecutionJob *>(argument);
    trace("running %s on a %zu MiB stack", job->entry->name,
          kExecutionStackSize / (1024 * 1024));
    job->reason = lifted_run_dispatched(job->entry_va, job->state, job->memory);
    job->result = job->state->gpr.rax.qword;
    job->entered = lifted_functions_entered();
    job->deepest = lifted_deepest_dispatch();
    job->missing = lifted_missing_target_count();
    return nullptr;
}

void trace(const char *format, ...) {
    if (!g_trace) {
        return;
    }
    va_list args;
    va_start(args, format);
    std::fputs("trace: ", stderr);
    std::vfprintf(stderr, format, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
    va_end(args);
}

constexpr uint64_t kStackSize = 0x100000;      /* 1 MiB */
/* One reserved block for the memory descriptor and the guest register file. */
constexpr uint64_t kStateSize = 0x100000;      /* 1 MiB */
constexpr uint64_t kPageSize = 0x1000;         /* the descriptor gets its own page */
/* Space above RSP for the 32-byte home area the Microsoft ABI reserves, plus the
 * extra 8 that puts the entry RSP at 8 mod 16, where a callee expects to start.
 * The reference executor uses the same shape. */
constexpr uint64_t kStackHeadroom = 0x1008;

int parse_u64(const char *text, uint64_t *out) {
    char *end = nullptr;
    unsigned long long value = strtoull(text, &end, 0);
    if (end == text || (end && *end != '\0')) {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int apply_poke(Memory *memory, const char *spec) {
    char *copy = strdup(spec);
    if (!copy) {
        return -1;
    }
    char *equals = strchr(copy, '=');
    if (!equals) {
        free(copy);
        return -1;
    }
    *equals = '\0';
    const char *hex = equals + 1;
    uint64_t address = 0;
    if (parse_u64(copy, &address) != 0) {
        free(copy);
        return -1;
    }
    size_t length = strlen(hex);
    if (length % 2 != 0) {
        free(copy);
        return -1;
    }
    for (size_t i = 0; i < length; i += 2) {
        int high = hex_nibble(hex[i]);
        int low = hex_nibble(hex[i + 1]);
        uint8_t *pointer = (high < 0 || low < 0) ? nullptr
                                                 : guest_ptr(memory, address + i / 2, 1);
        if (!pointer) {
            std::fprintf(stderr, "lifted: poke target %#" PRIx64 " is not mapped\n",
                         address + i / 2);
            free(copy);
            return -1;
        }
        *pointer = (uint8_t)((high << 4) | low);
    }
    free(copy);
    return 0;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "usage: %s IMAGE FUNCTION_VA [a] [b] [c] [d]\n"
                     "       %s IMAGE FUNCTION_VA [a b c d] [--poke ADDR=HEXBYTES] "
                     "[--dump ADDR:LEN]\n",
                     argv[0], argv[0]);
        return 1;
    }

    const char *path = argv[1];
    uint64_t function_va = 0;
    if (parse_u64(argv[2], &function_va) != 0) {
        std::fprintf(stderr, "lifted: bad function address %s\n", argv[2]);
        return 1;
    }

    uint64_t args[4] = {0, 0, 0, 0};
    const char *pokes[16];
    int poke_count = 0;
    uint64_t dump_addr[16];
    uint64_t dump_len[16];
    int dump_count = 0;
    bool report_undefined = false;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--poke") == 0 && i + 1 < argc) {
            if (poke_count >= 16) {
                std::fprintf(stderr, "lifted: too many --poke options\n");
                return 1;
            }
            pokes[poke_count++] = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--dump") == 0 && i + 1 < argc) {
            if (dump_count >= 16) {
                std::fprintf(stderr, "lifted: too many --dump options\n");
                return 1;
            }
            char *spec = argv[++i];
            char *colon = strchr(spec, ':');
            if (!colon) {
                std::fprintf(stderr, "lifted: --dump wants ADDR:LEN\n");
                return 1;
            }
            *colon = '\0';
            if (parse_u64(spec, &dump_addr[dump_count]) != 0 ||
                parse_u64(colon + 1, &dump_len[dump_count]) != 0) {
                std::fprintf(stderr, "lifted: bad --dump spec\n");
                return 1;
            }
            dump_count++;
            continue;
        }
        if (strcmp(argv[i], "--report-undefined") == 0) {
            report_undefined = true;
            continue;
        }
        if (strcmp(argv[i], "--trace") == 0) {
            g_trace = true;
            trace_enabled = true;
            continue;
        }
        if (i - 3 < 4 && parse_u64(argv[i], &args[i - 3]) != 0) {
            std::fprintf(stderr, "lifted: bad argument %s\n", argv[i]);
            return 1;
        }
    }

    char err[512];
    pe_image image;
    trace("mapping %s", path);
    if (pe_map(path, &image, err, sizeof(err)) != 0) {
        std::fprintf(stderr, "lifted: %s\n", err);
        return 1;
    }

    trace("image mapped at %#" PRIx64 " size %#" PRIx64 ", entry %#" PRIx64,
          image.image_base, image.size_of_image, image.image_base + image.entry_rva);
    trace("reserving the guest stack");
    /* Address 0: the host picks. Only the guest image is address-bound, because
     * only the image's address is something the guest itself depends on. */
    void *stack = pe_reserve(0, kStackSize);
    if (!stack) {
        std::fprintf(stderr, "lifted: cannot map a guest stack (errno %d)\n", errno);
        pe_unmap(&image);
        return 1;
    }
    const uint64_t stack_base = (uint64_t)(uintptr_t)stack;

    trace("guest stack mapped at %p, entry rsp %#" PRIx64, stack,
          stack_base + kStackSize - kStackHeadroom);
    /* The guest state and its memory descriptor come from the host's allocator,
     * not from the heap and not from this frame. In a Wine process glibc's heap
     * and this frame are both invisible to Wine, which can hand the same
     * addresses to its own allocator; memory the runtime keeps for the whole run
     * has to be memory Wine knows about. */
    void *state_block = pe_reserve(0, kStateSize + kPageSize);
    if (!state_block) {
        std::fprintf(stderr, "lifted: cannot reserve the guest state block\n");
        pe_release(stack, kStackSize);
        pe_unmap(&image);
        return 1;
    }
    /* The descriptor gets a page of its own, aligned, so the guard below covers
     * exactly the descriptor and nothing the runtime legitimately writes. */
    const uintptr_t block = (uintptr_t)state_block;
    uint8_t *descriptor_page =
        (uint8_t *)((block + kPageSize - 1) & ~(uintptr_t)(kPageSize - 1));
    Memory &memory = *reinterpret_cast<Memory *>(descriptor_page);
    memory.image = &image;
    memory.stack = (uint8_t *)stack;
    memory.stack_base = stack_base;
    memory.stack_size = kStackSize;
    lifted_report_undefined(report_undefined);
    lifted_set_memory_trace(report_undefined);
    lifted_set_dispatch_trace(trace_enabled);

    for (int i = 0; i < poke_count; i++) {
        if (apply_poke(&memory, pokes[i]) != 0) {
            std::fprintf(stderr, "lifted: bad --poke %s\n", pokes[i]);
            pe_release(stack, kStackSize);
            pe_unmap(&image);
            return 1;
        }
    }

    {
        pthread_attr_t attributes;
        void *stack_base = nullptr;
        size_t stack_size = 0;
        if (pthread_getattr_np(pthread_self(), &attributes) == 0) {
            pthread_attr_getstack(&attributes, &stack_base, &stack_size);
            pthread_attr_destroy(&attributes);
        }
        trace("pthread stack %p..%p (%zu bytes), current frame %p", stack_base,
              static_cast<char *>(stack_base) + stack_size, stack_size,
              __builtin_frame_address(0));
    }
    trace("looking up %#" PRIx64 " among %zu lifted functions", function_va,
          lifted_entry_count());

    if (getenv("LINUXRECOMP_GUARD_MEMORY")) {
        if (pe_protect(descriptor_page, kPageSize, PE_PROT_READ) != 0) {
            std::fprintf(stderr, "lifted: cannot guard the memory descriptor\n");
            return 1;
        }
        trace("memory descriptor guarded read-only at %p", descriptor_page);
    }

    struct sigaction action;
    std::memset(&action, 0, sizeof(action));
    action.sa_sigaction = crash_handler;
    /* SA_ONSTACK: a fault whose own stack is unusable can only be reported on
     * another stack, which is also what Wine's handlers do. */
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGSEGV, &action, nullptr);
    sigaction(SIGBUS, &action, nullptr);
    sigaction(SIGILL, &action, nullptr);
    sigaction(SIGFPE, &action, nullptr);
    {
        static char alternate[64 * 1024];
        stack_t alt;
        std::memset(&alt, 0, sizeof(alt));
        alt.ss_sp = alternate;
        alt.ss_size = sizeof(alternate);
        sigaltstack(&alt, nullptr);
    }
    g_guest_base = image.image_base;
    g_guest_size = image.size_of_image;

    const LiftedEntry *entry = lifted_lookup(function_va);
    if (!entry) {
        std::fprintf(stderr,
                     "lifted: no lifted function for %#" PRIx64 " (built with %zu)\n",
                     function_va, lifted_entry_count());
        for (size_t i = 0; i < lifted_entry_count(); i++) {
            const LiftedEntry *available = lifted_entry(i);
            std::fprintf(stderr, "lifted:   available %s at %#" PRIx64 "\n",
                         available->name, available->va);
        }
        pe_release(stack, kStackSize);
        pe_unmap(&image);
        return 3;
    }

    if (sizeof(State) > kStateSize) {
        std::fprintf(stderr, "lifted: State (%zu bytes) does not fit the reserved block\n",
                     sizeof(State));
        pe_release(stack, kStackSize);
        pe_unmap(&image);
        return 1;
    }
    State &state = *reinterpret_cast<State *>(descriptor_page + kPageSize);
    std::memset(&state, 0, sizeof(state));
    state.gpr.rcx.qword = args[0];
    state.gpr.rdx.qword = args[1];
    state.gpr.r8.qword = args[2];
    state.gpr.r9.qword = args[3];
    const uint64_t stack_top = stack_base + kStackSize;
    /* Leave room above RSP for the 32-byte home space the Microsoft ABI reserves
     * for the caller, which a function may read. Without the headroom those reads
     * land past the region and stop the trace for a reason that has nothing to do
     * with the function being tested. */
    state.gpr.rsp.qword = stack_top - kStackHeadroom;
    uint64_t *return_slot = (uint64_t *)guest_ptr(&memory, stack_top - kStackHeadroom, 8);
    if (return_slot) {
        *return_slot = 0;
    }

    ExecutionJob job{};
    job.entry = entry;
    job.entry_va = function_va;
    job.state = &state;
    job.memory = &memory;

    trace("entering %s", entry->name);
    if (host_run_guest(run_guest, &job, kExecutionStackSize) != 0) {
        std::fprintf(stderr, "lifted: cannot start the execution thread\n");
        pe_release(stack, kStackSize);
        pe_unmap(&image);
        return 1;
    }

    StopReason reason = job.reason;
    trace("returned from %s with %s", entry->name, lifted_stop_reason_name(reason));

    trace("looking up the section name");
    const char *section = pe_section_name(&image, function_va);
    trace("printing the report");
    std::fprintf(stderr, "lifted: image=%s base=%#" PRIx64 " section=%s symbol=%s va=%#" PRIx64
                " args=%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64
                " result=%#" PRIx64 " result_dec=%" PRIu64 "\n",
                path, image.image_base, section ? section : "?", entry->name,
                function_va, args[0], args[1], args[2], args[3],
                job.result, job.result);
    trace("printing the stop line");
    std::fprintf(stderr, "lifted: stop %s at %#" PRIx64 " (%s)\n",
                lifted_stop_reason_name(reason), lifted_stop_pc(), lifted_stop_detail());
    std::fprintf(stderr, "lifted: entered=%" PRIu64 " deepest=%" PRIu64 " missing=%zu\n",
                job.entered, job.deepest, job.missing);
    for (size_t i = 0; i < lifted_missing_target_count(); i++) {
        std::fprintf(stderr, "lifted: unresolved %#" PRIx64 "\n", lifted_missing_target(i));
    }

    for (int i = 0; i < dump_count; i++) {
        std::fprintf(stderr, "lifted: memory %#" PRIx64 "+%" PRIu64 " =", dump_addr[i],
                    dump_len[i]);
        for (uint64_t offset = 0; offset < dump_len[i]; offset++) {
            uint8_t *pointer = guest_ptr(&memory, dump_addr[i] + offset, 1);
            std::fprintf(stderr, " %02x", pointer ? *pointer : 0);
        }
        std::fprintf(stderr, "\n");
    }

    std::fflush(stderr);
    trace("exiting with %s", reason == StopReason::kReturned ? "0" : "4");
    pe_release(stack, kStackSize);
    pe_unmap(&image);
    /* Exit directly. Once guest execution has happened in a Wine process, the
     * normal return from main can sit in Wine's teardown indefinitely, which
     * turns a finished test into a hung one. Everything observable is flushed
     * first, so nothing is lost by skipping that teardown. */
    std::fflush(nullptr);
    _exit(reason == StopReason::kReturned ? 0 : 4);
}
