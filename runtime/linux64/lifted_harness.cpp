/* Run a Remill-lifted function under the linuxrecomp runtime.
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

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>

namespace {

constexpr uint64_t kStackBase = 0x200000;      /* well below the image bases we map */
constexpr uint64_t kStackSize = 0x100000;      /* 1 MiB */
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
        if (i - 3 < 4 && parse_u64(argv[i], &args[i - 3]) != 0) {
            std::fprintf(stderr, "lifted: bad argument %s\n", argv[i]);
            return 1;
        }
    }

    char err[512];
    pe_image image;
    if (pe_map(path, &image, err, sizeof(err)) != 0) {
        std::fprintf(stderr, "lifted: %s\n", err);
        return 1;
    }

    void *stack = mmap((void *)(uintptr_t)kStackBase, kStackSize,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (stack == MAP_FAILED) {
        std::fprintf(stderr, "lifted: cannot map the guest stack at %#" PRIx64 "\n",
                     kStackBase);
        pe_unmap(&image);
        return 1;
    }

    Memory memory{};
    memory.image = &image;
    memory.stack = (uint8_t *)stack;
    memory.stack_base = kStackBase;
    memory.stack_size = kStackSize;
    lifted_report_undefined(report_undefined);

    for (int i = 0; i < poke_count; i++) {
        if (apply_poke(&memory, pokes[i]) != 0) {
            std::fprintf(stderr, "lifted: bad --poke %s\n", pokes[i]);
            munmap(stack, kStackSize);
            pe_unmap(&image);
            return 1;
        }
    }

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
        munmap(stack, kStackSize);
        pe_unmap(&image);
        return 3;
    }

    State state;
    std::memset(&state, 0, sizeof(state));
    state.gpr.rcx.qword = args[0];
    state.gpr.rdx.qword = args[1];
    state.gpr.r8.qword = args[2];
    state.gpr.r9.qword = args[3];
    const uint64_t stack_top = kStackBase + kStackSize;
    /* Leave room above RSP for the 32-byte home space the Microsoft ABI reserves
     * for the caller, which a function may read. Without the headroom those reads
     * land past the region and stop the trace for a reason that has nothing to do
     * with the function being tested. */
    state.gpr.rsp.qword = stack_top - kStackHeadroom;
    uint64_t *return_slot = (uint64_t *)guest_ptr(&memory, stack_top - kStackHeadroom, 8);
    if (return_slot) {
        *return_slot = 0;
    }

    StopReason reason = lifted_run_dispatched(function_va, &state, &memory);

    const char *section = pe_section_name(&image, function_va);
    std::printf("lifted: image=%s base=%#" PRIx64 " section=%s symbol=%s va=%#" PRIx64
                " args=%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64
                " result=%#" PRIx64 " result_dec=%" PRIu64 "\n",
                path, image.image_base, section ? section : "?", entry->name,
                function_va, args[0], args[1], args[2], args[3],
                state.gpr.rax.qword, state.gpr.rax.qword);
    std::printf("lifted: stop %s at %#" PRIx64 " (%s)\n",
                lifted_stop_reason_name(reason), lifted_stop_pc(), lifted_stop_detail());
    std::printf("lifted: entered=%" PRIu64 " deepest=%" PRIu64 " missing=%zu\n",
                lifted_functions_entered(), lifted_deepest_dispatch(),
                lifted_missing_target_count());
    for (size_t i = 0; i < lifted_missing_target_count(); i++) {
        std::printf("lifted: unresolved %#" PRIx64 "\n", lifted_missing_target(i));
    }

    for (int i = 0; i < dump_count; i++) {
        std::printf("lifted: memory %#" PRIx64 "+%" PRIu64 " =", dump_addr[i],
                    dump_len[i]);
        for (uint64_t offset = 0; offset < dump_len[i]; offset++) {
            uint8_t *pointer = guest_ptr(&memory, dump_addr[i] + offset, 1);
            std::printf(" %02x", pointer ? *pointer : 0);
        }
        std::printf("\n");
    }

    munmap(stack, kStackSize);
    pe_unmap(&image);
    return reason == StopReason::kReturned ? 0 : 4;
}
