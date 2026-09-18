/* Call one function from a PE32+ image on the real CPU.
 *
 * The guest's own machine code is x86-64, so once the image is mapped at its
 * preferred base (see image_pe64.c) a function can be called directly. That
 * gives the project a reference execution for differential tests with no
 * emulator and no dependency to install: the oracle is the CPU running the
 * original bytes.
 *
 * Arguments use the Microsoft x64 convention (rcx, rdx, r8, r9) through the
 * ms_abi attribute, so the call matches what the guest expects. Integer
 * arguments only for now; a function taking floats or vectors needs the
 * matching prototypes, which arrives when a target needs it.
 *
 * Usage:
 *   refexec IMAGE FUNCTION_VA [a] [b] [c] [d]      call and print the result
 *   refexec --dump IMAGE VA [a b c d] ADDR:LEN     also dump guest memory
 *   refexec --poke ADDR=HEXBYTES IMAGE VA ...      write guest memory first
 *
 * Exit codes: 0 success, 1 usage or mapping error, 2 the guest faulted.
 */
#define _GNU_SOURCE
#include "image_pe64.h"

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

/* Set while a guest function is running, so a fault can say whether it happened
 * in guest code or in the harness itself. A crash report that cannot make that
 * distinction is not much use. */
static uint64_t g_image_base = 0;
static uint64_t g_image_size = 0;

typedef uint64_t(__attribute__((ms_abi)) * ms_fn_u64)(uint64_t, uint64_t, uint64_t,
                                                      uint64_t);

/* Guest stack shape, shared with the lifted harness so both executors hand the
 * function the same stack: same addresses, same zeroed contents.
 *
 * The reference executor runs the guest function on the host stack by default.
 * That is fine for a function that only touches registers, and wrong for a
 * function that reads its caller's stack frame or the ABI's home space, because
 * then the two executors see different memory and a difference in results says
 * nothing about the lifter. Switching RSP to the same guest region removes that
 * source of noise.
 */
#define GUEST_STACK_BASE 0x200000
#define GUEST_STACK_SIZE 0x100000
/* 0x1008 keeps the entry RSP at 8 mod 16, which is where the Microsoft ABI says
 * a callee starts: the caller's `call` has pushed its return address onto a
 * 16-byte-aligned stack. A misaligned entry makes a function that spills with an
 * aligned SSE store fault in the reference and quietly succeed in the lifted
 * code, which would read as a lifter bug. */
#define GUEST_STACK_HEADROOM 0x1008

/* Call a Microsoft-ABI function with RSP switched to *sp* and a register state
 * that matches what the lifted harness sets up.
 *
 * System V argument order on entry: rdi = function, rsi = stack pointer,
 * rdx/rcx/r8/r9 = the four guest arguments.
 *
 * Three things matter here, and all three are about making the two executors
 * comparable rather than about the call itself:
 *
 *   - the guest arguments are reshuffled into the Microsoft order (rcx, rdx,
 *     r8, r9); r8 and r9 are already in place, rcx and rdx are not;
 *   - every other general register is zeroed and the flags are cleared, because
 *     the lifted harness starts from a zeroed State. Without this a function
 *     that returns without defining a register hands back whatever this helper
 *     left there, and the differential test reports a divergence that is an
 *     artefact of the test. HLExtract's 0x1400055D0 is exactly that case: its
 *     zero-argument path is a bare `ret`, and the reference used to return the
 *     function pointer this helper had left in RAX;
 *   - the guest enters through `jmp` with the return address already in its
 *     stack slot, not through `call`, so RSP at entry and the return slot are
 *     both under our control.
 *
 * The entry point and stack pointer live in frame slots rather than registers
 * because every register has to be zero for the guest. The first version kept
 * them in registers saved on the stack, and the save pushes then overwrote those
 * slots, so the call went through a zeroed register. An isolated probe of this
 * helper caught it, and the fault report now prints the guest RIP and address,
 * which is what made it visible.
 *
 * The one value that cannot match the harness is the return-address slot itself:
 * it holds a real host address here and a zero there.
 */
__attribute__((naked)) static uint64_t call_on_guest_stack(void *function, uint64_t sp,
                                                           uint64_t a0, uint64_t a1,
                                                           uint64_t a2, uint64_t a3) {
    __asm__ volatile(
        "pushq %rbp\n\t"
        "movq %rsp, %rbp\n\t"
        "pushq %rbx\n\t"                 /* saved registers occupy rbp-8 .. rbp-56 */
        "pushq %rsi\n\t"
        "pushq %rdi\n\t"
        "pushq %r12\n\t"
        "pushq %r13\n\t"
        "pushq %r14\n\t"
        "pushq %r15\n\t"
        "subq $16, %rsp\n\t"             /* scratch below the saves */
        "movq %rdi, -64(%rbp)\n\t"       /* guest entry point */
        "movq %rsi, -72(%rbp)\n\t"       /* guest stack pointer */
        "movq %rcx, %rax\n\t"            /* a1 out of the way */
        "movq %rdx, %rcx\n\t"            /* a0 -> rcx */
        "movq %rax, %rdx\n\t"            /* a1 -> rdx */
        "xorl %ebx, %ebx\n\t"
        "xorl %esi, %esi\n\t"
        "xorl %edi, %edi\n\t"
        "xorl %eax, %eax\n\t"
        "xorl %r10d, %r10d\n\t"
        "xorl %r11d, %r11d\n\t"
        "xorl %r12d, %r12d\n\t"
        "xorl %r13d, %r13d\n\t"
        "xorl %r14d, %r14d\n\t"
        "xorl %r15d, %r15d\n\t"
        "pushq $2\n\t"                   /* RFLAGS bit 1 is always set */
        "popfq\n\t"                      /* CF, PF, AF, ZF, SF, OF all clear */
        "movq -72(%rbp), %rsp\n\t"       /* switch to the guest stack */
        "leaq 1f(%rip), %rax\n\t"
        "movq %rax, (%rsp)\n\t"          /* the guest's return address */
        "xorl %eax, %eax\n\t"            /* rax = 0 at entry, like the lifted State */
        "jmp *-64(%rbp)\n\t"             /* enter the guest, no register needed */
        "1:\n\t"
        "leaq -56(%rbp), %rsp\n\t"       /* back to the host stack, saved registers */
        "popq %r15\n\t"
        "popq %r14\n\t"
        "popq %r13\n\t"
        "popq %r12\n\t"
        "popq %rdi\n\t"
        "popq %rsi\n\t"
        "popq %rbx\n\t"
        "popq %rbp\n\t"
        "ret\n\t");
}

static void fault_handler(int sig, siginfo_t *info, void *context) {
    static char message[512];
    ucontext_t *uc = (ucontext_t *)context;
    uint64_t rip = 0;
#if defined(__x86_64__)
    rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
#endif
    const char *where = "in the harness";
    if (g_image_size && rip >= g_image_base && rip < g_image_base + g_image_size) {
        where = "in guest code";
    }
    int length = snprintf(message, sizeof(message),
                          "refexec: guest faulted with signal %d at rip=%#" PRIx64
                          " address=%#" PRIx64 " (%s)\n",
                          sig, rip, (uint64_t)(uintptr_t)info->si_addr, where);
    ssize_t ignored = write(STDERR_FILENO, message, (size_t)length);
    (void)ignored;
    _exit(2);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 0);
    if (end == text || (end && *end != '\0')) {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

/* --poke ADDR=HEXBYTES: place bytes in guest memory before the call, so a
 * function that reads data can be given the input its disassembly expects. */
static int apply_poke(pe_image *image, const char *spec) {
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
        if (high < 0 || low < 0) {
            free(copy);
            return -1;
        }
        void *pointer = pe_ptr(image, address + i / 2);
        if (!pointer) {
            fprintf(stderr, "refexec: poke target %#" PRIx64 " is outside the image\n",
                    address + i / 2);
            free(copy);
            return -1;
        }
        *(uint8_t *)pointer = (uint8_t)((high << 4) | low);
    }
    free(copy);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s IMAGE FUNCTION_VA [a] [b] [c] [d]\n"
                "       %s IMAGE FUNCTION_VA [a b c d] [--dump ADDR:LEN] "
                "[--poke ADDR=HEXBYTES]\n",
                argv[0], argv[0]);
        return 1;
    }

    const char *path = argv[1];
    uint64_t function_va = 0;
    if (parse_u64(argv[2], &function_va) != 0) {
        fprintf(stderr, "refexec: bad function address %s\n", argv[2]);
        return 1;
    }

    uint64_t args[4] = {0, 0, 0, 0};
    const char *pokes[16];
    int poke_count = 0;
    uint64_t dump_addr[16];
    uint64_t dump_len[16];
    int dump_count = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--dump") == 0 && i + 1 < argc) {
            if (dump_count >= 16) {
                fprintf(stderr, "refexec: too many --dump options\n");
                return 1;
            }
            char *spec = argv[++i];
            char *colon = strchr(spec, ':');
            if (!colon) {
                fprintf(stderr, "refexec: --dump wants ADDR:LEN\n");
                return 1;
            }
            *colon = '\0';
            if (parse_u64(spec, &dump_addr[dump_count]) != 0 ||
                parse_u64(colon + 1, &dump_len[dump_count]) != 0) {
                fprintf(stderr, "refexec: bad --dump spec\n");
                return 1;
            }
            dump_count++;
            continue;
        }
        if (strcmp(argv[i], "--poke") == 0 && i + 1 < argc) {
            if (poke_count >= 16) {
                fprintf(stderr, "refexec: too many --poke options\n");
                return 1;
            }
            pokes[poke_count++] = argv[++i];
            continue;
        }
        if (i - 3 < 4 && parse_u64(argv[i], &args[i - 3]) != 0) {
            fprintf(stderr, "refexec: bad argument %s\n", argv[i]);
            return 1;
        }
    }

    char err[512];
    pe_image image;
    if (pe_map(path, &image, err, sizeof(err)) != 0) {
        fprintf(stderr, "refexec: %s\n", err);
        return 1;
    }

    for (int i = 0; i < poke_count; i++) {
        if (apply_poke(&image, pokes[i]) != 0) {
            fprintf(stderr, "refexec: bad --poke %s\n", pokes[i]);
            pe_unmap(&image);
            return 1;
        }
    }

    if (!pe_ptr(&image, function_va)) {
        fprintf(stderr, "refexec: %#" PRIx64 " is outside the image (base %#" PRIx64
                        ", size %#" PRIx64 ")\n",
                function_va, image.image_base, image.size_of_image);
        pe_unmap(&image);
        return 1;
    }
    const char *section = pe_section_name(&image, function_va);
    if (!pe_is_code(&image, function_va)) {
        fprintf(stderr, "refexec: %#" PRIx64 " is in %s, not executable code\n",
                function_va, section ? section : "no section");
        pe_unmap(&image);
        return 1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = fault_handler;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGBUS, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGFPE, &action, NULL);
    g_image_base = image.image_base;
    g_image_size = image.size_of_image;

    ms_fn_u64 function = (ms_fn_u64)(uintptr_t)function_va;

    void *guest_stack = mmap((void *)(uintptr_t)GUEST_STACK_BASE, GUEST_STACK_SIZE,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (guest_stack == MAP_FAILED) {
        fprintf(stderr, "refexec: cannot map the guest stack at %#x\n", GUEST_STACK_BASE);
        pe_unmap(&image);
        return 1;
    }
    const uint64_t stack_pointer = GUEST_STACK_BASE + GUEST_STACK_SIZE - GUEST_STACK_HEADROOM;

    uint64_t result = call_on_guest_stack(function, stack_pointer, args[0], args[1],
                                          args[2], args[3]);

    printf("refexec: image=%s base=%#" PRIx64 " section=%s va=%#" PRIx64
           " args=%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64 ",%#" PRIx64
           " result=%#" PRIx64 " result_dec=%" PRIu64 "\n",
           path, image.image_base, section ? section : "?", function_va, args[0], args[1],
           args[2], args[3], result, result);

    for (int i = 0; i < dump_count; i++) {
        printf("refexec: memory %#" PRIx64 "+%" PRIu64 " =", dump_addr[i], dump_len[i]);
        for (uint64_t offset = 0; offset < dump_len[i]; offset++) {
            void *pointer = pe_ptr(&image, dump_addr[i] + offset);
            printf(" %02x", pointer ? *(const uint8_t *)pointer : 0);
        }
        printf("\n");
    }

    munmap(guest_stack, GUEST_STACK_SIZE);
    pe_unmap(&image);
    return 0;
}
