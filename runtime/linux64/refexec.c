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
#include <unistd.h>

typedef uint64_t(__attribute__((ms_abi)) * ms_fn_u64)(uint64_t, uint64_t, uint64_t,
                                                      uint64_t);

static void fault_handler(int sig) {
    char message[128];
    int length = snprintf(message, sizeof(message),
                          "refexec: guest faulted with signal %d\n", sig);
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
    action.sa_handler = fault_handler;
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGBUS, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGFPE, &action, NULL);

    ms_fn_u64 function = (ms_fn_u64)(uintptr_t)function_va;
    uint64_t result = function(args[0], args[1], args[2], args[3]);

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

    pe_unmap(&image);
    return 0;
}
