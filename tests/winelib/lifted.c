/* Probe 2: a plain native ELF library standing in for lifted guest code.
 *
 * This is the shape the Remill path produces: a symbol named after the guest
 * virtual address, called by the runtime's dispatcher. It is deliberately not
 * compiled by winegcc -- recompiled guest code must not depend on the Win32
 * toolchain, only on the DLLs it calls.
 */

#include <stdint.h>

uint64_t sub_140001000(uint64_t a, uint64_t b) {
    uint64_t x = a + b;
    if (x & 1u) {
        x ^= 0x123456789abcdef0ULL;
    }
    return x * 3u;
}

uint64_t sub_140001040(void) {
    return 0x5A5A5A5A5A5A5A5AULL;
}
