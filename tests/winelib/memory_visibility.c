/* Does Wine know about the memory the runtime hands to guest code?
 *
 * Wine keeps its own view of the address space. A region obtained with a plain
 * mmap is not in that view: VirtualQuery reports it as MEM_FREE, so Wine can hand
 * the same addresses out again, and whatever we put there can be overwritten
 * under us. The linux64 runtime therefore takes guest memory from the host's
 * allocator (runtime/linux64/wine_memory.c installs Wine's VirtualAlloc for the
 * winelib build), and this probe checks that Wine's view agrees.
 *
 * Run: ./scripts/check-winelib.sh
 */
#define _GNU_SOURCE
#include "image_pe64.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <windows.h>

static DWORD state_of(void *address) {
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(address, &info, sizeof(info))) {
        return 0;
    }
    return (DWORD)info.State;
}

int main(void) {
    const uint64_t mmap_base = 0x300000;
    const uint64_t reserved_base = 0x400000;
    const uint64_t size = 0x10000;
    int failures = 0;

    void *raw = mmap((void *)(uintptr_t)mmap_base, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (raw == MAP_FAILED) {
        printf("memory: could not mmap at %#llx\n", (unsigned long long)mmap_base);
        return 1;
    }
    DWORD raw_state = state_of(raw);
    printf("memory: mmap region state=%lu (FREE=%lu COMMIT=%lu)\n", (unsigned long)raw_state,
           (unsigned long)MEM_FREE, (unsigned long)MEM_COMMIT);
    if (raw_state != MEM_FREE) {
        printf("memory: expected Wine to consider a plain mmap region free\n");
        failures++;
    }

    /* Through the loader's backend, which installs Wine's allocator. */
    void *reserved = pe_reserve(reserved_base, size);
    if (reserved != (void *)(uintptr_t)reserved_base) {
        printf("memory: pe_reserve returned %p, wanted %#llx\n", reserved,
               (unsigned long long)reserved_base);
        return 1;
    }
    DWORD reserved_state = state_of(reserved);
    printf("memory: pe_reserve region state=%lu\n", (unsigned long)reserved_state);
    if (reserved_state != MEM_COMMIT) {
        printf("memory: expected Wine to know about the region pe_reserve returned\n");
        failures++;
    }

    /* And Wine must not hand the same addresses out again. */
    void *again = VirtualAlloc((LPVOID)(uintptr_t)reserved_base, size, MEM_RESERVE, PAGE_READWRITE);
    printf("memory: second reservation at the same base=%p\n", again);
    if (again != NULL) {
        printf("memory: Wine re-issued an address that was already committed\n");
        failures++;
    }

    printf("memory: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
