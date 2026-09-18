/* Guest memory through Wine's own allocator.
 *
 * Wine keeps its own view of the address space, and memory it does not know about
 * is memory it will reuse: a range obtained with a plain mmap is reported by
 * VirtualQuery as MEM_FREE, so Wine can hand the same addresses to its own
 * allocator. tests/winelib/memory_visibility.c checks that difference directly,
 * and scripts/check-winelib.sh runs it.
 *
 * A reservation address of 0 means "anywhere": only the guest image is
 * address-bound, because only its address is something the guest depends on.
 * Taking the memory from Wine's process heap (HeapAlloc) instead was measured as
 * well and changed nothing about the remaining failure (see the trace in
 * docs/agents/traces/wine-host-guest-execution.md), so this stays with the
 * simpler allocator.
 *
 * Only the winelib build links this file. The default backend stays mmap, so the
 * native harness and the reference executor need nothing from Wine.
 */
#include "image_pe64.h"

#include <stdint.h>
#include <windows.h>

static void *wine_reserve(uint64_t address, uint64_t size) {
    void *mapped = VirtualAlloc(address ? (LPVOID)(uintptr_t)address : NULL, (SIZE_T)size,
                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    return mapped == NULL ? NULL : mapped;
}

static int wine_release(void *address, uint64_t size) {
    (void)size;
    return VirtualFree(address, 0, MEM_RELEASE) ? 0 : -1;
}

static int wine_protect(void *address, uint64_t size, int protection) {
    DWORD page = PAGE_NOACCESS;
    if (protection & PE_PROT_EXEC) {
        page = (protection & PE_PROT_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    } else if (protection & PE_PROT_READ) {
        page = (protection & PE_PROT_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
    }
    DWORD previous = 0;
    return VirtualProtect(address, (SIZE_T)size, page, &previous) ? 0 : -1;
}

static const pe_memory_ops kWineMemoryOps = { wine_reserve, wine_release, wine_protect };

/* Installed before main runs, so every later reservation, including the loader's
 * image mapping and the harness's guest stack, goes through Wine. */
__attribute__((constructor)) static void install_wine_memory_ops(void) {
    pe_set_memory_ops(&kWineMemoryOps);
}
