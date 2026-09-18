/* Guest memory through Wine's own allocator.
 *
 * Wine keeps its own view of the address space, and a range obtained with a plain
 * mmap is not in it: VirtualQuery reports such a range as MEM_FREE, so Wine can
 * hand the same addresses out again for a thread stack, a heap block or a section.
 * A guest image or guest stack placed with mmap can therefore be overwritten by
 * unrelated Wine activity, which surfaces as a fault that depends on timing
 * rather than on anything in the lifted code.
 *
 * Mapping through VirtualAlloc puts the region in Wine's bookkeeping, and
 * VirtualProtect applies the section permissions the same way.
 *
 * Measured on wine-11.15 with a plain mmap:
 *
 *     mmap stack 0x200000, image 0x140000000
 *     after mmap, stack 0x200000:     state=MEM_FREE size=0x7fd60000
 *     after mmap, image 0x140000000:  state=MEM_FREE size=0x6ffebf320000
 *
 * scripts/check-winelib.sh asserts the difference, so this cannot regress
 * silently.
 *
 * Only the winelib build links this file. The default backend stays mmap, so the
 * native harness and the reference executor need nothing from Wine.
 */
#include "image_pe64.h"

#include <stdint.h>
#include <windows.h>

static void *wine_reserve(uint64_t address, uint64_t size) {
    void *mapped = VirtualAlloc((LPVOID)(uintptr_t)address, (SIZE_T)size,
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
