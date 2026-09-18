/* The host hook for imports when the host is Wine.
 *
 * This is the whole reason the project is a winelib program: kernel32, user32 and
 * the rest are Wine's implementations, reached through Wine's own loader search
 * rules, in the process. A resolved address is a PE-side address that is valid
 * only inside this Wine process, which is exactly the lifetime it is used for.
 *
 * Only the winelib build links this file.
 */
#include "imports.h"

#include <stdint.h>
#include <windows.h>

void *host_resolve_import(const char *dll, const char *name, uint16_t ordinal, int by_ordinal) {
    HMODULE module = LoadLibraryA(dll);
    if (!module) {
        return NULL;
    }
    if (by_ordinal) {
        return (void *)(uintptr_t)GetProcAddress(module, (LPCSTR)(uintptr_t)ordinal);
    }
    return (void *)(uintptr_t)GetProcAddress(module, name);
}

int imports_host_available(void) {
    return 1;
}
