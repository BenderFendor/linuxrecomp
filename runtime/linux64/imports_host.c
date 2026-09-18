/* The host hook for imports when there is no Win32 implementation to bind to.
 *
 * The native harness is where lifted code is checked against the reference
 * executor, and there is no kernel32 in that process. It binds nothing and says
 * so, so a run that reaches an import reports an unresolved slot rather than a
 * plausible-looking wrong address.
 */
#include "imports.h"

#include <stddef.h>
#include <stdint.h>

void *host_resolve_import(const char *dll, const char *name, uint16_t ordinal, int by_ordinal) {
    (void)dll;
    (void)name;
    (void)ordinal;
    (void)by_ordinal;
    return NULL;
}

int imports_host_available(void) {
    return 0;
}
