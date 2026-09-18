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

void *host_resolve_import(const char *dll, const char *name, uint16_t ordinal, int by_ordinal,
                          const char *image_path) {
    (void)dll;
    (void)name;
    (void)ordinal;
    (void)by_ordinal;
    (void)image_path;
    return NULL;
}

void *host_get_proc_address(uint64_t module, const char *name) {
    (void)module;
    (void)name;
    return NULL;
}

void *host_get_command_line(void) { return NULL; }
const uint16_t *host_get_environment_w(void) { return NULL; }
const char *host_get_environment_a(void) { return NULL; }
int host_get_startup_info(void *buffer, unsigned long size) {
    (void)buffer;
    (void)size;
    return 0;
}

void *host_get_module_handle(const char *name) {
    (void)name;
    return NULL;
}

int imports_host_available(void) {
    return 0;
}
