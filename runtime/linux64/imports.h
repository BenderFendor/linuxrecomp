/* Import resolution: guest IAT slots bound to the host's implementations.
 *
 * A lifted PE calls an import the way the original did: it loads a slot from the
 * image's import address table and calls whatever is there. This project does not
 * reimplement kernel32, so the slot has to hold something that works, and only the
 * host can supply it. The host hook below is the single place that knows how; the
 * table and the PE walk are shared, so the native build resolves nothing and says
 * so rather than pretending.
 *
 * The runtime also needs the table, to recognise a call target that is a host
 * import rather than a guest address. That is what imports_find_host is for.
 */
#ifndef LINUXRECOMP_IMPORTS_H
#define LINUXRECOMP_IMPORTS_H

#include "image_pe64.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IMPORTS_MAX 4096
#define IMPORT_DLL_MAX 64
#define IMPORT_NAME_MAX 128

typedef struct {
    char dll[IMPORT_DLL_MAX];
    char name[IMPORT_NAME_MAX];
    uint16_t ordinal;
    int by_ordinal;
    uint64_t iat_va;        /* guest address of the slot the image calls through */
    uint64_t host_address;  /* what the slot holds after binding */
} import_entry;

typedef struct {
    import_entry entries[IMPORTS_MAX];
    size_t count;
    size_t unresolved;
} import_table;

/* Host hook: resolve dll!name (or dll!ordinal) to a host address, or NULL when the
 * host cannot supply it. Provided per host: imports_wine.c for the winelib build,
 * and a stub that always fails otherwise.
 *
 * `image_path` is the recompiled program's own path. A program's DLLs live next to
 * it, not next to the harness that runs it, so the host searches there first. */
void *host_resolve_import(const char *dll, const char *name, uint16_t ordinal, int by_ordinal,
                          const char *image_path);

/* Walk the image's import directory, resolve every thunk through the host, write
 * the resolved host address into the guest's IAT slot, and record the binding.
 * Returns 0 on success, -1 with a message in `error` when the image cannot be
 * walked. Thunks the host cannot resolve are counted, not fatal: a program that
 * never calls them still runs. */
int imports_bind(const pe_image *image, const char *image_path, import_table *table, char *error,
                 size_t error_size);

/* The binding for a host address, or NULL when the address is not one of ours. */
const import_entry *imports_find_host(const import_table *table, uint64_t host_address);

/* Record another host address the program can call, so the dispatcher recognises it.
 * A program can obtain one at run time (GetProcAddress), and a call through a pointer
 * the runtime does not know is a call it cannot route. */
import_entry *imports_register(import_table *table, uint64_t host_address, const char *dll,
                               const char *name);

/* Host hook: the host's own GetProcAddress, for the thunk that needs it. */
void *host_get_proc_address(uint64_t module, const char *name);

/* Host hooks for imports whose result has to be copied into guest memory rather than
 * passed through: the host's own answer is a host address. */
void *host_get_command_line(void);
const uint16_t *host_get_environment_w(void);
const char *host_get_environment_a(void);
int host_get_startup_info(void *buffer, unsigned long size);

/* True when the host can resolve imports at all. */
int imports_host_available(void);

#ifdef __cplusplus
}
#endif

#endif
