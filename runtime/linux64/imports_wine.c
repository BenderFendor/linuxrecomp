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
#include <stdio.h>
#include <string.h>
#include <windows.h>

/* Load the DLL the way a program's own directory is searched first: a recompiled
 * program's DLLs sit next to the program, not next to the harness running it. */
static HMODULE load_beside_image(const char *dll, const char *image_path) {
    if (!image_path || !*image_path) {
        return NULL;
    }
    const char *separator = strrchr(image_path, '/');
    if (!separator) {
        return NULL;
    }
    char path[1024];
    size_t directory = (size_t)(separator - image_path) + 1;
    if (directory + strlen(dll) + 1 > sizeof(path)) {
        return NULL;
    }
    memcpy(path, image_path, directory);
    snprintf(path + directory, sizeof(path) - directory, "%s", dll);
    return LoadLibraryA(path);
}

void *host_resolve_import(const char *dll, const char *name, uint16_t ordinal, int by_ordinal,
                          const char *image_path) {
    HMODULE module = load_beside_image(dll, image_path);
    if (!module) {
        module = LoadLibraryA(dll);
    }
    if (!module) {
        return NULL;
    }
    if (by_ordinal) {
        return (void *)(uintptr_t)GetProcAddress(module, (LPCSTR)(uintptr_t)ordinal);
    }
    return (void *)(uintptr_t)GetProcAddress(module, name);
}

void *host_get_proc_address(uint64_t module, const char *name) {
    if (!module) {
        return NULL;
    }
    /* A name below 64 KiB is an ordinal, the way MAKEINTRESOURCE spells one. */
    if (!name) {
        return NULL;
    }
    uintptr_t value = (uintptr_t)name;
    if (value < 0x10000) {
        return (void *)(uintptr_t)GetProcAddress((HMODULE)(uintptr_t)module,
                                                 (LPCSTR)value);
    }
    return (void *)(uintptr_t)GetProcAddress((HMODULE)(uintptr_t)module, name);
}

int imports_host_available(void) {
    return 1;
}
