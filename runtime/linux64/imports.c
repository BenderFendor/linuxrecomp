/* Import table: walk a mapped PE's import directory and bind every thunk.
 *
 * The walk is shared between hosts; only `host_resolve_import` differs, which is
 * why this file is plain C with no Wine or POSIX dependency.
 *
 * A PE64 import thunk is a `uint64_t` whose low 31 bits are either an ordinal
 * (bit 63 set) or an RVA to a hint/name entry: a 2-byte hint followed by a
 * NUL-terminated name. The image's IAT holds those values before a loader runs, so
 * an unbound slot called by lifted code would jump into the hint/name text; binding
 * means replacing the slot with something callable.
 */
#include "imports.h"

#include <stdio.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* Optional header, from the same layout the loader parses. */
static const uint8_t *optional_header(const pe_image *image) {
    const uint8_t *base = image->data;
    uint32_t pe_offset = rd32(base + 0x3C);
    return base + pe_offset + 24;
}

static uint32_t directory_rva(const pe_image *image, int index) {
    const uint8_t *opt = optional_header(image);
    const uint8_t *entry = opt + 112 + index * 8; /* PE32+: data directories at 112 */
    return rd32(entry);
}

static size_t directory_size(const pe_image *image, int index) {
    const uint8_t *opt = optional_header(image);
    return rd32(opt + 112 + index * 8 + 4);
}

/* The protection a section's characteristics ask for. */
static int section_protection(const pe_image *image, uint64_t va) {
    for (uint32_t i = 0; i < image->num_sections; i++) {
        const pe_section *section = &image->sections[i];
        uint64_t start = image->image_base + section->rva;
        uint64_t size = section->virtual_size ? section->virtual_size : section->raw_size;
        if (va >= start && va < start + size) {
            int protection = PE_PROT_READ;
            if (section->characteristics & 0x80000000u) { /* IMAGE_SCN_MEM_WRITE */
                protection |= PE_PROT_WRITE;
            }
            if (section->characteristics & 0x20000000u) { /* IMAGE_SCN_MEM_EXECUTE */
                protection |= PE_PROT_EXEC;
            }
            return protection;
        }
    }
    return PE_PROT_READ;
}

static int copy_cstring(const pe_image *image, uint64_t va, char *out, size_t capacity) {
    const char *source = (const char *)pe_ptr(image, va);
    if (!source) {
        return -1;
    }
    size_t i = 0;
    while (i + 1 < capacity && source[i] != '\0') {
        out[i] = source[i];
        i++;
    }
    out[i] = '\0';
    return source[i] == '\0' ? 0 : -1;
}

int imports_bind(const pe_image *image, import_table *table, char *error, size_t error_size) {
    memset(table, 0, sizeof(*table));
    if (!image->data) {
        snprintf(error, error_size, "no mapped image");
        return -1;
    }
    const uint32_t import_rva = directory_rva(image, 1);
    if (import_rva == 0) {
        return 0; /* nothing to import */
    }
    /* The slots live in the image's IAT, which normally sits in a read-only
     * section: a real loader writes them with the pages temporarily writable, so do
     * the same and then put the section's own protection back. */
    const uint32_t iat_rva = directory_rva(image, 12);
    const size_t iat_size = directory_size(image, 12);
    uint8_t *iat = (iat_rva && iat_size) ? (uint8_t *)pe_ptr(image, image->image_base + iat_rva)
                                         : NULL;
    if (iat) {
        pe_protect(iat, iat_size, PE_PROT_READ | PE_PROT_WRITE);
    }

    const uint8_t *descriptor = (const uint8_t *)pe_ptr(image, image->image_base + import_rva);
    if (!descriptor) {
        snprintf(error, error_size, "import directory %#x is not mapped", import_rva);
        return -1;
    }

    for (int i = 0; i < 4096; i++, descriptor += 20) {
        uint32_t original_first_thunk = rd32(descriptor + 0);
        uint32_t name_rva = rd32(descriptor + 12);
        uint32_t first_thunk = rd32(descriptor + 16);
        if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) {
            break;
        }
        char dll[IMPORT_DLL_MAX];
        if (copy_cstring(image, image->image_base + name_rva, dll, sizeof(dll)) != 0) {
            snprintf(error, error_size, "import descriptor %d has an unreadable DLL name", i);
            return -1;
        }

        /* A binary without an original-first-thunk cannot be walked: there is no
         * name table left, only the bound addresses. */
        uint32_t thunk_rva = original_first_thunk ? original_first_thunk : first_thunk;
        for (int index = 0; thunk_rva != 0 && index < 65536; index++) {
            const uint8_t *thunk = (const uint8_t *)pe_ptr(image, image->image_base + thunk_rva +
                                                                       index * 8);
            if (!thunk) {
                break;
            }
            uint64_t value = rd64(thunk);
            if (value == 0) {
                break;
            }
            if (index >= (int)(directory_size(image, 12) / 8) && directory_size(image, 12) != 0) {
                /* The IAT directory bounds the slots when it is present. */
            }
            if (table->count >= IMPORTS_MAX) {
                snprintf(error, error_size, "more than %d imports", IMPORTS_MAX);
                return -1;
            }
            import_entry *entry = &table->entries[table->count];
            snprintf(entry->dll, sizeof(entry->dll), "%s", dll);
            entry->iat_va = image->image_base + first_thunk + (uint64_t)index * 8;
            entry->by_ordinal = (value >> 63) != 0;
            entry->ordinal = (uint16_t)(value & 0xFFFF);
            entry->name[0] = '\0';
            if (!entry->by_ordinal &&
                copy_cstring(image, image->image_base + (value & 0x7FFFFFFF) + 2, entry->name,
                             sizeof(entry->name)) != 0) {
                snprintf(error, error_size, "%s: import %d has an unreadable name", dll, index);
                return -1;
            }

            void *resolved = host_resolve_import(entry->dll, entry->name, entry->ordinal,
                                                 entry->by_ordinal);
            if (!resolved) {
                table->unresolved++;
                entry->host_address = 0;
            } else {
                entry->host_address = (uint64_t)(uintptr_t)resolved;
                uint8_t *slot = (uint8_t *)pe_ptr(image, entry->iat_va);
                if (!slot) {
                    snprintf(error, error_size, "%s: IAT slot %#llx is not mapped", dll,
                             (unsigned long long)entry->iat_va);
                    return -1;
                }
                uint64_t pointer = entry->host_address;
                memcpy(slot, &pointer, sizeof(pointer));
            }
            table->count++;
        }
    }

    if (iat) {
        pe_protect(iat, iat_size, section_protection(image, image->image_base + iat_rva));
    }
    return 0;
}

const import_entry *imports_find_host(const import_table *table, uint64_t host_address) {
    if (!table || host_address == 0) {
        return NULL;
    }
    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].host_address == host_address) {
            return &table->entries[i];
        }
    }
    return NULL;
}
