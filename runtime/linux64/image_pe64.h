/* Map a PE32+/AMD64 image at the addresses it was linked for.
 *
 * This is the seed of the runtime image loader, and it is also how the project
 * gets a reference execution for differential tests without an emulator: the
 * guest's `.text` is already x86-64, so once the image sits at its own virtual
 * addresses, a leaf function can be called directly from C using the Microsoft
 * ABI attribute and its result compared against the lifted version.
 *
 * Policy: the image must be mapped at its preferred base. Relocating is a
 * deliberate non-goal here, because mixing raw guest addresses with rebased host
 * addresses is the failure mode that produces plausible-looking wrong behaviour.
 * Any base relocations in the image are therefore irrelevant: they exist to
 * support rebasing, and we never rebase. If the preferred base is unavailable
 * the mapping fails loudly.
 */
#ifndef LINUXRECOMP_IMAGE_PE64_H
#define LINUXRECOMP_IMAGE_PE64_H

#include <stddef.h>
#include <stdint.h>

#define PE_MAX_SECTIONS 32

typedef struct {
    char name[9];
    uint32_t rva;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
} pe_section;

typedef struct {
    uint8_t *data;            /* mapped image, or NULL */
    uint64_t image_base;      /* guest base the image was linked for */
    uint64_t size_of_image;   /* bytes mapped */
    uint32_t entry_rva;
    uint32_t size_of_headers;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t num_sections;
    pe_section sections[PE_MAX_SECTIONS];
} pe_image;

/* Map `path` at its preferred base. Returns 0 on success, -1 on failure with a
 * message in `err`. */
int pe_map(const char *path, pe_image *image, char *err, size_t err_len);

/* Release a mapping created by pe_map. Safe to call on a zeroed image. */
void pe_unmap(pe_image *image);

/* Host pointer for a guest virtual address, or NULL when unmapped. */
void *pe_ptr(const pe_image *image, uint64_t va);

/* True when `va` falls inside an executable section. */
int pe_is_code(const pe_image *image, uint64_t va);

/* Name of the section containing `va`, or NULL. */
const char *pe_section_name(const pe_image *image, uint64_t va);

#endif /* LINUXRECOMP_IMAGE_PE64_H */
