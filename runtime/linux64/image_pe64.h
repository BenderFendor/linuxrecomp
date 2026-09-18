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

#ifdef __cplusplus
extern "C" {
#endif

#define PE_MAX_SECTIONS 32

/* Protection flags, matching the host-independent names the loader uses. */
#define PE_PROT_READ  1
#define PE_PROT_WRITE 2
#define PE_PROT_EXEC  4

/* How the loader obtains and protects guest memory.
 *
 * The default uses mmap. A winelib host installs Wine's VirtualAlloc and
 * VirtualProtect instead, and that is not a detail: Wine keeps its own view of
 * the address space, and a range obtained with a plain mmap is reported by
 * VirtualQuery as MEM_FREE, so Wine can hand the same range out again for a
 * thread stack, a heap or a section. The symptom is a fault that depends on
 * unrelated timing, and it goes away once Wine knows the range is ours.
 */
/* A reservation address of 0 means the host picks. Guest regions are only
 * address-sensitive when the guest itself depends on the address (its image
 * base); everything else should let the host choose, because a host that keeps
 * its own allocator will hand out a range it considers free, even one that a
 * fixed-address reservation has already taken. */
typedef struct {
    void *(*reserve)(uint64_t address, uint64_t size);
    int (*release)(void *address, uint64_t size);
    int (*protect)(void *address, uint64_t size, int protection);
} pe_memory_ops;

/* Install a memory backend. Passing NULL restores the mmap default. */
void pe_set_memory_ops(const pe_memory_ops *ops);

/* Reserve and release guest memory through the installed backend. */
void *pe_reserve(uint64_t address, uint64_t size);
int pe_release(void *address, uint64_t size);
int pe_protect(void *address, uint64_t size, int protection);

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

/* A data directory of the mapped image: its RVA and size.
 *
 * The directories live in the optional header, and reading them from the mapping
 * rather than from the file keeps one source of truth for the image's layout.
 * Returns 0 when the directory is absent or empty. */
int pe_data_directory(const pe_image *image, int index, uint32_t *rva, uint32_t *size);

/* Name of the section containing `va`, or NULL. */
const char *pe_section_name(const pe_image *image, uint64_t va);

#ifdef __cplusplus
}
#endif

#endif /* LINUXRECOMP_IMAGE_PE64_H */
