#define _GNU_SOURCE
#include "image_pe64.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define SCN_MEM_EXECUTE 0x20000000u
#define SCN_MEM_READ    0x40000000u
#define SCN_MEM_WRITE   0x80000000u

#define OPTIONAL_MAGIC_PE32PLUS 0x20Bu
#define MACHINE_AMD64 0x8664u

#define PAGE 4096ull

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static int fail(char *err, size_t err_len, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (err && err_len) {
        vsnprintf(err, err_len, fmt, args);
    }
    va_end(args);
    return -1;
}

static uint8_t *read_file(const char *path, size_t *size_out, char *err, size_t err_len) {
    FILE *handle = fopen(path, "rb");
    if (!handle) {
        fail(err, err_len, "cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    if (fseek(handle, 0, SEEK_END) != 0) {
        fclose(handle);
        fail(err, err_len, "cannot seek %s", path);
        return NULL;
    }
    long size = ftell(handle);
    if (size <= 0) {
        fclose(handle);
        fail(err, err_len, "%s is empty", path);
        return NULL;
    }
    rewind(handle);
    uint8_t *bytes = malloc((size_t)size);
    if (!bytes) {
        fclose(handle);
        fail(err, err_len, "out of memory reading %s", path);
        return NULL;
    }
    if (fread(bytes, 1, (size_t)size, handle) != (size_t)size) {
        free(bytes);
        fclose(handle);
        fail(err, err_len, "short read on %s", path);
        return NULL;
    }
    fclose(handle);
    *size_out = (size_t)size;
    return bytes;
}

static int protect_range(uint8_t *base, uint64_t start_va, uint64_t image_base,
                         uint64_t length, int prot) {
    if (length == 0) {
        return 0;
    }
    uint64_t start = start_va - image_base;
    uint64_t end = start + length;
    uint64_t page_start = start & ~(PAGE - 1);
    uint64_t page_end = (end + PAGE - 1) & ~(PAGE - 1);
    return mprotect(base + page_start, (size_t)(page_end - page_start), prot);
}

int pe_map(const char *path, pe_image *image, char *err, size_t err_len) {
    memset(image, 0, sizeof(*image));

    size_t file_size = 0;
    uint8_t *file = read_file(path, &file_size, err, err_len);
    if (!file) {
        return -1;
    }

    if (file_size < 0x40 || file[0] != 'M' || file[1] != 'Z') {
        free(file);
        return fail(err, err_len, "%s: not a PE image", path);
    }
    uint32_t pe_offset = rd32(file + 0x3C);
    if (pe_offset + 24 > file_size || memcmp(file + pe_offset, "PE\0\0", 4) != 0) {
        free(file);
        return fail(err, err_len, "%s: no PE signature", path);
    }

    const uint8_t *coff = file + pe_offset + 4;
    uint16_t machine = rd16(coff);
    uint16_t num_sections = rd16(coff + 2);
    uint16_t opt_size = rd16(coff + 16);
    const uint8_t *opt = coff + 20;
    uint16_t magic = rd16(opt);

    if (magic != OPTIONAL_MAGIC_PE32PLUS) {
        free(file);
        return fail(err, err_len, "%s: not PE32+, optional magic 0x%X", path, magic);
    }
    if (machine != MACHINE_AMD64) {
        free(file);
        return fail(err, err_len, "%s: machine 0x%X is not AMD64", path, machine);
    }
    if (num_sections > PE_MAX_SECTIONS) {
        free(file);
        return fail(err, err_len, "%s: %u sections exceeds %d", path, num_sections,
                    PE_MAX_SECTIONS);
    }

    image->image_base = rd64(opt + 24);
    image->entry_rva = rd32(opt + 16);
    image->size_of_image = rd32(opt + 56);
    image->size_of_headers = rd32(opt + 60);
    image->subsystem = rd16(opt + 68);
    image->dll_characteristics = rd16(opt + 70);
    image->num_sections = num_sections;

    const uint8_t *table = opt + opt_size;
    for (uint16_t i = 0; i < num_sections; i++) {
        const uint8_t *entry = table + i * 40;
        pe_section *section = &image->sections[i];
        memcpy(section->name, entry, 8);
        section->name[8] = '\0';
        section->virtual_size = rd32(entry + 8);
        section->rva = rd32(entry + 12);
        section->raw_size = rd32(entry + 16);
        section->raw_offset = rd32(entry + 20);
        section->characteristics = rd32(entry + 36);
    }

    if (image->size_of_image == 0) {
        free(file);
        return fail(err, err_len, "%s: SizeOfImage is zero", path);
    }

    /* The preferred base or nothing. See the policy note in the header. */
    void *mapped = mmap((void *)(uintptr_t)image->image_base, image->size_of_image,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mapped == MAP_FAILED) {
        int saved = errno;
        free(file);
        return fail(err, err_len,
                    "%s: cannot map %#llx bytes at preferred base %#llx: %s "
                    "(relocating is not supported)",
                    path, (unsigned long long)image->size_of_image,
                    (unsigned long long)image->image_base, strerror(saved));
    }
    if ((uintptr_t)mapped != image->image_base) {
        munmap(mapped, image->size_of_image);
        free(file);
        return fail(err, err_len, "%s: mapped at %p instead of %#llx", path, mapped,
                    (unsigned long long)image->image_base);
    }
    image->data = mapped;

    memcpy(image->data, file, image->size_of_headers < file_size ? image->size_of_headers
                                                                 : file_size);
    for (uint16_t i = 0; i < num_sections; i++) {
        const pe_section *section = &image->sections[i];
        if (section->raw_size == 0) {
            continue; /* .bss and friends: the anonymous mapping is already zero */
        }
        if ((uint64_t)section->raw_offset + section->raw_size > file_size) {
            pe_unmap(image);
            free(file);
            return fail(err, err_len,
                        "%s: section %s claims %#x raw bytes at offset %#x, past end "
                        "of file (%zu bytes)",
                        path, section->name, section->raw_size, section->raw_offset,
                        file_size);
        }
        memcpy(image->data + section->rva, file + section->raw_offset, section->raw_size);
    }
    free(file);

    /* Headers are read-only afterwards; sections follow their characteristics. */
    if (mprotect(image->data, (size_t)image->size_of_headers, PROT_READ) != 0) {
        pe_unmap(image);
        return fail(err, err_len, "%s: cannot protect headers", path);
    }
    for (uint16_t i = 0; i < num_sections; i++) {
        const pe_section *section = &image->sections[i];
        uint64_t size = section->virtual_size > section->raw_size ? section->virtual_size
                                                                 : section->raw_size;
        int prot = PROT_READ;
        if (section->characteristics & SCN_MEM_WRITE) {
            prot |= PROT_WRITE;
        }
        if (section->characteristics & SCN_MEM_EXECUTE) {
            prot |= PROT_EXEC;
        }
        if (protect_range(image->data, image->image_base + section->rva, image->image_base,
                          size, prot) != 0) {
            pe_unmap(image);
            return fail(err, err_len, "%s: cannot protect section %s", path,
                        section->name);
        }
    }
    return 0;
}

void pe_unmap(pe_image *image) {
    if (image->data) {
        munmap(image->data, image->size_of_image);
    }
    memset(image, 0, sizeof(*image));
}

void *pe_ptr(const pe_image *image, uint64_t va) {
    if (!image->data || va < image->image_base) {
        return NULL;
    }
    uint64_t offset = va - image->image_base;
    if (offset >= image->size_of_image) {
        return NULL;
    }
    return image->data + offset;
}

int pe_is_code(const pe_image *image, uint64_t va) {
    for (uint32_t i = 0; i < image->num_sections; i++) {
        const pe_section *section = &image->sections[i];
        uint64_t start = image->image_base + section->rva;
        uint64_t size = section->virtual_size > section->raw_size ? section->virtual_size
                                                                 : section->raw_size;
        if (va >= start && va < start + size) {
            return (section->characteristics & SCN_MEM_EXECUTE) != 0;
        }
    }
    return 0;
}

const char *pe_section_name(const pe_image *image, uint64_t va) {
    for (uint32_t i = 0; i < image->num_sections; i++) {
        const pe_section *section = &image->sections[i];
        uint64_t start = image->image_base + section->rva;
        uint64_t size = section->virtual_size > section->raw_size ? section->virtual_size
                                                                 : section->raw_size;
        if (va >= start && va < start + size) {
            return section->name;
        }
    }
    return NULL;
}
