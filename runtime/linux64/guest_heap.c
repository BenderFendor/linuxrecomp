/* Guest heap: a first-fit allocator over a reserved slice of guest memory.
 *
 * Blocks carry a header inside the guest's own memory, so an allocation's address
 * is a guest address and the guest can be handed it directly. Header:
 *
 *     struct block { uint64_t size; uint64_t free; uint64_t next; uint64_t previous; }
 *
 * `size` counts the payload, `next`/`previous` chain every block in address order
 * so freeing coalesces with neighbours. This is deliberately small: it exists so a
 * recompiled program's allocations are guest memory, not so it can replace a real
 * heap's performance.
 */
#include "guest_heap.h"

#include "image_pe64.h"

#include <string.h>

#define ALIGNMENT 16
#define HEADER_SIZE ((uint64_t)sizeof(block))
#define MIN_SPLIT (64)

typedef struct block block;
struct block {
    uint64_t size;
    uint64_t free;
    block *next;
    block *previous;
};

static block *g_first = NULL;
static uint64_t g_base = 0;
static uint64_t g_size = 0;
static uint64_t g_allocated = 0;
static uint64_t g_peak = 0;

uint64_t guest_heap_base(void) { return g_base; }
uint64_t guest_heap_size(void) { return g_size; }
uint64_t guest_heap_allocated(void) { return g_allocated; }
uint64_t guest_heap_peak(void) { return g_peak; }

static uint64_t align_up(uint64_t value) {
    return (value + (ALIGNMENT - 1)) & ~(uint64_t)(ALIGNMENT - 1);
}

/* A guest region's host address is its guest address, because the runtime reserves
 * each region at the address the guest will use: the image at its preferred base,
 * and the stack and heap wherever the host puts them, which is then also the guest
 * address. guest_ptr relies on the same identity. */
static uint8_t *host_pointer(uint64_t guest_address) {
    return (uint8_t *)(uintptr_t)guest_address;
}

static uint64_t payload(const block *entry) {
    return (uint64_t)(uintptr_t)entry + HEADER_SIZE;
}

int guest_heap_init(uint64_t size) {
    if (size < 1024 * 1024) {
        size = 64 * 1024 * 1024;
    }
    void *reserved = pe_reserve(0, size);
    if (!reserved) {
        return -1;
    }
    g_base = (uint64_t)(uintptr_t)reserved;
    g_size = size;
    g_first = (block *)reserved;
    g_first->size = size - HEADER_SIZE;
    g_first->free = 1;
    g_first->next = NULL;
    g_first->previous = NULL;
    g_allocated = 0;
    g_peak = 0;
    return 0;
}

/* Split a free block when the remainder can hold a header and a useful payload. */
static void split(block *entry, uint64_t size) {
    if (entry->size < size + HEADER_SIZE + MIN_SPLIT) {
        return;
    }
    block *rest = (block *)((uint8_t *)entry + HEADER_SIZE + size);
    rest->size = entry->size - size - HEADER_SIZE;
    rest->free = 1;
    rest->next = entry->next;
    rest->previous = entry;
    if (rest->next) {
        rest->next->previous = rest;
    }
    entry->next = rest;
    entry->size = size;
}

static void coalesce(block *entry) {
    if (entry->next && entry->next->free) {
        entry->size += HEADER_SIZE + entry->next->size;
        entry->next = entry->next->next;
        if (entry->next) {
            entry->next->previous = entry;
        }
    }
}

uint64_t guest_heap_alloc(uint64_t size) {
    if (!g_first) {
        return 0;
    }
    if (size == 0) {
        size = ALIGNMENT;
    }
    size = align_up(size);
    for (block *entry = g_first; entry; entry = entry->next) {
        if (!entry->free || entry->size < size) {
            continue;
        }
        split(entry, size);
        entry->free = 0;
        g_allocated += entry->size;
        if (g_allocated > g_peak) {
            g_peak = g_allocated;
        }
        return payload(entry);
    }
    return 0;
}

static block *block_of(uint64_t address) {
    if (address < g_base + HEADER_SIZE || address >= g_base + g_size) {
        return NULL;
    }
    return (block *)((uint8_t *)(uintptr_t)(address - HEADER_SIZE));
}

int guest_heap_free(uint64_t address) {
    block *entry = block_of(address);
    if (!entry || entry->free) {
        return 0;
    }
    entry->free = 1;
    if (g_allocated >= entry->size) {
        g_allocated -= entry->size;
    }
    coalesce(entry);
    if (entry->previous && entry->previous->free) {
        block *previous = entry->previous;
        coalesce(previous);
    }
    return 1;
}

uint64_t guest_heap_size_of(uint64_t address) {
    block *entry = block_of(address);
    return entry ? entry->size : 0;
}

uint64_t guest_heap_realloc(uint64_t address, uint64_t size) {
    if (!address) {
        return guest_heap_alloc(size);
    }
    block *entry = block_of(address);
    if (!entry) {
        return 0;
    }
    uint64_t wanted = align_up(size ? size : ALIGNMENT);
    if (entry->size >= wanted) {
        split(entry, wanted);
        return address;
    }
    /* Grow in place when the next block is free and big enough. */
    if (entry->next && entry->next->free &&
        entry->size + HEADER_SIZE + entry->next->size >= wanted) {
        coalesce(entry);
        split(entry, wanted);
        return address;
    }
    uint64_t moved = guest_heap_alloc(wanted);
    if (!moved) {
        return 0;
    }
    uint8_t *source = host_pointer(address);
    uint8_t *target = host_pointer(moved);
    if (source && target) {
        memcpy(target, source, entry->size < wanted ? entry->size : wanted);
    }
    guest_heap_free(address);
    return moved;
}
