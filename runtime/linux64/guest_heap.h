/* A heap that lives in the guest's address space.
 *
 * A recompiled program allocates (HeapAlloc, VirtualAlloc, and the CRT's malloc on
 * top of them) and then reads and writes through what it got back. If those
 * allocations came from the host, every such access would be an access to host
 * memory that the guest address space does not describe, which is exactly what the
 * memory model refuses: the first HLExtract run to reach HeapAlloc stopped with
 * "write of unmapped guest address 0x7ffffe231460", a host pointer.
 *
 * So the guest heap is guest memory, reserved through the same host backend as the
 * image and the stack, handed out by a small first-fit allocator. It is not a
 * reimplementation of the Win32 heap: the allocation family is thunked to this so
 * that the memory a guest program owns is memory the guest can address.
 */
#ifndef LINUXRECOMP_GUEST_HEAP_H
#define LINUXRECOMP_GUEST_HEAP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reserve the guest heap. Returns 0 on success, -1 when the host refuses. */
int guest_heap_init(uint64_t size);

/* The heap's extent in the guest address space, for the memory model. */
uint64_t guest_heap_base(void);
uint64_t guest_heap_size(void);

/* Allocate `size` bytes, returning a guest address or 0. */
uint64_t guest_heap_alloc(uint64_t size);

/* Grow, shrink or move an allocation, returning a guest address or 0. */
uint64_t guest_heap_realloc(uint64_t address, uint64_t size);

/* Release an allocation. Returns 1 when the address was ours. */
int guest_heap_free(uint64_t address);

/* Size of an allocation, or 0 when the address is not one of ours. */
uint64_t guest_heap_size_of(uint64_t address);

/* Statistics, for a run report. */
uint64_t guest_heap_allocated(void);
uint64_t guest_heap_peak(void);

#ifdef __cplusplus
}
#endif

#endif
