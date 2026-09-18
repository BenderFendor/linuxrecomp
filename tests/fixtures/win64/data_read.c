/* Data-section behaviour, in one small image.
 *
 * A lifted program has to see the original bytes of .rdata and .data at the
 * addresses the image was linked for, and writes to .data have to land where a
 * later read finds them. That is a claim about the runtime, so it gets a fixture
 * rather than an argument:
 *
 *   read_magic()       reads a const uint32_t, so it only passes if .rdata is
 *                      mapped at its guest address
 *   read_global()      reads a non-const global in .data
 *   write_global(v)    writes .data and returns the previous value, so a caller
 *                      can check both the write and the read-back
 *
 * main() exists so the image links as an executable; nothing runs it.
 */

#include <stdint.h>

static const uint32_t kMagic = 0x1234ABCDu;          /* .rdata */
__declspec(dllexport) uint32_t global_value = 0x0BADF00Du;   /* .data, exported so
                                        a test can find its address in the image
                                        instead of hard-coding one */

__declspec(dllexport) uint32_t read_magic(void) {
    return kMagic;
}

__declspec(dllexport) uint32_t read_global(void) {
    return global_value;
}

__declspec(dllexport) uint32_t write_global(uint32_t value) {
    uint32_t previous = global_value;
    global_value = value;
    return previous;
}

int main(void) {
    return (int)(read_magic() ^ read_global());
}
