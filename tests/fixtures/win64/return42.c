#include <stdint.h>

__declspec(dllexport) uint64_t add_then_mul(uint64_t a, uint64_t b) {
    uint64_t x = a + b;
    if (x & 1u) {
        x ^= 0x123456789abcdef0ULL;
    }
    return x * 3u;
}

int main(void) {
    return (int)(add_then_mul(10, 4) & 0xffu);
}
