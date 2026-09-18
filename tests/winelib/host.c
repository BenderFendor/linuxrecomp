/* Probe 3: the composition that matters. A winelib host calls Wine's Win32
 * APIs and calls into a separately built native ELF shared library, in the
 * same process. If this links and runs, the runtime can keep lifted guest code
 * free of Wine and still use Wine for the Windows API surface.
 *
 * Built by scripts/check-winelib.sh.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

extern uint64_t sub_140001000(uint64_t a, uint64_t b);
extern uint64_t sub_140001040(void);

int main(void) {
    ULONGLONG t0 = GetTickCount64();
    uint64_t dispatched = sub_140001000(10, 4);
    uint64_t second = sub_140001040();
    Sleep(1);
    ULONGLONG t1 = GetTickCount64();
    printf("composed: dispatched=%llu second=0x%llx tick_ok=%d\n",
           (unsigned long long)dispatched, (unsigned long long)second, t1 >= t0);
    return 0;
}
