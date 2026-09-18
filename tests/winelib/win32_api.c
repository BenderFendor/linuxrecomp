/* Probe 1: Win32 API calls reaching Wine's own DLLs from native code.
 *
 * Built by scripts/check-winelib.sh with `winegcc`. What it proves: the Win32
 * implementation comes from Wine's DLLs (linked here through -lkernel32), so
 * the pipeline does not reimplement kernel32 and does not run anything through
 * Wine's instruction emulation -- the code in this file is native x86-64 ELF.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    ULONGLONG t0 = GetTickCount64();
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    Sleep(1);
    ULONGLONG t1 = GetTickCount64();
    printf("win32 api: pid=%lu tid=%lu tick_ok=%d module=%p\n",
           (unsigned long)pid, (unsigned long)tid, t1 >= t0,
           (void *)GetModuleHandleA(NULL));
    return 0;
}
