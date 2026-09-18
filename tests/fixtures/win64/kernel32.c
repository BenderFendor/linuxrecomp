#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

int main(void) {
    const ULONGLONG before = GetTickCount64();
    Sleep(1);
    const ULONGLONG after = GetTickCount64();
    return (after >= before) ? 0 : 1;
}
