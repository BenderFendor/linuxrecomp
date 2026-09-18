/* Probe 4: the reverse direction. Wine creates a thread and calls a native
 * function that is not a Wine module. Window procedures, thread bodies, TLS
 * callbacks, timer callbacks and COM entry points all need this path, so it is
 * checked before any of them are implemented.
 */
#include <windows.h>
#include <stdio.h>

static volatile LONG hits = 0;

/* Stands in for a lifted callback: it calls back into the Win32 layer too. */
static DWORD WINAPI lifted_thread_body(LPVOID param) {
    LONG *counter = (LONG *)param;
    for (int index = 0; index < 3; index++) {
        InterlockedIncrement(counter);
        Sleep(0);
    }
    return 0x1234;
}

int main(void) {
    HANDLE thread = CreateThread(NULL, 0, lifted_thread_body, (LPVOID)&hits, 0, NULL);
    if (!thread) {
        printf("callback: CreateThread failed %lu\n", (unsigned long)GetLastError());
        return 1;
    }
    DWORD wait = WaitForSingleObject(thread, 5000);
    DWORD code = 0;
    GetExitCodeThread(thread, &code);
    CloseHandle(thread);
    printf("callback: hits=%ld wait=%lu exit=0x%lx\n",
           (long)hits, (unsigned long)wait, (unsigned long)code);
    return 0;
}
