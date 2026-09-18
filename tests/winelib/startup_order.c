/* What is safe to do, and when, in a winelib module?
 *
 * The linux64 runtime runs recompiled guest code inside a process whose Win32 API
 * comes from Wine. That makes the module's startup ordering a property worth
 * knowing rather than guessing: when does Wine's Win32 layer become usable, and
 * what happens to ordinary Unix file descriptors?
 *
 * Run: ./scripts/check-winelib.sh
 */
#define _GNU_SOURCE
#include <windows.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOG_PATH "/tmp/linuxrecomp-startup-order.log"

static void note(const char *what) {
    int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    dprintf(fd, "%s\n", what);
    close(fd);
}

/* ELF constructors run before Wine has called into the module. */
__attribute__((constructor)) static void constructor(void) {
    note("ctor: entry");
    void *committed = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    note(committed ? "ctor: VirtualAlloc MEM_COMMIT worked" : "ctor: VirtualAlloc failed");
    if (committed) {
        VirtualFree(committed, 0, MEM_RELEASE);
    }
    note("ctor: exit");
}

int main(void) {
    note("main: entry");

    void *at_base = VirtualAlloc((LPVOID)(uintptr_t)0x140000000, 0x10000,
                                 MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    note(at_base == (void *)(uintptr_t)0x140000000 ? "main: VirtualAlloc at 0x140000000 worked"
                                                  : "main: VirtualAlloc at 0x140000000 failed");

    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(at_base, &info, sizeof(info))) {
        char line[128];
        snprintf(line, sizeof(line), "main: VirtualQuery state=%lu protect=%lu",
                 (unsigned long)info.State, (unsigned long)info.Protect);
        note(line);
    }

    /* Unix-side stdio after Win32 calls have been made. */
    if (fputs("main: stderr write\n", stderr) < 0) {
        note("main: stderr write failed");
    } else {
        note("main: stderr write worked");
    }

    printf("main: stdout write\n");
    fflush(stdout);
    note("main: stdout write worked");

    if (at_base) {
        VirtualFree(at_base, 0, MEM_RELEASE);
    }
    note("main: exit");
    return 0;
}
