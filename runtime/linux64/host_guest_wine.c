/* Wine host: a thread Wine creates, for a stack Wine knows about.
 *
 * Guest code needs far more stack than Wine's 1 MiB main-thread stack, and the
 * thread it runs on must be one Wine allocated. Wine keeps its own view of the
 * address space, and a stack that came from a plain mmap (which is what
 * pthread_create uses) is not in that view: Wine reports the range as free and
 * can hand the same addresses to its own allocator afterwards. Measured failure
 * mode on wine-11.15 is a thread whose stack is overwritten under it, which
 * surfaces as SIGSEGV inside libc longjmp with a garbage RSP.
 *
 * CreateThread puts the stack in Wine's bookkeeping, so nothing else can be given
 * the same addresses.
 *
 * Wine's asynchronous signals are blocked for the thread's whole life: Wine
 * reaches into threads with SIGQUIT and SIGUSR1, and it cannot unwind a thread
 * whose frames are not Windows frames.
 *
 * Only the winelib build links this file.
 */
#include "host_guest.h"

#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <windows.h>

typedef struct {
    void *(*entry)(void *);
    void *argument;
} WineGuestStart;

static void block_wine_signals(void) {
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGQUIT);
    sigaddset(&blocked, SIGUSR1);
    sigaddset(&blocked, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &blocked, NULL);
}

static DWORD WINAPI guest_thread_main(LPVOID parameter) {
    WineGuestStart *start = (WineGuestStart *)parameter;
    block_wine_signals();
    start->entry(start->argument);
    return 0;
}

int host_run_guest(void *(*entry)(void *), void *argument, uint64_t stack_size) {
    WineGuestStart start = { entry, argument };
    HANDLE thread = CreateThread(NULL, (SIZE_T)stack_size, guest_thread_main, &start, 0, NULL);
    if (thread == NULL) {
        return -1;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return 0;
}
