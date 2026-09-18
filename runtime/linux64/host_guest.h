/* Running guest code with a large stack, through the host.
 *
 * The lifted code needs far more stack than a program's main thread normally has:
 * Remill's prologue allocates the whole State and Memory frame plus spill slots
 * before executing a single guest instruction, and a PE module's main thread gets
 * a 1 MiB PE stack, of which almost nothing is left by the time main runs.
 *
 * Which thread the guest runs on is a host decision, and in a Wine process it is
 * a delicate one:
 *
 *   - A pthread is invisible to Wine. Wine installs process-wide signal handlers
 *     that assume a Wine thread context, so a signal delivered to a foreign thread
 *     makes Wine's handler longjmp through state that was never set up for it.
 *     Measured: SIGSEGV inside libc siglongjmp, called from a corrupt frame.
 *
 *   - A thread from Wine's own CreateThread is known to Wine, so Wine's handler
 *     does run for a fault in it, but the handler dispatches a Windows exception,
 *     finds no SEH frame beneath our ELF frames, and longjmps into garbage.
 *     Measured: SIGSEGV inside libc __longjmp with a non-canonical RSP, which only
 *     became visible after the harness installed a handler with its own alternate
 *     stack.
 *
 * A Wine thread is still the right home for guest code (Wine owns the stack, and
 * a winelib module has no PE header to raise the main thread's 1 MiB stack from),
 * so host_guest_wine.c creates one with CreateThread and blocks the signals Wine
 * uses to reach into threads, SIGQUIT and SIGUSR1, for its lifetime.
 *
 * Guest execution inside a Wine process is not reliable yet; the measurements and
 * the remaining work are in docs/agents/traces/wine-host-guest-execution.md. The
 * native host is unaffected, and the differential tests use it.
 *
 * The host decides: a pthread in a native process, a Wine-owned thread in a Wine
 * process.
 */
#ifndef LINUXRECOMP_HOST_GUEST_H
#define LINUXRECOMP_HOST_GUEST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Run *entry(argument)* with *stack_size* bytes of stack available. Returns 0 on
 * success, -1 if the host could not provide that. */
int host_run_guest(void *(*entry)(void *), void *argument, uint64_t stack_size);

#ifdef __cplusplus
}
#endif

#endif
