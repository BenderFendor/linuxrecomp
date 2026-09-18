/* Native host: a pthread with a large stack.
 *
 * See host_guest.h for why guest code does not run on the program's main stack,
 * and host_guest_wine.c for what a Wine process does instead.
 */
#include "host_guest.h"

#include <pthread.h>
#include <stddef.h>

int host_run_guest(void *(*entry)(void *), void *argument, uint64_t stack_size) {
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes) != 0) {
        return -1;
    }
    if (pthread_attr_setstacksize(&attributes, (size_t)stack_size) != 0) {
        pthread_attr_destroy(&attributes);
        return -1;
    }

    pthread_t thread;
    int created = pthread_create(&thread, &attributes, entry, argument);
    pthread_attr_destroy(&attributes);
    if (created != 0) {
        return -1;
    }
    pthread_join(thread, NULL);
    return 0;
}
