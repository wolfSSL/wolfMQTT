/* Force the multithreaded client and rename the POSIX primitives behind
 * wm_SemInit/wm_SemFree so the dedicated semaphore test can make their
 * initialization fail deterministically. */
#include "wolfmqtt/options.h"

#ifndef WOLFMQTT_MULTITHREAD
    #define WOLFMQTT_MULTITHREAD
#endif

#if defined(__FreeBSD__) || defined(__linux__) || defined(__QNX__)
    /* Declare the real primitives before renaming them. */
    #include <pthread.h>
    int wolfmqtt_test_pthread_mutex_init(pthread_mutex_t* m,
        const pthread_mutexattr_t* a);
    int wolfmqtt_test_pthread_mutex_destroy(pthread_mutex_t* m);
    int wolfmqtt_test_pthread_cond_init(pthread_cond_t* c,
        const pthread_condattr_t* a);
    int wolfmqtt_test_pthread_cond_destroy(pthread_cond_t* c);
    #define pthread_mutex_init wolfmqtt_test_pthread_mutex_init
    #define pthread_mutex_destroy wolfmqtt_test_pthread_mutex_destroy
    #define pthread_cond_init wolfmqtt_test_pthread_cond_init
    #define pthread_cond_destroy wolfmqtt_test_pthread_cond_destroy
#endif
