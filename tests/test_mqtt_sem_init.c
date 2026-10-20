/* Native semaphore initialization failure tests with deterministic POSIX
 * primitive injection. */

#include <stdio.h>
#include <errno.h>

#include "wolfmqtt/mqtt_client.h"

#ifdef WOLFMQTT_POSIX_SEMAPHORES

/* The config header renames these in every translation unit; call the real
 * primitives from the hooks below. */
#undef pthread_mutex_init
#undef pthread_mutex_destroy
#undef pthread_cond_init
#undef pthread_cond_destroy

static int mutex_fail_on;  /* fail the Nth mutex init, 0 = never */
static int cond_fail_on;   /* fail the Nth cond init, 0 = never */
static int mutex_inits;
static int cond_inits;
static int mutex_live;
static int cond_live;

static void reset_counts(void)
{
    mutex_fail_on = 0;
    cond_fail_on = 0;
    mutex_inits = 0;
    cond_inits = 0;
    mutex_live = 0;
    cond_live = 0;
}

int wolfmqtt_test_pthread_mutex_init(pthread_mutex_t* m,
    const pthread_mutexattr_t* a)
{
    int rc;
    if (++mutex_inits == mutex_fail_on) {
        return EAGAIN;
    }
    rc = pthread_mutex_init(m, a);
    if (rc == 0) {
        mutex_live++;
    }
    return rc;
}

int wolfmqtt_test_pthread_mutex_destroy(pthread_mutex_t* m)
{
    mutex_live--;
    return pthread_mutex_destroy(m);
}

int wolfmqtt_test_pthread_cond_init(pthread_cond_t* c,
    const pthread_condattr_t* a)
{
    int rc;
    if (++cond_inits == cond_fail_on) {
        return ENOMEM;
    }
    rc = pthread_cond_init(c, a);
    if (rc == 0) {
        cond_live++;
    }
    return rc;
}

int wolfmqtt_test_pthread_cond_destroy(pthread_cond_t* c)
{
    cond_live--;
    return pthread_cond_destroy(c);
}

static int test_connect(void* context, const char* host, word16 port,
    int timeout_ms)
{
    (void)context;
    (void)host;
    (void)port;
    (void)timeout_ms;
    return MQTT_CODE_SUCCESS;
}

static int test_io(void* context, byte* buf, int buf_len, int timeout_ms)
{
    (void)context;
    (void)buf;
    (void)buf_len;
    (void)timeout_ms;
    return MQTT_CODE_ERROR_TIMEOUT;
}

static int test_write(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    (void)context;
    (void)buf;
    (void)timeout_ms;
    return buf_len;
}

static int test_disconnect(void* context)
{
    (void)context;
    return MQTT_CODE_SUCCESS;
}

/* A failed native mutex or condition-variable initialization must fail
 * MqttClient_Init rather than mark the lock initialized, and must leave no
 * native object behind once the failed init has cleaned up. */
static int run_init_failure(const char* name, int fail_mutex, int fail_cond)
{
    MqttClient client;
    MqttNet net;
    byte tx_buf[64];
    byte rx_buf[64];
    int rc;

    reset_counts();
    mutex_fail_on = fail_mutex;
    cond_fail_on = fail_cond;
    XMEMSET(&net, 0, sizeof(net));
    net.connect = test_connect;
    net.read = test_io;
    net.write = test_write;
    net.disconnect = test_disconnect;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc == MQTT_CODE_SUCCESS) {
        MqttClient_DeInit(&client);
        fprintf(stderr, "%s: MqttClient_Init reported success\n", name);
        return 1;
    }
    if (mutex_live != 0 || cond_live != 0) {
        fprintf(stderr, "%s: rc=%d leaked mutexes=%d conds=%d\n",
            name, rc, mutex_live, cond_live);
        return 1;
    }
    return 0;
}

int main(void)
{
    int fail = 0;

    /* First and a later lock: the first fails before anything else is set
     * up, the later one after earlier locks were initialized. */
    fail |= run_init_failure("first mutex", 1, 0);
    fail |= run_init_failure("second mutex", 2, 0);
    fail |= run_init_failure("first cond", 0, 1);
    fail |= run_init_failure("second cond", 0, 2);
    return fail;
}

#else

int main(void)
{
    /* Only the POSIX semaphore backend is exercised here. */
    return 77;
}

#endif /* WOLFMQTT_POSIX_SEMAPHORES */
