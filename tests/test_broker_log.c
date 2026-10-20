/* Broker log sanitization tests. The broker is built with logging enabled and
 * PRINTF redirected into a capture buffer, so a test can check what reaches
 * the log sink. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_broker.h"

/* The broker sources call these in every configuration. */
static char g_log[4096];
static size_t g_log_len;
static unsigned long g_time_s;

void wolfmqtt_test_log(const char* fmt, ...)
{
    va_list ap;
    int n;

    if (g_log_len >= sizeof(g_log) - 1) {
        return;
    }
    va_start(ap, fmt);
    n = vsnprintf(g_log + g_log_len, sizeof(g_log) - g_log_len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        g_log_len += (size_t)n;
        if (g_log_len > sizeof(g_log) - 1) {
            g_log_len = sizeof(g_log) - 1;
        }
    }
}

unsigned long wolfmqtt_test_broker_time_s(void)
{
    return g_time_s;
}

#if defined(WOLFMQTT_BROKER_PERSIST) && !defined(WOLFMQTT_STATIC_MEMORY) && \
    !defined(WOLFMQTT_BROKER_NO_LOG)

#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

static int net_listen(void* ctx, BROKER_SOCKET_T* sock, word16 port,
    int backlog)
{
    (void)ctx; (void)sock; (void)port; (void)backlog;
    return MQTT_CODE_SUCCESS;
}

static int net_accept(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock)
{
    (void)ctx; (void)listen_sock; (void)client_sock;
    return MQTT_CODE_CONTINUE;
}

static int net_read(void* ctx, BROKER_SOCKET_T sock, byte* buf, int buf_len,
    int timeout_ms)
{
    (void)ctx; (void)sock; (void)buf; (void)buf_len; (void)timeout_ms;
    return MQTT_CODE_CONTINUE;
}

static int net_write(void* ctx, BROKER_SOCKET_T sock, const byte* buf,
    int buf_len, int timeout_ms)
{
    (void)ctx; (void)sock; (void)buf; (void)timeout_ms;
    return buf_len;
}

static int net_close(void* ctx, BROKER_SOCKET_T sock)
{
    (void)ctx; (void)sock;
    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
static int test_derive_key(void* ctx, byte* out_key, word32 key_len)
{
    (void)ctx;
    XMEMSET(out_key, 0x11, key_len);
    return MQTT_CODE_SUCCESS;
}
#endif

/* Remove root/<ns>/<record> as laid out by the POSIX backend. */
static void remove_store(const char* root)
{
    char path[512];
    char sub[1024];
    DIR* d;
    DIR* sd;
    struct dirent* e;
    struct dirent* se;

    d = opendir(root);
    if (d == NULL) {
        return;
    }
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') {
            continue;
        }
        (void)snprintf(path, sizeof(path), "%s/%s", root, e->d_name);
        sd = opendir(path);
        if (sd != NULL) {
            while ((se = readdir(sd)) != NULL) {
                if (se->d_name[0] == '.') {
                    continue;
                }
                (void)snprintf(sub, sizeof(sub), "%s/%s", path, se->d_name);
                (void)unlink(sub);
            }
            (void)closedir(sd);
            (void)rmdir(path);
        }
        else {
            (void)unlink(path);
        }
    }
    (void)closedir(d);
    (void)rmdir(root);
}

static int init_broker(MqttBroker* broker, MqttBrokerNet* net,
    MqttBrokerPersistHooks* hooks)
{
    int rc;

    XMEMSET(broker, 0, sizeof(*broker));
    rc = MqttBroker_Init(broker, net);
    if (rc == MQTT_CODE_SUCCESS) {
        rc = MqttBroker_SetPersistHooks(broker, hooks);
    }
    return rc;
}

/* A persisted Session whose expiry passed while the broker was down is
 * logged when the restore sweep drops it. The Client Identifier is chosen by
 * the remote client and may hold control bytes (MQTT 5.0 section 1.5.4 only
 * forbids U+0000), so it must reach the log escaped: a raw CR/LF would forge
 * log lines and a raw ESC would drive the operator's terminal. */
static int test_restore_expired_session_logs_escaped_client_id(void)
{
    static const char cid[] = "x\x1b[31m\ny";
    char root_template[] = "./wolfmqtt-log-XXXXXX";
    MqttBroker first;
    MqttBroker second;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    char* root;
    int rc;
    int fail = 0;

    XMEMSET(&net, 0, sizeof(net));
    net.listen = net_listen;
    net.accept = net_accept;
    net.read = net_read;
    net.write = net_write;
    net.close = net_close;
    XMEMSET(&hooks, 0, sizeof(hooks));

    root = mkdtemp(root_template);
    if (root == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }
    rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "persist init returned %d\n", rc);
        remove_store(root);
        return 1;
    }
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = test_derive_key;
#endif

    /* First run: stamp META and persist an orphan Session that expires one
     * second after it was orphaned at time 1. */
    g_time_s = 1;
    rc = init_broker(&first, &net, &hooks);
    if (rc == MQTT_CODE_SUCCESS) {
        rc = BrokerPersist_Restore(&first);
    }
    if (rc == MQTT_CODE_SUCCESS) {
        rc = BrokerPersist_PutOrphanSession(&first, cid,
            MQTT_CONNECT_PROTOCOL_LEVEL_5, 1, (WOLFMQTT_BROKER_TIME_T)1);
    }
    MqttBroker_Free(&first);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "first broker setup returned %d\n", rc);
        fail = 1;
    }

    /* Restart well after the expiry. */
    if (!fail) {
        g_time_s = 100;
        rc = init_broker(&second, &net, &hooks);
        g_log_len = 0;
        g_log[0] = '\0';
        if (rc == MQTT_CODE_SUCCESS) {
            rc = BrokerPersist_Restore(&second);
        }
        MqttBroker_Free(&second);
        if (rc != MQTT_CODE_SUCCESS) {
            fprintf(stderr, "restore returned %d\n", rc);
            fail = 1;
        }
    }

    if (!fail) {
        if (strstr(g_log, "expired session") == NULL) {
            fprintf(stderr, "expiry not logged: %s\n", g_log);
            fail = 1;
        }
        else if (strchr(g_log, 0x1b) != NULL ||
                strchr(g_log, '\n') != NULL) {
            fprintf(stderr, "raw control bytes reached the log\n");
            fail = 1;
        }
        else if (strstr(g_log, "client_id=x\\e[31m\\ny") == NULL) {
            fprintf(stderr, "client_id not escaped as expected: %s\n",
                g_log);
            fail = 1;
        }
    }

    MqttBrokerNet_PersistPosix_Free(&hooks);
    remove_store(root);
    return fail;
}

int main(void)
{
    return test_restore_expired_session_logs_escaped_client_id();
}

#else

int main(void)
{
    /* Needs the dynamic-memory persistence restore with logging enabled. */
    return 77;
}

#endif
