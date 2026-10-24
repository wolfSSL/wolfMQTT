/* Property-lock initialization failure tests with deterministic semaphore
 * injection. */

#include <stdio.h>

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_packet.h"
#include "wolfmqtt/mqtt_socket.h"

static int sem_init_calls;
static int sem_free_attempts;
static int sem_free_calls;
static int sem_invalid_free_calls;
static int sem_fail_all;
static int sem_fail_on_call;
static int sem_fail_free_on_call;
static wm_Sem* sem_complete_on_lock;
static MqttPendResp* sem_pending_to_complete;
static int sem_pending_completions;
static int ping_read_calls;
static int ping_disconnect_calls;
static int sem_invalid_unlock_calls;
static wm_Sem* sem_watch_client_lock;
static wm_Sem* sem_watch_recv_lock;
static MqttMsgStat* sem_watch_ping_stat;
static int sem_stale_ping_locks;
static int sem_watched_recv_locks;
static wm_Sem* sem_fail_lock;
static wm_Sem* sem_fail_lock_while_held;
static int sem_fail_lock_skip;
static int quota_write_calls;
static MqttClient* sem_flag_client;
static word32 sem_flag_bits;
static MqttClient* io_lock_client;
static int io_locks_held_at_close;
/* Counts lockClient acquisitions on sem_track_client made while
 * sem_track_while_held is owned, and records which one changed
 * sem_track_bit in client->flags, so a later run can fail exactly that one. */
static MqttClient* sem_track_client;
static wm_Sem* sem_track_while_held;
static word32 sem_track_bit;
static word32 sem_track_before;
static int sem_track_count;
static int sem_track_counted;
static int sem_track_toggle_at;

#ifdef ENABLE_MQTT_CURL
    #define TEST_CLIENT_LOCK_COUNT 4
#else
    #define TEST_CLIENT_LOCK_COUNT 3
#endif

static void reset_sem_state(void)
{
    sem_init_calls = 0;
    sem_free_attempts = 0;
    sem_free_calls = 0;
    sem_invalid_free_calls = 0;
    sem_fail_all = 0;
    sem_fail_on_call = 0;
    sem_fail_free_on_call = 0;
    sem_complete_on_lock = NULL;
    sem_pending_to_complete = NULL;
    sem_pending_completions = 0;
    ping_read_calls = 0;
    ping_disconnect_calls = 0;
    sem_invalid_unlock_calls = 0;
    sem_watch_client_lock = NULL;
    sem_watch_recv_lock = NULL;
    sem_watch_ping_stat = NULL;
    sem_stale_ping_locks = 0;
    sem_watched_recv_locks = 0;
    sem_fail_lock = NULL;
    sem_fail_lock_while_held = NULL;
    sem_fail_lock_skip = 0;
    quota_write_calls = 0;
    sem_flag_client = NULL;
    sem_flag_bits = 0;
    sem_track_client = NULL;
    sem_track_while_held = NULL;
    sem_track_bit = 0;
    sem_track_before = 0;
    sem_track_count = 0;
    sem_track_counted = 0;
    sem_track_toggle_at = 0;
}

int wm_SemInit(wm_Sem* sem)
{
    (void)sem;
    sem_init_calls++;
    if (sem_fail_all || (sem_init_calls == sem_fail_on_call)) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    sem->initialized = 1;
    sem->lock_count = 0;
    return MQTT_CODE_SUCCESS;
}

int wm_SemFree(wm_Sem* sem)
{
    sem_free_attempts++;
    if (sem->initialized == 0) {
        sem_invalid_free_calls++;
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (sem_free_attempts == sem_fail_free_on_call) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    sem->initialized = 0;
    sem_free_calls++;
    return MQTT_CODE_SUCCESS;
}

int wm_SemLock(wm_Sem* sem)
{
    /* Fail one acquisition of sem_fail_lock made while
     * sem_fail_lock_while_held is owned (or any acquisition when it is NULL),
     * after skipping sem_fail_lock_skip such acquisitions, so a test can
     * target a single lock inside a larger operation. */
    if (sem == sem_fail_lock && (sem_fail_lock_while_held == NULL ||
            sem_fail_lock_while_held->lock_count > 0)) {
        if (sem_fail_lock_skip > 0) {
            sem_fail_lock_skip--;
        }
        else {
            sem_fail_lock = NULL;
            return MQTT_CODE_ERROR_SYSTEM;
        }
    }
    sem->lock_count++;
    if (sem_track_client != NULL && sem == &sem_track_client->lockClient &&
            (sem_track_while_held == NULL ||
             sem_track_while_held->lock_count > 0)) {
        sem_track_count++;
        sem_track_counted = 1;
        sem_track_before = sem_track_client->flags & sem_track_bit;
    }
    /* Model another thread that updated client->flags under lockClient and
     * released it just as this acquisition succeeded. */
    if (sem_flag_client != NULL && sem == &sem_flag_client->lockClient) {
        sem_flag_client->flags |= sem_flag_bits;
    }
    if (sem == sem_watch_recv_lock) {
        sem_watched_recv_locks++;
    }
    if (sem == sem_watch_client_lock && sem_watch_ping_stat != NULL &&
            sem_watched_recv_locks == 0 &&
            sem_watch_ping_stat->write == MQTT_MSG_WAIT &&
            sem_watch_ping_stat->read > MQTT_MSG_WAIT &&
            !sem_watch_ping_stat->isReadActive) {
        sem_stale_ping_locks++;
    }
    if (sem == sem_complete_on_lock && sem_pending_to_complete != NULL) {
        sem_pending_to_complete->packetDone = 1;
        sem_pending_to_complete->packet_ret = MQTT_CODE_SUCCESS;
        sem_pending_to_complete = NULL;
        sem_pending_completions++;
    }
    return MQTT_CODE_SUCCESS;
}

int wm_SemUnlock(wm_Sem* sem)
{
    if (sem_track_client != NULL && sem == &sem_track_client->lockClient &&
            sem_track_counted) {
        sem_track_counted = 0;
        if (sem_track_toggle_at == 0 &&
                (sem_track_client->flags & sem_track_bit) !=
                    sem_track_before) {
            sem_track_toggle_at = sem_track_count;
        }
    }
    if (sem->lock_count == 0) {
        sem_invalid_unlock_calls++;
    }
    else {
        sem->lock_count--;
    }
    return MQTT_CODE_SUCCESS;
}

static int ping_net_connect(void* context, const char* host, word16 port,
    int timeout_ms);
static int ping_net_write(void* context, const byte* buf, int buf_len,
    int timeout_ms);
static int ping_net_disconnect(void* context);

typedef struct SnPingFrames {
    const byte* frames[2];
    int lengths[2];
    int frame;
    int offset;
} SnPingFrames;

static int sn_ping_net_read(void* context, byte* buf, int buf_len,
    int timeout_ms)
{
    SnPingFrames* frames = (SnPingFrames*)context;
    int available;
    int read_len;

    (void)timeout_ms;
    if (frames->frame >= 2) {
        return MQTT_CODE_CONTINUE;
    }
    available = frames->lengths[frames->frame] - frames->offset;
    read_len = (buf_len < available) ? buf_len : available;
    XMEMCPY(buf, frames->frames[frames->frame] + frames->offset,
        (size_t)read_len);
    frames->offset += read_len;
    if (frames->offset == frames->lengths[frames->frame]) {
        frames->frame++;
        frames->offset = 0;
    }
    return read_len;
}

static int test_sn_null_ping_resets_terminal_read_state(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    SnPingFrames frames;
    byte tx_buf[64];
    byte rx_buf[64];
    static const byte malformed[] = {
        0x03, SN_MSG_TYPE_PING_RESP, 0x00
    };
    static const byte valid[] = { 0x02, SN_MSG_TYPE_PING_RESP };

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));
    XMEMSET(&frames, 0, sizeof(frames));
    frames.frames[0] = malformed;
    frames.lengths[0] = (int)sizeof(malformed);
    frames.frames[1] = valid;
    frames.lengths[1] = (int)sizeof(valid);
    net.context = &frames;
    net.connect = ping_net_connect;
    net.read = sn_ping_net_read;
    net.write = ping_net_write;
    net.disconnect = ping_net_disconnect;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "SN ping client initialization returned %d\n", rc);
        return 1;
    }
    (void)MqttClient_Flags(&client, 0, MQTT_CLIENT_FLAG_IS_DTLS);

    rc = SN_Client_Ping(&client, NULL);
    if (rc != MQTT_CODE_ERROR_MALFORMED_DATA) {
        fprintf(stderr, "malformed SN PINGRESP returned %d\n", rc);
        MqttClient_DeInit(&client);
        return 1;
    }
    sem_watch_client_lock = &client.lockClient;
    sem_watch_recv_lock = &client.lockRecv;
    sem_watch_ping_stat = &client.pingSN.stat;
    rc = SN_Client_Ping(&client, NULL);
    if (rc != MQTT_CODE_SUCCESS || frames.frame != 2 ||
            sem_invalid_unlock_calls != 0 || sem_stale_ping_locks != 0) {
        fprintf(stderr,
            "SN ping retry returned %d, frames=%d invalid unlocks=%d stale locks=%d\n",
            rc, frames.frame, sem_invalid_unlock_calls,
            sem_stale_ping_locks);
        MqttClient_DeInit(&client);
        return 1;
    }

    MqttClient_DeInit(&client);
    return 0;
}

static int ping_net_connect(void* context, const char* host, word16 port,
    int timeout_ms)
{
    (void)context;
    (void)host;
    (void)port;
    (void)timeout_ms;
    return MQTT_CODE_SUCCESS;
}

static int ping_net_read(void* context, byte* buf, int buf_len, int timeout_ms)
{
    (void)context;
    (void)buf;
    (void)buf_len;
    (void)timeout_ms;
    ping_read_calls++;
    return MQTT_CODE_ERROR_TIMEOUT;
}

static int ping_net_write(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    (void)context;
    (void)buf;
    (void)timeout_ms;
    return buf_len;
}

static int ping_net_disconnect(void* context)
{
    (void)context;
    ping_disconnect_calls++;
    return MQTT_CODE_SUCCESS;
}

static int test_ping_response_completed_during_read_lock(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    MqttPing ping;
    byte tx_buf[64];
    byte rx_buf[64];

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));
    XMEMSET(&ping, 0, sizeof(ping));
    net.connect = ping_net_connect;
    net.read = ping_net_read;
    net.write = ping_net_write;
    net.disconnect = ping_net_disconnect;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "ping-race client initialization returned %d\n", rc);
        return 1;
    }

    /* [MQTT-3.1.0-1] makes CONNECT the first packet a Client sends, so
     * MqttClient_Ping_ex refuses to run before one. This test drives the ping
     * path directly, so declare the post-CONNECT state it presumes. */
    (void)MqttClient_Flags(&client, 0, MQTT_CLIENT_FLAG_CONNECT_SENT);

    /* Model another reader delivering PINGRESP after the waiter's first
     * pending-response check but while that waiter acquires lockRecv. */
    sem_complete_on_lock = &client.lockRecv;
    sem_pending_to_complete = &ping.pendResp;
    rc = MqttClient_Ping_ex(&client, &ping);

    if (rc != MQTT_CODE_SUCCESS || sem_pending_completions != 1 ||
            ping_read_calls != 0 || ping_disconnect_calls != 0) {
        fprintf(stderr,
            "completed ping returned %d, completions=%d reads=%d disconnects=%d\n",
            rc, sem_pending_completions, ping_read_calls,
            ping_disconnect_calls);
        MqttClient_DeInit(&client);
        return 1;
    }

    MqttClient_DeInit(&client);
    return 0;
}

static int test_property_lock_failure(void)
{
    int rc;

    reset_sem_state();
    sem_fail_all = 1;

    rc = MqttProps_Init();
    if (rc != MQTT_CODE_ERROR_SYSTEM) {
        fprintf(stderr, "first property-lock failure returned %d\n", rc);
        return 1;
    }

    rc = MqttProps_Init();
    if (rc != MQTT_CODE_ERROR_SYSTEM) {
        fprintf(stderr, "second property-lock failure returned %d\n", rc);
        return 1;
    }
    if (sem_init_calls != 2) {
        fprintf(stderr, "property lock initialized %d times, expected 2\n",
            sem_init_calls);
        return 1;
    }

    (void)MqttProps_ShutDown();
    (void)MqttProps_ShutDown();
    if (sem_free_calls != 0) {
        fprintf(stderr, "uninitialized property lock freed %d times\n",
            sem_free_calls);
        return 1;
    }

    return 0;
}

static int test_partial_client_init(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    byte tx_buf[64];
    byte rx_buf[64];

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));
    /* Property lock and lockSend succeed; lockRecv fails. */
    sem_fail_on_call = 3;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_ERROR_SYSTEM) {
        fprintf(stderr, "partial client initialization returned %d\n", rc);
        return 1;
    }
    if (sem_init_calls != 3) {
        fprintf(stderr, "client initialized %d semaphores, expected 3\n",
            sem_init_calls);
        return 1;
    }
    if ((sem_free_calls != 2) || (sem_invalid_free_calls != 0)) {
        fprintf(stderr, "partial cleanup freed %d valid and %d invalid locks\n",
            sem_free_calls, sem_invalid_free_calls);
        return 1;
    }

    MqttClient_DeInit(&client);
    if ((sem_free_calls != 2) || (sem_invalid_free_calls != 0)) {
        fprintf(stderr, "repeat cleanup freed %d valid and %d invalid locks\n",
            sem_free_calls, sem_invalid_free_calls);
        return 1;
    }

    return 0;
}

static int test_failed_client_free_retried(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    byte tx_buf[64];
    byte rx_buf[64];

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));

    /* Let all locks initialize, then make socket validation fail so cleanup
     * runs; fail the first lock free while leaving that injected lock live. */
    sem_fail_free_on_call = 1;
    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_ERROR_BAD_ARG) {
        fprintf(stderr, "socket initialization failure returned %d\n", rc);
        return 1;
    }

    sem_fail_free_on_call = 0;
    MqttClient_DeInit(&client);

    if ((sem_free_attempts != TEST_CLIENT_LOCK_COUNT + 2) ||
            (sem_free_calls != TEST_CLIENT_LOCK_COUNT + 1) ||
            (sem_invalid_free_calls != 0)) {
        fprintf(stderr,
            "free retry made %d attempts, %d successes and %d invalid frees\n",
            sem_free_attempts, sem_free_calls, sem_invalid_free_calls);
        return 1;
    }

    return 0;
}

static int test_repeated_client_deinit_preserves_property_owner(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    byte tx_buf[64];
    byte rx_buf[64];

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));

    /* Hold one property reference on behalf of another live client. */
    rc = MqttProps_Init();
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "existing property owner initialization returned %d\n",
            rc);
        return 1;
    }

    /* This client initializes its locks, then fails socket validation and
     * performs its own cleanup before the explicit second deinit below. */
    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_ERROR_BAD_ARG) {
        fprintf(stderr, "failed client initialization returned %d\n", rc);
        (void)MqttProps_ShutDown();
        return 1;
    }
    MqttClient_DeInit(&client);

    if (sem_free_calls != TEST_CLIENT_LOCK_COUNT) {
        fprintf(stderr, "repeat deinit freed another client's property lock\n");
        (void)MqttProps_ShutDown();
        return 1;
    }

    (void)MqttProps_ShutDown();
    if (sem_free_calls != TEST_CLIENT_LOCK_COUNT + 1) {
        fprintf(stderr, "property owner cleanup freed %d locks, expected %d\n",
            sem_free_calls, TEST_CLIENT_LOCK_COUNT + 1);
        return 1;
    }

    return 0;
}

static int test_failed_property_free_retried(void)
{
    int rc;

    reset_sem_state();
    rc = MqttProps_Init();
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "property initialization returned %d\n", rc);
        return 1;
    }

    sem_fail_free_on_call = 1;
    rc = MqttProps_ShutDown();
    if (rc != MQTT_CODE_ERROR_SYSTEM) {
        fprintf(stderr, "property free failure returned %d\n", rc);
        return 1;
    }
    sem_fail_free_on_call = 0;
    rc = MqttProps_ShutDown();
    if ((rc != MQTT_CODE_SUCCESS) || (sem_free_attempts != 2) ||
            (sem_free_calls != 1)) {
        fprintf(stderr, "property free retry made %d attempts and %d frees\n",
            sem_free_attempts, sem_free_calls);
        return 1;
    }

    return 0;
}

static int quota_net_write(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    (void)context;
    (void)buf;
    (void)timeout_ms;
    quota_write_calls++;
    return buf_len;
}

/* [MQTT-3.3.4-9] The Client MUST NOT send more QoS 1/2 PUBLISH packets than
 * the server's Receive Maximum allows. If lockClient cannot be taken to
 * reserve a unit, the quota was never checked, so the PUBLISH must be refused
 * rather than sent. The quota is exhausted here so any send exceeds it. */
static int test_recv_quota_lock_failure_refuses_publish(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    MqttPublish publish;
    byte tx_buf[64];
    byte rx_buf[64];
    byte payload[1] = { 'x' };

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));
    XMEMSET(&publish, 0, sizeof(publish));
    net.connect = ping_net_connect;
    net.read = ping_net_read;
    net.write = quota_net_write;
    net.disconnect = ping_net_disconnect;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "quota client initialization returned %d\n", rc);
        return 1;
    }
    (void)MqttClient_Flags(&client, 0,
        MQTT_CLIENT_FLAG_CONNECT_SENT | MQTT_CLIENT_FLAG_IS_CONNECTED);
    client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    client.server_recv_max_negotiated = 1;
    client.server_recv_max = 0;

    publish.qos = MQTT_QOS_1;
    publish.packet_id = 1;
    publish.topic_name = "t";
    publish.buffer = payload;
    publish.total_len = (word32)sizeof(payload);

    /* With lockSend held, MqttWriteStart first takes lockClient to mark the
     * writer active; the next lockClient acquisition is the Receive Maximum
     * reservation, which is the one that fails. */
    sem_fail_lock = &client.lockClient;
    sem_fail_lock_while_held = &client.lockSend;
    sem_fail_lock_skip = 1;
    rc = MqttClient_Publish(&client, &publish);
    sem_fail_lock = NULL;
    sem_fail_lock_while_held = NULL;

    if (rc != MQTT_CODE_ERROR_SYSTEM || quota_write_calls != 0 ||
            publish.stat.recvQuotaHeld != 0 || client.server_recv_max != 0) {
        fprintf(stderr,
            "quota lock failure returned %d, writes=%d held=%d quota=%u\n",
            rc, quota_write_calls, publish.stat.recvQuotaHeld,
            (unsigned)client.server_recv_max);
        MqttClient_DeInit(&client);
        return 1;
    }

    MqttClient_DeInit(&client);
    return 0;
}

/* client->flags is shared with other threads and guarded by lockClient in
 * multithread builds, so the keep-alive check of NO_AUTO_KEEPALIVE must read
 * it under that lock. Here another thread disables automatic keep-alive under
 * lockClient; a read that bypasses the lock misses that update and sends a
 * PINGREQ the application has turned off. The ping is otherwise due:
 * keep-alive is negotiated and nothing has been sent since time 0. */
static int test_keepalive_flag_read_takes_client_lock(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    byte tx_buf[64];
    byte rx_buf[64];

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));
    net.connect = ping_net_connect;
    net.read = ping_net_read;
    net.write = quota_net_write;
    net.disconnect = ping_net_disconnect;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "keep-alive client initialization returned %d\n", rc);
        return 1;
    }
    (void)MqttClient_Flags(&client, 0, MQTT_CLIENT_FLAG_CONNECT_SENT |
        MQTT_CLIENT_FLAG_IS_CONNECTED);
    client.keep_alive_sec = 60;
    client.last_tx_time = 0;

    sem_flag_client = &client;
    sem_flag_bits = MQTT_CLIENT_FLAG_NO_AUTO_KEEPALIVE;
    rc = MqttClient_WaitMessage_ex(&client, &client.msg, 1000);
    sem_flag_client = NULL;

    if (quota_write_calls != 0) {
        fprintf(stderr,
            "keep-alive ignored a locked flag update: rc=%d writes=%d\n",
            rc, quota_write_calls);
        MqttClient_DeInit(&client);
        return 1;
    }

    MqttClient_DeInit(&client);
    return 0;
}

static int io_lock_disconnect_calls;

static int io_lock_net_disconnect(void* context)
{
    (void)context;
    io_lock_disconnect_calls++;
    if (io_lock_client != NULL) {
        io_locks_held_at_close =
            (io_lock_client->lockRecv.lock_count > 0 &&
             io_lock_client->lockSend.lock_count > 0);
    }
    return MQTT_CODE_SUCCESS;
}

/* MqttClient_NetDisconnect_Wait releases the transport only while holding
 * lockRecv and lockSend, so no read or write on another thread can still be
 * using socket or TLS state when it is freed. The transport's disconnect
 * callback records whether both I/O locks were held when it ran. */
static int test_net_disconnect_wait_holds_io_locks(void)
{
    int rc;
    MqttClient client;
    MqttNet net;
    byte tx_buf[64];
    byte rx_buf[64];

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));
    net.connect = ping_net_connect;
    net.read = ping_net_read;
    net.write = ping_net_write;
    net.disconnect = io_lock_net_disconnect;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "disconnect-wait client initialization returned %d\n",
            rc);
        return 1;
    }
    (void)MqttClient_Flags(&client, 0, MQTT_CLIENT_FLAG_IS_CONNECTED);
    io_lock_client = &client;
    io_locks_held_at_close = 0;

    rc = MqttClient_NetDisconnect_Wait(&client);
    io_lock_client = NULL;

    if (rc != MQTT_CODE_SUCCESS || !io_locks_held_at_close ||
            client.lockRecv.lock_count != 0 ||
            client.lockSend.lock_count != 0 ||
            (MqttClient_Flags(&client, 0, 0) &
                MQTT_CLIENT_FLAG_IS_CONNECTED) != 0) {
        fprintf(stderr,
            "disconnect-wait rc=%d locks_held=%d recv=%d send=%d\n",
            rc, io_locks_held_at_close, client.lockRecv.lock_count,
            client.lockSend.lock_count);
        MqttClient_DeInit(&client);
        return 1;
    }

    MqttClient_DeInit(&client);
    return 0;
}

/* If lockSend cannot be taken, MqttClient_NetDisconnect_Wait must release
 * the lockRecv it already holds and leave the transport alone; if lockRecv
 * cannot be taken, it must not touch the transport either. */
static int run_net_disconnect_wait_lock_failure(int fail_send)
{
    int rc;
    MqttClient client;
    MqttNet net;
    byte tx_buf[64];
    byte rx_buf[64];
    int fail = 0;

    reset_sem_state();
    XMEMSET(&net, 0, sizeof(net));
    net.connect = ping_net_connect;
    net.read = ping_net_read;
    net.write = ping_net_write;
    net.disconnect = io_lock_net_disconnect;

    rc = MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
        rx_buf, sizeof(rx_buf), 1000);
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "lock-failure client initialization returned %d\n",
            rc);
        return 1;
    }
    (void)MqttClient_Flags(&client, 0, MQTT_CLIENT_FLAG_IS_CONNECTED);
    io_lock_disconnect_calls = 0;
    if (fail_send) {
        sem_fail_lock = &client.lockSend;
        sem_fail_lock_while_held = &client.lockRecv;
    }
    else {
        sem_fail_lock = &client.lockRecv;
        sem_fail_lock_while_held = NULL;
    }

    rc = MqttClient_NetDisconnect_Wait(&client);
    sem_fail_lock = NULL;
    sem_fail_lock_while_held = NULL;

    if (rc != MQTT_CODE_ERROR_SYSTEM || io_lock_disconnect_calls != 0 ||
            client.lockRecv.lock_count != 0 ||
            client.lockSend.lock_count != 0 ||
            (MqttClient_Flags(&client, 0, 0) &
                MQTT_CLIENT_FLAG_IS_CONNECTED) == 0) {
        fprintf(stderr,
            "disconnect-wait fail_send=%d rc=%d closes=%d recv=%d send=%d\n",
            fail_send, rc, io_lock_disconnect_calls,
            client.lockRecv.lock_count, client.lockSend.lock_count);
        fail = 1;
    }

    MqttClient_DeInit(&client);
    return fail;
}

typedef struct AuthWindowNet {
    int connack_pos;
    int writes;
} AuthWindowNet;

/* v5 CONNACK (MQTT 5.0 section 3.2): accepted, Session Present 0, Property
 * Length 0. */
static const byte auth_window_connack[] = { 0x20, 0x03, 0x00, 0x00, 0x00 };

static int auth_window_net_read(void* context, byte* buf, int buf_len,
    int timeout_ms)
{
    AuthWindowNet* an = (AuthWindowNet*)context;
    int n = (int)sizeof(auth_window_connack) - an->connack_pos;

    (void)timeout_ms;
    if (n <= 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (n > buf_len) {
        n = buf_len;
    }
    XMEMCPY(buf, auth_window_connack + an->connack_pos, (size_t)n);
    an->connack_pos += n;
    return n;
}

static int auth_window_net_write(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    AuthWindowNet* an = (AuthWindowNet*)context;

    (void)buf;
    (void)timeout_ms;
    an->writes++;
    return buf_len;
}

/* Runs one v5 CONNECT, carrying an Authentication Method when with_method is
 * set, against a CONNACK. When fail_at is non-zero, the fail_at'th lockClient
 * acquisition made while while_held is owned fails. Otherwise the run records
 * in sem_track_toggle_at which acquisition changed AUTH_PENDING. */
static int run_auth_window_connect(MqttClient* client, AuthWindowNet* an,
    int with_method, wm_Sem* (*while_held)(MqttClient*), int fail_at)
{
    MqttConnect connect;
    MqttProp method_prop;
    int rc;

    XMEMSET(an, 0, sizeof(*an));
    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "auth";
    if (with_method) {
        XMEMSET(&method_prop, 0, sizeof(method_prop));
        method_prop.type = MQTT_PROP_AUTH_METHOD;
        method_prop.data_str.str = (char*)"m";
        method_prop.data_str.len = 1;
        connect.props = &method_prop;
    }
    (void)MqttClient_Flags(client, MQTT_CLIENT_FLAG_CONNECT_SENT,
        MQTT_CLIENT_FLAG_IS_CONNECTED);

    sem_track_client = client;
    sem_track_while_held = while_held(client);
    sem_track_bit = MQTT_CLIENT_FLAG_AUTH_PENDING;
    sem_track_count = 0;
    sem_track_counted = 0;
    sem_track_toggle_at = 0;
    if (fail_at > 0) {
        sem_fail_lock = &client->lockClient;
        sem_fail_lock_while_held = while_held(client);
        sem_fail_lock_skip = fail_at - 1;
    }
    rc = MqttClient_Connect(client, &connect);
    sem_fail_lock = NULL;
    sem_fail_lock_while_held = NULL;
    sem_fail_lock_skip = 0;
    sem_track_client = NULL;
    return rc;
}

static wm_Sem* auth_window_send_lock(MqttClient* client)
{
    return &client->lockSend;
}

static wm_Sem* auth_window_recv_lock(MqttClient* client)
{
    return &client->lockRecv;
}

static int auth_window_client_init(MqttClient* client, MqttNet* net,
    AuthWindowNet* an, byte* tx_buf, byte* rx_buf, int buf_len)
{
    XMEMSET(net, 0, sizeof(*net));
    net->context = an;
    net->connect = ping_net_connect;
    net->read = auth_window_net_read;
    net->write = auth_window_net_write;
    net->disconnect = ping_net_disconnect;
    return MqttClient_Init(client, net, NULL, tx_buf, buf_len, rx_buf,
        buf_len, 1000);
}

/* [MQTT-3.1.2-30] With an Authentication Method only AUTH or DISCONNECT may
 * follow CONNECT until the CONNACK. If lockClient fails while raising that
 * window, the CONNECT must not be sent, since nothing would hold back other
 * packets, and no lock or pending response may be left behind. */
static int test_auth_window_set_lock_failure(void)
{
    int rc;
    int set_at;
    MqttClient client;
    MqttNet net;
    AuthWindowNet an;
    byte tx_buf[64];
    byte rx_buf[64];
    int fail = 0;

    reset_sem_state();
    rc = auth_window_client_init(&client, &net, &an, tx_buf, rx_buf,
        (int)sizeof(tx_buf));
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "auth-window client initialization returned %d\n",
            rc);
        return 1;
    }

    /* Learn which acquisition under lockSend raises the window. */
    rc = run_auth_window_connect(&client, &an, 1, auth_window_send_lock, 0);
    set_at = sem_track_toggle_at;
    MqttClient_DeInit(&client);
    if (rc != MQTT_CODE_SUCCESS || set_at == 0) {
        fprintf(stderr, "auth-window dry run rc=%d set_at=%d\n", rc, set_at);
        return 1;
    }

    reset_sem_state();
    rc = auth_window_client_init(&client, &net, &an, tx_buf, rx_buf,
        (int)sizeof(tx_buf));
    if (rc != MQTT_CODE_SUCCESS) {
        return 1;
    }
    rc = run_auth_window_connect(&client, &an, 1, auth_window_send_lock,
        set_at);
    if (rc != MQTT_CODE_ERROR_SYSTEM || an.writes != 0 ||
            client.lockSend.lock_count != 0 ||
            client.lockClient.lock_count != 0 ||
            client.firstPendResp != NULL ||
            (client.flags & MQTT_CLIENT_FLAG_CONNECT_SENT) != 0) {
        fprintf(stderr,
            "auth-window set failure rc=%d writes=%d send=%d client=%d "
            "pend=%p flags=0x%x\n", rc, an.writes,
            client.lockSend.lock_count, client.lockClient.lock_count,
            (void*)client.firstPendResp, (unsigned)client.flags);
        fail = 1;
    }

    MqttClient_DeInit(&client);
    return fail;
}

/* If lockClient fails while the CONNACK closes the authentication window, the
 * CONNACK must fail rather than leave the window silently open-ended, and the
 * next CONNECT must reset the stale flag. */
static int test_auth_window_clear_lock_failure(void)
{
    int rc;
    int clear_at;
    MqttClient client;
    MqttNet net;
    AuthWindowNet an;
    byte tx_buf[64];
    byte rx_buf[64];
    int fail = 0;

    reset_sem_state();
    rc = auth_window_client_init(&client, &net, &an, tx_buf, rx_buf,
        (int)sizeof(tx_buf));
    if (rc != MQTT_CODE_SUCCESS) {
        fprintf(stderr, "auth-window client initialization returned %d\n",
            rc);
        return 1;
    }

    /* Learn which acquisition under lockRecv closes the window. */
    rc = run_auth_window_connect(&client, &an, 1, auth_window_recv_lock, 0);
    clear_at = sem_track_toggle_at;
    MqttClient_DeInit(&client);
    if (rc != MQTT_CODE_SUCCESS || clear_at == 0) {
        fprintf(stderr, "auth-window dry run rc=%d clear_at=%d\n", rc,
            clear_at);
        return 1;
    }

    reset_sem_state();
    rc = auth_window_client_init(&client, &net, &an, tx_buf, rx_buf,
        (int)sizeof(tx_buf));
    if (rc != MQTT_CODE_SUCCESS) {
        return 1;
    }
    rc = run_auth_window_connect(&client, &an, 1, auth_window_recv_lock,
        clear_at);
    if (rc != MQTT_CODE_ERROR_SYSTEM ||
            client.lockRecv.lock_count != 0 ||
            client.lockClient.lock_count != 0) {
        fprintf(stderr, "auth-window clear failure rc=%d recv=%d client=%d\n",
            rc, client.lockRecv.lock_count, client.lockClient.lock_count);
        fail = 1;
    }

    /* A later CONNECT without a method resets the window it left set. */
    if (!fail) {
        rc = run_auth_window_connect(&client, &an, 0, auth_window_send_lock,
            0);
        if (rc != MQTT_CODE_SUCCESS ||
                (client.flags & MQTT_CLIENT_FLAG_AUTH_PENDING) != 0) {
            fprintf(stderr, "auth-window reconnect rc=%d flags=0x%x\n", rc,
                (unsigned)client.flags);
            fail = 1;
        }
    }

    MqttClient_DeInit(&client);
    return fail;
}

int main(void)
{
    if (test_sn_null_ping_resets_terminal_read_state() != 0) {
        return 1;
    }
    if (test_ping_response_completed_during_read_lock() != 0) {
        return 1;
    }
    if (test_property_lock_failure() != 0) {
        return 1;
    }
    if (test_partial_client_init() != 0) {
        return 1;
    }
    if (test_failed_client_free_retried() != 0) {
        return 1;
    }
    if (test_failed_property_free_retried() != 0) {
        return 1;
    }
    if (test_repeated_client_deinit_preserves_property_owner() != 0) {
        return 1;
    }
    if (test_recv_quota_lock_failure_refuses_publish() != 0) {
        return 1;
    }
    if (test_keepalive_flag_read_takes_client_lock() != 0) {
        return 1;
    }
    if (test_net_disconnect_wait_holds_io_locks() != 0) {
        return 1;
    }
    if (run_net_disconnect_wait_lock_failure(1) != 0) {
        return 1;
    }
    if (run_net_disconnect_wait_lock_failure(0) != 0) {
        return 1;
    }
    if (test_auth_window_set_lock_failure() != 0) {
        return 1;
    }
    if (test_auth_window_clear_lock_failure() != 0) {
        return 1;
    }
    return 0;
}
