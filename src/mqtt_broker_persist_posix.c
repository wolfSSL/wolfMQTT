/* mqtt_broker_persist_posix.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Default POSIX file-based persistence backend.
 *
 * Layout under <root>:
 *
 *   <root>/<ns_decimal>/<hex(key)>.bin
 *
 * One file per record. Atomic update via write-tmp + fsync + rename +
 * fsync directory. kv_iter walks the namespace directory, decodes hex
 * filenames back to key bytes, and invokes the supplied callback with
 * the full blob.
 *
 * Concurrency is not supported - a single broker process owns the
 * tree. The directory is created on first init (with mode 0700 to keep
 * persisted data accessible only to the broker user). */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_broker.h"

#ifdef WOLFMQTT_BROKER_PERSIST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

/* Context held by the backend. Lives inside the hooks->ctx pointer. */
typedef struct WmqbPosixCtx {
    char dir[512];
    /* Per-instance flag so Free knows we own this allocation. */
    int  owned;
} WmqbPosixCtx;

/* Forward decl of all hook callbacks. */
static int wmqb_posix_put(void* ctx, byte ns, const byte* key, word16 key_len,
    const byte* blob, word32 blob_len);
static int wmqb_posix_get(void* ctx, byte ns, const byte* key, word16 key_len,
    byte* out, word32* inout_len);
static int wmqb_posix_del(void* ctx, byte ns, const byte* key, word16 key_len);
static int wmqb_posix_iter(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
    void* cb_ctx);
static int wmqb_posix_sync(void* ctx);

/* hex encode key bytes into out (must be 2*key_len+1). Lowercase. */
static void wmqb_hex_encode(char* out, const byte* in, word16 in_len)
{
    static const char hex[] = "0123456789abcdef";
    word16 i;
    for (i = 0; i < in_len; i++) {
        out[2 * i]     = hex[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hex[in[i] & 0xF];
    }
    out[2 * in_len] = '\0';
}

/* hex decode a NUL-terminated hex string into out. Returns the byte
 * length on success, -1 on malformed input. */
static int wmqb_hex_decode(const char* in, byte* out, word16 out_cap)
{
    word16 n;
    word16 i;
    if (in == NULL) {
        return -1;
    }
    n = (word16)XSTRLEN(in);
    if ((n & 1) != 0 || (n / 2) > out_cap) {
        return -1;
    }
    for (i = 0; i < n / 2; i++) {
        byte hi, lo;
        char c = in[2 * i];
        if (c >= '0' && c <= '9') hi = (byte)(c - '0');
        else if (c >= 'a' && c <= 'f') hi = (byte)(10 + c - 'a');
        else if (c >= 'A' && c <= 'F') hi = (byte)(10 + c - 'A');
        else return -1;
        c = in[2 * i + 1];
        if (c >= '0' && c <= '9') lo = (byte)(c - '0');
        else if (c >= 'a' && c <= 'f') lo = (byte)(10 + c - 'a');
        else if (c >= 'A' && c <= 'F') lo = (byte)(10 + c - 'A');
        else return -1;
        out[i] = (byte)((hi << 4) | lo);
    }
    return n / 2;
}

/* Build "<root>/<ns>" path. Returns 0 on success, negative on overflow. */
static int wmqb_ns_dir(const WmqbPosixCtx* c, byte ns, char* out,
    size_t out_cap)
{
    int n = snprintf(out, out_cap, "%s/%u", c->dir, (unsigned)ns);
    if (n <= 0 || (size_t)n >= out_cap) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    return 0;
}

/* Build "<root>/<ns>/<hex>.bin" path. */
static int wmqb_rec_path(const WmqbPosixCtx* c, byte ns, const byte* key,
    word16 key_len, char* out, size_t out_cap)
{
    char hex[2 * 256 + 1];
    int n;
    if (key_len > 256) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    wmqb_hex_encode(hex, key, key_len);
    n = snprintf(out, out_cap, "%s/%u/%s.bin", c->dir, (unsigned)ns, hex);
    if (n <= 0 || (size_t)n >= out_cap) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    return 0;
}

/* mkdir -p semantics for a single trailing component. Tolerates EEXIST. */
static int wmqb_mkdir(const char* path)
{
    if (mkdir(path, 0700) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return MQTT_CODE_ERROR_SYSTEM;
}

/* Ensure <root>/<ns> exists. Idempotent. */
static int wmqb_ensure_ns_dir(const WmqbPosixCtx* c, byte ns)
{
    char path[576];
    int rc;
    rc = wmqb_mkdir(c->dir);
    if (rc != 0) {
        return rc;
    }
    rc = wmqb_ns_dir(c, ns, path, sizeof(path));
    if (rc != 0) {
        return rc;
    }
    return wmqb_mkdir(path);
}

/* fsync a directory by open() + fsync() + close(). Best-effort. */
static void wmqb_fsync_dir(const char* path)
{
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        (void)fsync(fd);
        (void)close(fd);
    }
}

/* kv_put: write to <root>/<ns>/<hex>.bin.tmp, fsync, rename, fsync dir. */
static int wmqb_posix_put(void* ctx, byte ns, const byte* key,
    word16 key_len, const byte* blob, word32 blob_len)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    char final_path[640];
    char tmp_path[660];
    char ns_path[576];
    int  fd;
    int  rc;
    ssize_t w;
    word32 written = 0;

    if (c == NULL || key == NULL || blob == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_ensure_ns_dir(c, ns);
    if (rc != 0) {
        return rc;
    }
    rc = wmqb_rec_path(c, ns, key, key_len, final_path, sizeof(final_path));
    if (rc != 0) {
        return rc;
    }
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path) <= 0) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }

    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    while (written < blob_len) {
        w = write(fd, blob + written, blob_len - written);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)close(fd);
            (void)unlink(tmp_path);
            return MQTT_CODE_ERROR_SYSTEM;
        }
        written += (word32)w;
    }
    if (fsync(fd) < 0) {
        (void)close(fd);
        (void)unlink(tmp_path);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    (void)close(fd);
    if (rename(tmp_path, final_path) < 0) {
        (void)unlink(tmp_path);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    /* fsync the namespace dir so rename is durable. */
    if (wmqb_ns_dir(c, ns, ns_path, sizeof(ns_path)) == 0) {
        wmqb_fsync_dir(ns_path);
    }
    return 0;
}

static int wmqb_posix_get(void* ctx, byte ns, const byte* key,
    word16 key_len, byte* out, word32* inout_len)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    char path[640];
    int  fd;
    int  rc;
    ssize_t r;
    word32 cap;
    word32 read_total = 0;

    if (c == NULL || key == NULL || inout_len == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    cap = *inout_len;
    rc = wmqb_rec_path(c, ns, key, key_len, path, sizeof(path));
    if (rc != 0) {
        return rc;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            *inout_len = 0;
            return MQTT_CODE_ERROR_NOT_FOUND;
        }
        return MQTT_CODE_ERROR_SYSTEM;
    }
    while (read_total < cap) {
        r = read(fd, out + read_total, cap - read_total);
        if (r == 0) {
            break;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)close(fd);
            return MQTT_CODE_ERROR_SYSTEM;
        }
        read_total += (word32)r;
    }
    (void)close(fd);
    *inout_len = read_total;
    return 0;
}

static int wmqb_posix_del(void* ctx, byte ns, const byte* key,
    word16 key_len)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    char path[640];
    char ns_path[576];
    int  rc;

    if (c == NULL || key == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_rec_path(c, ns, key, key_len, path, sizeof(path));
    if (rc != 0) {
        return rc;
    }
    if (unlink(path) < 0) {
        if (errno == ENOENT) {
            return 0;
        }
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (wmqb_ns_dir(c, ns, ns_path, sizeof(ns_path)) == 0) {
        wmqb_fsync_dir(ns_path);
    }
    return 0;
}

static int wmqb_posix_iter(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
    void* cb_ctx)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    char ns_path[576];
    DIR* d;
    struct dirent* ent;
    int rc;

    if (c == NULL || cb == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_ns_dir(c, ns, ns_path, sizeof(ns_path));
    if (rc != 0) {
        return rc;
    }
    d = opendir(ns_path);
    if (d == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        return MQTT_CODE_ERROR_SYSTEM;
    }
    while ((ent = readdir(d)) != NULL) {
        char rec_path[640];
        char key_hex[2 * 256 + 1];
        byte key_buf[256];
        byte* blob;
        word32 blob_cap;
        struct stat st;
        int fd;
        ssize_t r;
        word32 read_total;
        int kn;
        size_t nlen;
        const char* dot;
        int stop;

        if (ent->d_name[0] == '.') {
            continue;
        }
        nlen = strlen(ent->d_name);
        if (nlen < 5) {
            continue;
        }
        dot = ent->d_name + nlen - 4;
        if (strcmp(dot, ".bin") != 0) {
            continue;
        }
        if ((nlen - 4) >= sizeof(key_hex)) {
            continue;
        }
        XMEMCPY(key_hex, ent->d_name, nlen - 4);
        key_hex[nlen - 4] = '\0';
        kn = wmqb_hex_decode(key_hex, key_buf, sizeof(key_buf));
        if (kn < 0) {
            continue;
        }
        if (snprintf(rec_path, sizeof(rec_path), "%s/%s", ns_path,
                ent->d_name) <= 0) {
            continue;
        }
        if (stat(rec_path, &st) < 0) {
            continue;
        }
        if (st.st_size <= 0 || (word64)st.st_size > 16 * 1024 * 1024) {
            /* Sanity cap: refuse to load records larger than 16 MiB. */
            continue;
        }
        blob_cap = (word32)st.st_size;
        blob = (byte*)WOLFMQTT_MALLOC(blob_cap);
        if (blob == NULL) {
            (void)closedir(d);
            return MQTT_CODE_ERROR_MEMORY;
        }
        fd = open(rec_path, O_RDONLY);
        if (fd < 0) {
            WOLFMQTT_FREE(blob);
            continue;
        }
        read_total = 0;
        while (read_total < blob_cap) {
            r = read(fd, blob + read_total, blob_cap - read_total);
            if (r == 0) {
                break;
            }
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            read_total += (word32)r;
        }
        (void)close(fd);
        if (read_total != blob_cap) {
            WOLFMQTT_FREE(blob);
            continue;
        }
        stop = cb(key_buf, (word16)kn, blob, blob_cap, cb_ctx);
        WOLFMQTT_FREE(blob);
        if (stop != 0) {
            break;
        }
    }
    (void)closedir(d);
    return 0;
}

static int wmqb_posix_sync(void* ctx)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    /* The per-op fsync in put/del already covered the data + the
     * namespace dir. A top-level fsync of the root dir here ensures
     * any namespace-dir creates are durable too. */
    if (c == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    wmqb_fsync_dir(c->dir);
    return 0;
}

int MqttBrokerNet_PersistPosix_Init(MqttBrokerPersistHooks* hooks,
    const char* dir)
{
    WmqbPosixCtx* c;
    const char* use_dir = (dir != NULL) ? dir : BROKER_PERSIST_DIR_DEFAULT;
    size_t dlen;

    if (hooks == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    dlen = strlen(use_dir);
    if (dlen == 0 || dlen >= sizeof(((WmqbPosixCtx*)0)->dir)) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    c = (WmqbPosixCtx*)WOLFMQTT_MALLOC(sizeof(*c));
    if (c == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(c, 0, sizeof(*c));
    XMEMCPY(c->dir, use_dir, dlen);
    c->dir[dlen] = '\0';
    c->owned = 1;

    XMEMSET(hooks, 0, sizeof(*hooks));
    hooks->kv_put     = wmqb_posix_put;
    hooks->kv_get     = wmqb_posix_get;
    hooks->kv_del     = wmqb_posix_del;
    hooks->kv_iter    = wmqb_posix_iter;
    hooks->sync       = wmqb_posix_sync;
    hooks->ctx        = c;

    /* Create root dir up front so first put doesn't race. Tolerates
     * EEXIST inside wmqb_mkdir. Failure here is non-fatal at init time:
     * the first put will retry and surface any persistent error. */
    (void)wmqb_mkdir(c->dir);
    return 0;
}

void MqttBrokerNet_PersistPosix_Free(MqttBrokerPersistHooks* hooks)
{
    WmqbPosixCtx* c;
    if (hooks == NULL) {
        return;
    }
    c = (WmqbPosixCtx*)hooks->ctx;
    if (c != NULL && c->owned) {
        WOLFMQTT_FREE(c);
    }
    XMEMSET(hooks, 0, sizeof(*hooks));
}

#endif /* WOLFMQTT_BROKER_PERSIST */
