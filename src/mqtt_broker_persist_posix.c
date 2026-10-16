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
    int  root_fd;
    /* Per-instance flag so Free knows we own this allocation. */
    int  owned;
} WmqbPosixCtx;

#ifndef O_CLOEXEC
    #define O_CLOEXEC 0
#endif

/* Overridable so tests can inject durability failures. */
#ifndef WMQB_POSIX_FSYNC
    #define WMQB_POSIX_FSYNC(fd) fsync(fd)
#endif

/* Flush a namespace directory so a rename or unlink in it survives a crash.
 * Retries a bounded number of EINTRs, like the record write loop. */
static int wmqb_posix_fsync_dir(int dir_fd)
{
    int eintr_count = 0;

    while (WMQB_POSIX_FSYNC(dir_fd) < 0) {
        if (errno == EINTR && eintr_count++ < 16) {
            continue;
        }
        return MQTT_CODE_ERROR_SYSTEM;
    }
    return 0;
}

/* Forward decl of all hook callbacks. */
static int wmqb_posix_put(void* ctx, byte ns, const byte* key, word16 key_len,
    const byte* blob, word32 blob_len);
static int wmqb_posix_get(void* ctx, byte ns, const byte* key, word16 key_len,
    byte* out, word32* inout_len);
static int wmqb_posix_del(void* ctx, byte ns, const byte* key, word16 key_len);
static int wmqb_posix_iter(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
    void* cb_ctx);
static int wmqb_posix_sync(void* ctx);

/* Secure zeroing via a volatile pointer so the compiler cannot elide the
 * stores. Kept file-local because MqttClient_ForceZero has hidden linkage
 * and is not reachable from the standalone broker program. */
static void wmqb_posix_force_zero(void* mem, word32 len)
{
    volatile byte* p = (volatile byte*)mem;
    word32 i;
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

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
    size_t raw_len;
    if (in == NULL) {
        return -1;
    }
    /* Reject pathological inputs whose length would silently truncate
     * on the word16 cast below and slip through as a shorter-but-valid
     * decode. */
    raw_len = XSTRLEN(in);
    if (raw_len > 0xFFFFu) {
        return -1;
    }
    n = (word16)raw_len;
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

static int wmqb_validate_dir(int fd)
{
    struct stat st;

    if (fstat(fd, &st) < 0 || !S_ISDIR(st.st_mode) ||
            st.st_uid != geteuid() ||
            (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    return 0;
}

static int wmqb_normalize_root(const char* path, char* out, size_t out_sz)
{
    const char* prefix = "";
    size_t path_len;
    size_t prefix_len;

    if (path == NULL || out == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
#ifdef __MACH__
    if (XSTRCMP(path, "/tmp") == 0 || XSTRNCMP(path, "/tmp/", 5) == 0 ||
            XSTRCMP(path, "/var") == 0 ||
            XSTRNCMP(path, "/var/", 5) == 0) {
        prefix = "/private";
    }
#endif
    path_len = XSTRLEN(path);
    prefix_len = XSTRLEN(prefix);
    if (path_len == 0 || prefix_len + path_len >= out_sz) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMCPY(out, prefix, prefix_len);
    XMEMCPY(out + prefix_len, path, path_len + 1);
    return MQTT_CODE_SUCCESS;
}

/* Resolve every configured root component relative to a trusted descriptor.
 * Symlinks and ".." are rejected, and only the final component is created.
 * The returned descriptor pins the validated tree even if an ancestor is
 * later renamed. */
static int wmqb_open_root(const char* path, int* root_fd)
{
    char work[512];
    char* component;
    char* next;
    int current_fd;
    int next_fd;
    int is_last;
    size_t path_len;

    if (path == NULL || root_fd == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    path_len = XSTRLEN(path);
    if (path_len == 0 || path_len >= sizeof(work)) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMCPY(work, path, path_len + 1);
    current_fd = open(path[0] == '/' ? "/" : ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current_fd < 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }

    component = work;
    while (*component == '/') {
        component++;
    }
    while (*component != '\0') {
        next = component;
        while (*next != '\0' && *next != '/') {
            next++;
        }
        if (*next == '/') {
            *next = '\0';
            next++;
            while (*next == '/') {
                next++;
            }
        }
        is_last = (*next == '\0');
        if (XSTRCMP(component, ".") == 0) {
            component = next;
            continue;
        }
        if (XSTRCMP(component, "..") == 0) {
            (void)close(current_fd);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
        next_fd = openat(current_fd, component,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0 && errno == ENOENT && is_last) {
            if (mkdirat(current_fd, component, 0700) < 0 && errno != EEXIST) {
                (void)close(current_fd);
                return MQTT_CODE_ERROR_SYSTEM;
            }
            next_fd = openat(current_fd, component,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next_fd < 0) {
            (void)close(current_fd);
            return MQTT_CODE_ERROR_SYSTEM;
        }
        (void)close(current_fd);
        current_fd = next_fd;
        component = next;
    }
    if (wmqb_validate_dir(current_fd) != 0) {
        (void)close(current_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    *root_fd = current_fd;
    return 0;
}

static int wmqb_open_ns(const WmqbPosixCtx* c, byte ns, int create,
    int* ns_fd)
{
    char ns_name[4];
    int fd;
    int n;

    if (c == NULL || c->root_fd < 0 || ns_fd == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    n = snprintf(ns_name, sizeof(ns_name), "%u", (unsigned)ns);
    if (n <= 0 || (size_t)n >= sizeof(ns_name)) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    fd = openat(c->root_fd, ns_name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && create) {
        if (mkdirat(c->root_fd, ns_name, 0700) < 0 && errno != EEXIST) {
            return MQTT_CODE_ERROR_SYSTEM;
        }
        fd = openat(c->root_fd, ns_name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0) {
        return (errno == ENOENT) ? MQTT_CODE_ERROR_NOT_FOUND :
            MQTT_CODE_ERROR_SYSTEM;
    }
    if (wmqb_validate_dir(fd) != 0) {
        (void)close(fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    *ns_fd = fd;
    return 0;
}

static int wmqb_rec_name(const byte* key, word16 key_len, char* out,
    size_t out_cap)
{
    char hex[2 * 256 + 1];
    int n;

    if (key == NULL || out == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (key_len > 256) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    wmqb_hex_encode(hex, key, key_len);
    n = snprintf(out, out_cap, "%s.bin", hex);
    if (n <= 0 || (size_t)n >= out_cap) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    return 0;
}

/* kv_put: write to <root>/<ns>/<hex>.bin.tmp, fsync, rename, fsync dir. */
static int wmqb_posix_put(void* ctx, byte ns, const byte* key,
    word16 key_len, const byte* blob, word32 blob_len)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    char final_name[2 * 256 + 5];
    char tmp_name[2 * 256 + 9];
    struct stat st;
    int fd;
    int ns_fd = -1;
    int rc;
    int saved_errno;
    ssize_t w;
    word32 written = 0;

    if (c == NULL || key == NULL || blob == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_open_ns(c, ns, 1, &ns_fd);
    if (rc != 0) {
        return rc;
    }
    rc = wmqb_rec_name(key, key_len, final_name, sizeof(final_name));
    if (rc != 0) {
        (void)close(ns_fd);
        return rc;
    }
    {
        int n = snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);
        if (n < 0 || (size_t)n >= sizeof(tmp_name)) {
            (void)close(ns_fd);
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
    }

    fd = openat(ns_fd, tmp_name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) {
        struct stat old_st;

        /* A crash can leave the broker's regular temp file behind. Reclaim
         * only an owned, single-link, non-writable file; never remove a
         * symlink or other attacker-supplied object. The namespace itself is
         * validated as 0700-equivalent, so another uid cannot race this
         * check and unlink. */
        if (fstatat(ns_fd, tmp_name, &old_st, AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISREG(old_st.st_mode) && old_st.st_uid == geteuid() &&
                old_st.st_nlink == 1 &&
                (old_st.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
                unlinkat(ns_fd, tmp_name, 0) == 0) {
            fd = openat(ns_fd, tmp_name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        }
    }
    if (fd < 0) {
        (void)close(ns_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != geteuid() || st.st_nlink != 1) {
        (void)close(fd);
        (void)unlinkat(ns_fd, tmp_name, 0);
        (void)close(ns_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    {
        /* Bounded EINTR retry. A signal storm should not cause an
         * unbounded spin; bail with SYSTEM after 16 EINTRs so the
         * caller can decide what to do. */
        int eintr_count = 0;
        while (written < blob_len) {
            w = write(fd, blob + written, blob_len - written);
            if (w < 0) {
                if (errno == EINTR && eintr_count++ < 16) {
                    continue;
                }
                (void)close(fd);
                (void)unlinkat(ns_fd, tmp_name, 0);
                (void)close(ns_fd);
                return MQTT_CODE_ERROR_SYSTEM;
            }
            if (w == 0) {
                (void)close(fd);
                (void)unlinkat(ns_fd, tmp_name, 0);
                (void)close(ns_fd);
                return MQTT_CODE_ERROR_SYSTEM;
            }
            written += (word32)w;
        }
    }
    if (WMQB_POSIX_FSYNC(fd) < 0) {
        (void)close(fd);
        (void)unlinkat(ns_fd, tmp_name, 0);
        (void)close(ns_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (close(fd) < 0) {
        (void)unlinkat(ns_fd, tmp_name, 0);
        (void)close(ns_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (renameat(ns_fd, tmp_name, ns_fd, final_name) < 0) {
        saved_errno = errno;
        (void)unlinkat(ns_fd, tmp_name, 0);
        (void)close(ns_fd);
        errno = saved_errno;
        return MQTT_CODE_ERROR_SYSTEM;
    }
    /* fsync the namespace dir so rename is durable. */
    rc = wmqb_posix_fsync_dir(ns_fd);
    (void)close(ns_fd);
    return rc;
}

static int wmqb_posix_get(void* ctx, byte ns, const byte* key,
    word16 key_len, byte* out, word32* inout_len)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    char name[2 * 256 + 5];
    struct stat st;
    int fd;
    int ns_fd;
    int rc;
    ssize_t r;
    word32 cap;
    word32 read_total = 0;

    if (c == NULL || key == NULL || inout_len == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    cap = *inout_len;
    rc = wmqb_rec_name(key, key_len, name, sizeof(name));
    if (rc != 0) {
        return rc;
    }
    rc = wmqb_open_ns(c, ns, 0, &ns_fd);
    if (rc != 0) {
        if (rc == MQTT_CODE_ERROR_NOT_FOUND) {
            *inout_len = 0;
        }
        return rc;
    }
    fd = openat(ns_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        int open_errno = errno;

        (void)close(ns_fd);
        if (open_errno == ENOENT) {
            *inout_len = 0;
            return MQTT_CODE_ERROR_NOT_FOUND;
        }
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != geteuid()) {
        (void)close(fd);
        (void)close(ns_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    (void)close(ns_fd);
    {
        int eintr_count = 0;
        while (read_total < cap) {
            r = read(fd, out + read_total, cap - read_total);
            if (r == 0) {
                break;
            }
            if (r < 0) {
                if (errno == EINTR && eintr_count++ < 16) {
                    continue;
                }
                (void)close(fd);
                return MQTT_CODE_ERROR_SYSTEM;
            }
            read_total += (word32)r;
        }
    }
    (void)close(fd);
    *inout_len = read_total;
    return 0;
}

static int wmqb_posix_del(void* ctx, byte ns, const byte* key,
    word16 key_len)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    char name[2 * 256 + 5];
    int ns_fd;
    int rc;

    if (c == NULL || key == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_rec_name(key, key_len, name, sizeof(name));
    if (rc != 0) {
        return rc;
    }
    rc = wmqb_open_ns(c, ns, 0, &ns_fd);
    if (rc == MQTT_CODE_ERROR_NOT_FOUND) {
        return 0;
    }
    if (rc != 0) {
        return rc;
    }
    if (unlinkat(ns_fd, name, 0) < 0) {
        if (errno == ENOENT) {
            (void)close(ns_fd);
            return 0;
        }
        (void)close(ns_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    /* fsync the namespace dir so the unlink is durable. */
    rc = wmqb_posix_fsync_dir(ns_fd);
    (void)close(ns_fd);
    return rc;
}

static int wmqb_posix_iter(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
    void* cb_ctx)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    DIR* d;
    struct dirent* ent;
    int ns_fd;
    int rc;

    if (c == NULL || cb == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_open_ns(c, ns, 0, &ns_fd);
    if (rc == MQTT_CODE_ERROR_NOT_FOUND) {
        return 0;
    }
    if (rc != 0) {
        return rc;
    }
    d = fdopendir(ns_fd);
    if (d == NULL) {
        (void)close(ns_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    for (;;) {
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

        /* readdir reports both end of directory and failure as NULL; only
         * errno tells them apart. */
        errno = 0;
        ent = readdir(d);
        if (ent == NULL) {
            if (errno != 0) {
                rc = MQTT_CODE_ERROR_SYSTEM;
            }
            break;
        }
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
        /* Classify the entry by type and owner before opening it, so
         * symlinks, sockets, FIFOs and foreign files are skipped however the
         * platform would fail to open them. */
        if (fstatat(dirfd(d), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno == ENOENT) {
                continue; /* removed since readdir */
            }
            rc = MQTT_CODE_ERROR_SYSTEM;
            break;
        }
        if (!S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
            continue;
        }
        fd = openat(dirfd(d), ent->d_name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            /* Removed or swapped for a symlink since fstatat; anything else
             * on an owned record is an I/O failure that must not be
             * reported as a complete pass. */
            if (errno == ENOENT || errno == ELOOP) {
                continue;
            }
            rc = MQTT_CODE_ERROR_SYSTEM;
            break;
        }
        if (fstat(fd, &st) < 0) {
            (void)close(fd);
            rc = MQTT_CODE_ERROR_SYSTEM;
            break;
        }
        if (!S_ISREG(st.st_mode) ||
                st.st_uid != geteuid() || st.st_size <= 0 ||
                (word64)st.st_size > 16 * 1024 * 1024) {
            /* Refuse non-regular, foreign-owned, or oversized records. */
            (void)close(fd);
            continue;
        }
        blob_cap = (word32)st.st_size;
        blob = (byte*)WOLFMQTT_MALLOC(blob_cap);
        if (blob == NULL) {
            (void)close(fd);
            (void)closedir(d);
            return MQTT_CODE_ERROR_MEMORY;
        }
        read_total = 0;
        {
            int eintr_count = 0;
            while (read_total < blob_cap) {
                r = read(fd, blob + read_total, blob_cap - read_total);
                if (r == 0) {
                    break;
                }
                if (r < 0) {
                    if (errno == EINTR && eintr_count++ < 16) {
                        continue;
                    }
                    break;
                }
                read_total += (word32)r;
            }
        }
        (void)close(fd);
        if (read_total != blob_cap) {
            /* Scrub the record before releasing the heap buffer. In
             * encrypt-at-rest builds the blob is ciphertext, so the wipe is
             * harmless; in plaintext builds it clears session and payload
             * data from a buffer that would otherwise linger in the heap.
             * A read error or short read leaves the record unloaded, so
             * report it rather than skip it. */
            wmqb_posix_force_zero(blob, blob_cap);
            WOLFMQTT_FREE(blob);
            rc = MQTT_CODE_ERROR_SYSTEM;
            break;
        }
        stop = cb(key_buf, (word16)kn, blob, blob_cap, cb_ctx);
        wmqb_posix_force_zero(blob, blob_cap);
        WOLFMQTT_FREE(blob);
        if (stop != 0) {
            break;
        }
    }
    (void)closedir(d);
    return rc;
}

static int wmqb_posix_sync(void* ctx)
{
    WmqbPosixCtx* c = (WmqbPosixCtx*)ctx;
    /* The per-op fsync in put/del already covered the data + the
     * namespace dir. A top-level fsync of the root dir here ensures
     * any namespace-dir creates are durable too. */
    if (c == NULL || c->root_fd < 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    return (WMQB_POSIX_FSYNC(c->root_fd) == 0) ? 0 : MQTT_CODE_ERROR_SYSTEM;
}

int MqttBrokerNet_PersistPosix_Init(MqttBrokerPersistHooks* hooks,
    const char* dir)
{
    WmqbPosixCtx* c;
    const char* use_dir = (dir != NULL) ? dir : BROKER_PERSIST_DIR_DEFAULT;
    int rc;

    if (hooks == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    c = (WmqbPosixCtx*)WOLFMQTT_MALLOC(sizeof(*c));
    if (c == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(c, 0, sizeof(*c));
    c->root_fd = -1;
    rc = wmqb_normalize_root(use_dir, c->dir, sizeof(c->dir));
    if (rc != MQTT_CODE_SUCCESS) {
        WOLFMQTT_FREE(c);
        return rc;
    }
    c->owned = 1;

    rc = wmqb_open_root(c->dir, &c->root_fd);
    if (rc != MQTT_CODE_SUCCESS) {
        WOLFMQTT_FREE(c);
        return rc;
    }

    XMEMSET(hooks, 0, sizeof(*hooks));
    hooks->kv_put     = wmqb_posix_put;
    hooks->kv_get     = wmqb_posix_get;
    hooks->kv_del     = wmqb_posix_del;
    hooks->kv_iter    = wmqb_posix_iter;
    hooks->sync       = wmqb_posix_sync;
    hooks->ctx        = c;

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
        if (c->root_fd >= 0) {
            (void)close(c->root_fd);
            c->root_fd = -1;
        }
        WOLFMQTT_FREE(c);
    }
    XMEMSET(hooks, 0, sizeof(*hooks));
}

#endif /* WOLFMQTT_BROKER_PERSIST */
