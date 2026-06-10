/* mqtt_log.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFMQTT_EXAMPLE_LOG_H
#define WOLFMQTT_EXAMPLE_LOG_H

#include "wolfmqtt/mqtt_types.h" /* for byte / word32 */

#ifdef __cplusplus
extern "C" {
#endif

/* mqtt_log_sanitize is a header-only helper, so a translation unit that
 * includes it but whose log sink is compiled out (e.g. sn-multithread.c built
 * without WOLFMQTT_MULTITHREAD) leaves it unreferenced. Declaring it INLINE
 * keeps that quiet on GCC/Clang (-Wunused-function) and MSVC (C4505); the
 * attribute is a fallback for GCC/Clang builds that set NO_INLINE, where the
 * INLINE macro expands to nothing. */
#if defined(__GNUC__) || defined(__clang__)
    #define MQTT_LOG_MAYBE_UNUSED __attribute__((unused))
#else
    #define MQTT_LOG_MAYBE_UNUSED
#endif

/* Sanitize an untrusted string for safe logging (CWE-117 defense).
 *
 * MQTT/MQTT-SN strings such as a REGISTER topic name are controlled by the
 * remote peer. For MQTT-SN this peer is reachable over UDP, so an attacker who
 * can spoof the gateway's source address controls the bytes outright. Writing
 * such a string straight to a PRINTF/log sink lets the peer inject forged log
 * lines (embedded CR/LF) or hijack the operator's terminal with ANSI escape
 * sequences (ESC), making malicious output indistinguishable from genuine log
 * lines.
 *
 * This helper copies src into the caller's fixed-size dst buffer, replacing
 * every control byte (anything < 0x20, plus DEL 0x7f) with a printable escape
 * so the result is always safe to hand to PRINTF:
 *   CR -> "\r"   LF -> "\n"   TAB -> "\t"   VT -> "\v"   ESC -> "\e"
 *   any other control byte -> "\xHH"
 *
 * dst is always NUL-terminated when dstLen > 0. Output is truncated to fit dst
 * (never overflowed) and a multi-byte escape is emitted all-or-nothing, so the
 * result never ends in a dangling backslash. Returns dst so the call can be
 * used inline as a PRINTF argument. A NULL src yields "(null)".
 */
MQTT_LOG_MAYBE_UNUSED
static INLINE const char* mqtt_log_sanitize(char* dst, word32 dstLen,
    const char* src)
{
    static const char hex_digits[] = "0123456789abcdef";
    word32 di = 0;

    if (dst == NULL || dstLen == 0) {
        return dst;
    }
    if (src == NULL) {
        src = "(null)";
    }

    while (*src != '\0') {
        byte c = (byte)*src++;
        char rep[4];
        word32 repLen = 0;

        switch (c) {
            case '\r': rep[0] = '\\'; rep[1] = 'r'; repLen = 2; break;
            case '\n': rep[0] = '\\'; rep[1] = 'n'; repLen = 2; break;
            case '\t': rep[0] = '\\'; rep[1] = 't'; repLen = 2; break;
            case '\v': rep[0] = '\\'; rep[1] = 'v'; repLen = 2; break;
            case 0x1b: rep[0] = '\\'; rep[1] = 'e'; repLen = 2; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    /* Generic non-printable control byte -> \xHH */
                    rep[0] = '\\';
                    rep[1] = 'x';
                    rep[2] = hex_digits[(c >> 4) & 0x0f];
                    rep[3] = hex_digits[c & 0x0f];
                    repLen = 4;
                }
                else {
                    rep[0] = (char)c;
                    repLen = 1;
                }
                break;
        }

        /* Stop before overflow, always leaving room for the NUL terminator.
         * Because the check covers the whole replacement, a multi-byte escape
         * is never split across the truncation boundary. */
        if (di + repLen + 1 > dstLen) {
            break;
        }
        {
            word32 j;
            for (j = 0; j < repLen; j++) {
                dst[di++] = rep[j];
            }
        }
    }

    dst[di] = '\0';
    return dst;
}

#ifdef __cplusplus
}
#endif

#endif /* WOLFMQTT_EXAMPLE_LOG_H */
