/* mqtt_socket.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFMQTT_NONBLOCK
    /* need EWOULDBLOCK and EAGAIN */
    #ifdef MICROCHIP_MPLAB_HARMONY
        #include <sys/errno.h>
    #endif
    #include <errno.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_socket.h"


/* Public Functions */
#ifdef ENABLE_MQTT_TLS
int MqttSocket_TlsSocketReceive(WOLFSSL* ssl, char *buf, int sz,
    void *ptr)
{
    int rc;
    MqttClient *client = (MqttClient*)ptr;
    (void)ssl; /* Not used */

    rc = client->net->read(client->net->context, (byte*)buf, sz,
        client->tls.timeout_ms);

    /* save network read response */
    client->tls.sockRc = rc;

    if (rc == 0 || rc == MQTT_CODE_ERROR_TIMEOUT || rc == MQTT_CODE_STDIN_WAKE
                                                 || rc == MQTT_CODE_CONTINUE) {
        rc = WOLFSSL_CBIO_ERR_WANT_READ;
    }
    else if (rc < 0) {
        rc = WOLFSSL_CBIO_ERR_GENERAL;
    }
    return rc;
}

int MqttSocket_TlsSocketSend(WOLFSSL* ssl, char *buf, int sz,
    void *ptr)
{
    int rc;
    MqttClient *client = (MqttClient*)ptr;
    (void)ssl; /* Not used */

    rc = client->net->write(client->net->context, (byte*)buf, sz,
        client->tls.timeout_ms);

    /* save network write response */
    client->tls.sockRc = rc;

    if (rc == 0 || rc == MQTT_CODE_ERROR_TIMEOUT || rc == MQTT_CODE_CONTINUE) {
        rc = WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    else if (rc < 0) {
        rc = WOLFSSL_CBIO_ERR_GENERAL;
    }
    return rc;
}
#endif

int MqttSocket_Init(MqttClient *client, MqttNet *net)
{
    int rc = MQTT_CODE_ERROR_BAD_ARG;
    if (client) {
        client->net = net;
        client->flags &= ~(MQTT_CLIENT_FLAG_IS_CONNECTED |
            MQTT_CLIENT_FLAG_IS_TLS);
    #ifdef ENABLE_MQTT_TLS
        client->tls.ctx = NULL;
        client->tls.ssl = NULL;
        client->tls.timeout_ms = client->cmd_timeout_ms;
    #endif

        /* Validate callbacks are not null! */
        if (net && net->connect && net->read && net->write && net->disconnect) {
            rc = MQTT_CODE_SUCCESS;
        }
    }
    return rc;
}

static int MqttSocket_WriteDo(MqttClient *client, const byte* buf, int buf_len,
    int timeout_ms)
{
    int rc;

#ifdef ENABLE_MQTT_TLS
    if (client->flags & MQTT_CLIENT_FLAG_IS_TLS) {
        client->tls.timeout_ms = timeout_ms;
        rc = wolfSSL_write(client->tls.ssl, (char*)buf, buf_len);
        if (rc < 0) {
        #ifdef WOLFMQTT_DEBUG_SOCKET
            int error = wolfSSL_get_error(client->tls.ssl, 0);
            if (error != WOLFSSL_ERROR_WANT_WRITE) {
                PRINTF("MqttSocket_Write: SSL Error=%d (rc %d, sockrc %d)",
                    error, rc, client->tls.sockRc);
            }
        #endif

            /* return code from net callback */
            rc = client->tls.sockRc;
        }
    }
    else
#endif /* ENABLE_MQTT_TLS */
    {
        rc = client->net->write(client->net->context, buf, buf_len,
            timeout_ms);
    }

#ifdef WOLFMQTT_DEBUG_SOCKET
    if (rc != 0 && rc != MQTT_CODE_CONTINUE) { /* hide in non-blocking case */
        PRINTF("MqttSocket_Write: Len=%d, Rc=%d", buf_len, rc);
    }
#endif

    return rc;
}

int MqttSocket_Write(MqttClient *client, const byte* buf, int buf_len,
    int timeout_ms)
{
    int rc;

    /* Validate arguments */
    if (client == NULL || client->net == NULL || client->net->write == NULL ||
        buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* check for buffer position overflow */
    if (client->write.pos >= buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

#ifdef WOLFMQTT_NONBLOCK
    rc = MqttSocket_WriteDo(client, &buf[client->write.pos],
        buf_len - client->write.pos, timeout_ms);
    if (rc >= 0) {
        client->write.pos += rc;
        if (client->write.pos < buf_len) {
            rc = MQTT_CODE_CONTINUE;
        }
    }
    else if (rc == EWOULDBLOCK || rc == EAGAIN) {
        rc = MQTT_CODE_CONTINUE;
    }

#else
    do {
        rc = MqttSocket_WriteDo(client, &buf[client->write.pos],
            buf_len - client->write.pos, timeout_ms);
        if (rc <= 0) {
            break;
        }
        client->write.pos += rc;
    } while (client->write.pos < buf_len);
#endif /* WOLFMQTT_NONBLOCK */

    /* handle return code */
    if (rc > 0) {
        /* return length write and reset position */
        rc = client->write.pos;
        client->write.pos = 0;
    }

    return rc;
}

static int MqttSocket_ReadDo(MqttClient *client, byte* buf, int buf_len,
    int timeout_ms)
{
    int rc;

#ifdef ENABLE_MQTT_TLS
    if (client->flags & MQTT_CLIENT_FLAG_IS_TLS) {
        client->tls.timeout_ms = timeout_ms;
        rc = wolfSSL_read(client->tls.ssl, (char*)buf, buf_len);
        if (rc < 0) {
        #ifdef WOLFMQTT_DEBUG_SOCKET
            int error = wolfSSL_get_error(client->tls.ssl, 0);
            if (error != WOLFSSL_ERROR_WANT_READ) {
                PRINTF("MqttSocket_Read: SSL Error=%d", error);
            }
        #endif

            /* return code from net callback */
            rc = client->tls.sockRc;
        }
    }
    else
#endif /* ENABLE_MQTT_TLS */
    {
        rc = client->net->read(client->net->context, buf, buf_len, timeout_ms);
    }

#ifdef WOLFMQTT_DEBUG_SOCKET
    if (rc != 0 && rc != MQTT_CODE_CONTINUE) { /* hide in non-blocking case */
        PRINTF("MqttSocket_Read: Len=%d, Rc=%d", buf_len, rc);
    }
#endif

    return rc;
}

int MqttSocket_Read(MqttClient *client, byte* buf, int buf_len, int timeout_ms)
{
    int rc;

    /* Validate arguments */
    if (client == NULL || client->net == NULL || client->net->read == NULL ||
        buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* check for buffer position overflow */
    if (client->read.pos >= buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

#ifdef WOLFMQTT_NONBLOCK
    rc = MqttSocket_ReadDo(client, &buf[client->read.pos],
        buf_len - client->read.pos, timeout_ms);
    if (rc >= 0) {
        client->read.pos += rc;
        if (client->read.pos < buf_len) {
            rc = MQTT_CODE_CONTINUE;
        }
    }
    else if (rc == EWOULDBLOCK || rc == EAGAIN) {
        rc = MQTT_CODE_CONTINUE;
    }

#else
    do {
        rc = MqttSocket_ReadDo(client, &buf[client->read.pos],
            buf_len - client->read.pos, timeout_ms);
        if (rc <= 0) {
            break;
        }
        client->read.pos += rc;
    } while (client->read.pos < buf_len);
#endif /* WOLFMQTT_NONBLOCK */

    /* handle return code */
    if (rc > 0) {
        /* return length read and reset position */
        rc = client->read.pos;
        client->read.pos = 0;
    }

    return rc;
}

#ifdef WOLFMQTT_SN
int MqttSocket_Peek(MqttClient *client, byte* buf, int buf_len, int timeout_ms)
{
    int rc;

    /* Validate arguments */
    if (client == NULL || client->net == NULL || client->net->peek == NULL ||
        buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* check for buffer position overflow */
    if (client->read.pos >= buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    rc = client->net->peek(client->net->context, buf, buf_len, timeout_ms);
    if (rc > 0) {
    #ifdef WOLFMQTT_DEBUG_SOCKET
        PRINTF("MqttSocket_Peek: Len=%d, Rc=%d", buf_len, rc);
    #endif

        /* return length read and reset position */
        client->read.pos = 0;
    }

    return rc;
}
#endif

int MqttSocket_Connect(MqttClient *client, const char* host, word16 port,
    int timeout_ms, int use_tls, MqttTlsCb cb)
{
    int rc = MQTT_CODE_SUCCESS;

    /* Validate arguments */
    if (client == NULL || client->net == NULL ||
        client->net->connect == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifndef ENABLE_MQTT_TLS
    /* cannot use TLS unless ENABLE_MQTT_TLS is defined */
    if (use_tls) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
#endif

    if ((client->flags & MQTT_CLIENT_FLAG_IS_CONNECTED) == 0) {
        /* Validate port */
        if (port == 0) {
            port = (use_tls) ? MQTT_SECURE_PORT : MQTT_DEFAULT_PORT;
        }

        /* Connect to host */
        rc = client->net->connect(client->net->context, host, port, timeout_ms);
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }
        client->flags |= MQTT_CLIENT_FLAG_IS_CONNECTED;
    }

#ifdef ENABLE_MQTT_TLS
    if (use_tls) {
        if (client->tls.ctx == NULL) {
        #ifdef DEBUG_WOLFSSL
            wolfSSL_Debugging_ON();
        #endif

            /* Setup the WolfSSL library */
            rc = wolfSSL_Init();

            /* Issue callback to allow setup of the wolfSSL_CTX and cert
               verification settings */
            if ((rc == WOLFSSL_SUCCESS) && (cb != NULL)) {
                rc = cb(client);
            }
            if (rc != WOLFSSL_SUCCESS) {
                rc = MQTT_CODE_ERROR_TLS_CONNECT;
                goto exit;
            }
        }

        /* Create and initialize the WOLFSSL_CTX structure */
        if (client->tls.ctx == NULL) {
            /* Use defaults */
            client->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
            if (client->tls.ctx == NULL) {
                rc = MQTT_CODE_ERROR_TLS_CONNECT;
                goto exit;
            }
            wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_NONE, 0);
        }

    #ifndef NO_DH
        wolfSSL_CTX_SetMinDhKey_Sz(client->tls.ctx, WOLF_TLS_DHKEY_BITS_MIN);
    #endif

        /* Setup the IO callbacks */
        wolfSSL_CTX_SetIORecv(client->tls.ctx, MqttSocket_TlsSocketReceive);
        wolfSSL_CTX_SetIOSend(client->tls.ctx, MqttSocket_TlsSocketSend);

        if (client->tls.ssl == NULL) {
            client->tls.ssl = wolfSSL_new(client->tls.ctx);

            if (client->tls.ssl == NULL) {
                rc = MQTT_CODE_ERROR_TLS_CONNECT;
                goto exit;
            }
        }
        /* Set the IO callback context */
        wolfSSL_SetIOReadCtx(client->tls.ssl, (void *)client);
        wolfSSL_SetIOWriteCtx(client->tls.ssl, (void *)client);

        if (client->ctx != NULL) {
            /* Store any app data for use by the tls verify callback*/
            wolfSSL_SetCertCbCtx(client->tls.ssl, client->ctx);
        }

        rc = wolfSSL_connect(client->tls.ssl);
        if (rc != WOLFSSL_SUCCESS) {
            rc = MQTT_CODE_ERROR_TLS_CONNECT;
            goto exit;
        }

        client->flags |= MQTT_CLIENT_FLAG_IS_TLS;
        rc = MQTT_CODE_SUCCESS;
  }

exit:
    /* Handle error case */
    if (rc != MQTT_CODE_SUCCESS) {
    #ifdef WOLFMQTT_DEBUG_SOCKET
        const char* errstr = "";
    #endif
        int errnum = 0;
        if (client->tls.ssl) {
            errnum = wolfSSL_get_error(client->tls.ssl, 0);
            if ((errnum == WOLFSSL_ERROR_WANT_READ) ||
                (errnum == WOLFSSL_ERROR_WANT_WRITE)) {
                return MQTT_CODE_CONTINUE;
            }
        #ifdef WOLFMQTT_DEBUG_SOCKET
            errstr = wolfSSL_ERR_reason_error_string(errnum);
        #endif
        }

    #ifdef WOLFMQTT_DEBUG_SOCKET
        PRINTF("MqttSocket_TlsConnect Error %d: Num %d, %s",
            rc, errnum, errstr);
    #endif /* WOLFMQTT_DEBUG_SOCKET */

        /* Make sure we cleanup on error */
        MqttSocket_Disconnect(client);
    }

#else
    (void)cb;
#endif /* ENABLE_MQTT_TLS */

#ifdef WOLFMQTT_DEBUG_SOCKET
    PRINTF("MqttSocket_Connect: Rc=%d", rc);
#endif

    return rc;
}

int MqttSocket_Disconnect(MqttClient *client)
{
    int rc = MQTT_CODE_SUCCESS;
    if (client) {
    #ifdef ENABLE_MQTT_TLS
        if (client->tls.ssl) {
            wolfSSL_free(client->tls.ssl);
            client->tls.ssl = NULL;
        }
        if (client->tls.ctx) {
            wolfSSL_CTX_free(client->tls.ctx);
            client->tls.ctx = NULL;
        }
        wolfSSL_Cleanup();
        client->flags &= ~MQTT_CLIENT_FLAG_IS_TLS;
    #endif

        /* Make sure socket is closed */
        if (client->net && client->net->disconnect) {
            rc = client->net->disconnect(client->net->context);
        }
        client->flags &= ~MQTT_CLIENT_FLAG_IS_CONNECTED;
    }
#ifdef WOLFMQTT_DEBUG_SOCKET
    PRINTF("MqttSocket_Disconnect: Rc=%d", rc);
#endif

    /* Check for error */
    if (rc < 0) {
        rc = MQTT_CODE_ERROR_NETWORK;
    }

    return rc;
}
