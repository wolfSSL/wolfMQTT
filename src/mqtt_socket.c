/* mqtt_socket.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_socket.h"

/* Options */
#if 0
#define DEBUG_SOCKET
#endif


/* Private Functions */
#ifdef ENABLE_MQTT_TLS
static int MqttSocket_TlsSocketReceive(WOLFSSL* ssl, char *buf, int sz,
    void *ptr)
{
    int rc;
    MqttClient *client = (MqttClient*)ptr;
    (void)ssl; /* Not used */
    rc = client->net->read(client->net->context, (byte*)buf, sz,
        client->cmd_timeout_ms);
    if (rc == 0) {
        rc = WOLFSSL_CBIO_ERR_WANT_READ;
    }
    else if (rc < 0) {
        rc = WOLFSSL_CBIO_ERR_GENERAL;
    }
    return rc;
}

static int MqttSocket_TlsSocketSend(WOLFSSL* ssl, char *buf, int sz,
    void *ptr)
{
    int rc;
    MqttClient *client = (MqttClient*)ptr;
    (void)ssl; /* Not used */
    rc = client->net->write(client->net->context, (byte*)buf, sz,
        client->cmd_timeout_ms);
    if (rc == 0) {
        rc = WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    else if (rc < 0) {
        rc = WOLFSSL_CBIO_ERR_GENERAL;
    }
    return rc;
}
#endif


/* Public Functions */
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
#endif

        /* Validate callbacks are not null! */
        if (net && net->connect && net->read && net->write &&
            net->disconnect) {
            rc = MQTT_CODE_SUCCESS;
        }
    }
    return rc;
}

int MqttSocket_Write(MqttClient *client, const byte* buf, int buf_len,
    int timeout_ms)
{
    int rc;

    /* Validate arguments */
    if (client == NULL || client->net == NULL ||
        client->net->write == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef ENABLE_MQTT_TLS
    if (client->flags & MQTT_CLIENT_FLAG_IS_TLS) {
        int error;
        rc = wolfSSL_write(client->tls.ssl, (char*)buf, buf_len);
        error = wolfSSL_get_error(client->tls.ssl, 0);
#ifdef DEBUG_SOCKET
        printf("MqttSocket_Write: Len=%d, Rc=%d, Error=%d\n",
            buf_len, rc, error);
#endif
        if (error == SSL_ERROR_WANT_WRITE) {
            rc = 0; /* Timeout */
        }
    }
    else
#endif
    {
        rc = client->net->write(client->net->context, buf, buf_len,
            timeout_ms);

#ifdef DEBUG_SOCKET
        printf("MqttSocket_Write: Len=%d, Rc=%d\n", buf_len, rc);
#endif
    }

    /* Check for error */
    if (rc < 0) {
        rc = MQTT_CODE_ERROR_NETWORK;
    }

    return rc;
}

int MqttSocket_Read(MqttClient *client, byte* buf, int buf_len, int timeout_ms)
{
    int rc, pos, len;

    /* Validate arguments */
    if (client == NULL || client->net == NULL || client->net->read == NULL ||
        buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    pos = 0;
    len = buf_len;
    do {
#ifdef ENABLE_MQTT_TLS
        if (client->flags & MQTT_CLIENT_FLAG_IS_TLS) {
            int error;
            rc = wolfSSL_read(client->tls.ssl, (char*)&buf[pos], len);
            error = wolfSSL_get_error(client->tls.ssl, 0);
#ifdef DEBUG_SOCKET
            printf("MqttSocket_Read: Len=%d, Rc=%d, Error=%d\n",
                len, rc, error);
#endif
            if (error == SSL_ERROR_WANT_READ) {
                rc = 0; /* Timeout */
            }
        }
        else
#endif
        {
            rc = client->net->read(client->net->context, &buf[pos], len,
                timeout_ms);

#ifdef DEBUG_SOCKET
            printf("MqttSocket_Read: Len=%d, Rc=%d\n", len, rc);
#endif
        }

        if (rc > 0) {
            pos += rc;
            len -= rc;
        }
        else {
            break;
        }
    } while (len > 0);

    /* Check for timeout */
    if (rc == 0) {
        rc = MQTT_CODE_ERROR_TIMEOUT;
    }
    else if (rc < 0) {
        rc = MQTT_CODE_ERROR_NETWORK;
    }
    else {
        rc = pos;
    }

    return rc;
}

int MqttSocket_Connect(MqttClient *client, const char* host, word16 port,
    int timeout_ms, int use_tls, MqttTlsCb cb)
{
    int rc;

    /* Validate arguments */
    if (client == NULL || client->net == NULL ||
        client->net->connect == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Validate port */
    if (port == 0) {
        port = (use_tls) ? MQTT_SECURE_PORT : MQTT_DEFAULT_PORT;
    }

    /* Connect to host */
    rc = client->net->connect(client->net->context, host, port, timeout_ms);
    if (rc != 0) {
        return rc;
    }
    client->flags |= MQTT_CLIENT_FLAG_IS_CONNECTED;

#ifdef ENABLE_MQTT_TLS
    if (use_tls) {
        /* Setup the WolfSSL library */
        wolfSSL_Init();

        /* Create and initialize the WOLFSSL_CTX structure */
        client->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
        if (client->tls.ctx) {
            wolfSSL_CTX_set_verify(client->tls.ctx, SSL_VERIFY_NONE, 0);

            rc = SSL_SUCCESS;
            if (cb) {
                rc = cb(client);
            }

            if (rc == SSL_SUCCESS) {
                /* Seutp the async IO callbacks */
                wolfSSL_SetIORecv(client->tls.ctx,
                    MqttSocket_TlsSocketReceive);
                wolfSSL_SetIOSend(client->tls.ctx,
                    MqttSocket_TlsSocketSend);

                client->tls.ssl = wolfSSL_new(client->tls.ctx);
                if (client->tls.ssl) {
                    wolfSSL_SetIOReadCtx(client->tls.ssl, (void *)client) ;
                    wolfSSL_SetIOWriteCtx(client->tls.ssl, (void *)client) ;

                    rc = wolfSSL_connect(client->tls.ssl);
                    if (rc == SSL_SUCCESS) {
                        client->flags |= MQTT_CLIENT_FLAG_IS_TLS;
                        rc = MQTT_CODE_SUCCESS;
                    }
                }
                else {
                    printf("MqttSocket_TlsConnect: wolfSSL_new error!\n");
                    rc = -1;
                }
            }
        }
        else {
            printf("MqttSocket_TlsConnect: wolfSSL_CTX_new error!\n");
            rc = -1;
        }

        /* Handle error case */
        if (rc) {
            const char* errstr = NULL;
            int errnum = 0;
            if (client->tls.ssl) {
                errnum = wolfSSL_get_error(client->tls.ssl, 0);
                errstr = wc_GetErrorString(errnum);
            }

            printf("MqttSocket_TlsConnect Error %d: Num %d, %s\n",
                rc, errnum, errstr);

            /* Make sure we cleanup on error */
            MqttSocket_Disconnect(client);

            rc = MQTT_CODE_ERROR_TLS_CONNECT;
        }
    }
#else
    (void)cb;
#endif /* ENABLE_MQTT_TLS */

#ifdef DEBUG_SOCKET
    printf("MqttSocket_Connect: Rc=%d\n", rc);
#endif

    /* Check for error */
    if (rc < 0) {
        rc = MQTT_CODE_ERROR_NETWORK;
    }

    return rc;
}

int MqttSocket_Disconnect(MqttClient *client)
{
    int rc = MQTT_CODE_SUCCESS;
    if (client) {
#ifdef ENABLE_MQTT_TLS
        if (client->tls.ssl) wolfSSL_free(client->tls.ssl);
        if (client->tls.ctx) wolfSSL_CTX_free(client->tls.ctx);
        wolfSSL_Cleanup();
        client->flags &= ~MQTT_CLIENT_FLAG_IS_TLS;
#endif

        /* Make sure socket is closed */
        if (client->net && client->net->disconnect) {
            rc = client->net->disconnect(client->net->context);
        }
        client->flags &= ~MQTT_CLIENT_FLAG_IS_CONNECTED;
    }
#ifdef DEBUG_SOCKET
    printf("MqttSocket_Disconnect: Rc=%d\n", rc);
#endif

    /* Check for error */
    if (rc < 0) {
        rc = MQTT_CODE_ERROR_NETWORK;
    }

    return rc;
}
