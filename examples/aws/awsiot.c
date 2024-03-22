/* awsiot.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#include "wolfmqtt/mqtt_client.h"


/* This example only works with ENABLE_MQTT_TLS (wolfSSL library),
 * and without ENABLE_MQTT_CURL. */
#if defined(ENABLE_MQTT_TLS) && !defined(ENABLE_MQTT_CURL)
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/version.h>

    #undef  ENABLE_AWSIOT_EXAMPLE
    #define ENABLE_AWSIOT_EXAMPLE
#endif


#ifdef ENABLE_AWSIOT_EXAMPLE

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "awsiot.h"
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"
#include <wolfmqtt/version.h>

/* Locals */
static int mStopRead = 0;
static int mTestDone = 0;

/* Configuration */
#define APP_HARDWARE         "wolf_aws_iot_demo"
#define APP_FIRMWARE_VERSION LIBWOLFMQTT_VERSION_STRING

#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE         512    /* Maximum size for network read/write callbacks */
#endif
#define AWSIOT_HOST             "a2dujmi05ideo2-ats.iot.us-west-2.amazonaws.com"
#define AWSIOT_DEVICE_ID        "demoDevice"
#define AWSIOT_QOS              MQTT_QOS_1
#define AWSIOT_KEEP_ALIVE_SEC   DEFAULT_KEEP_ALIVE_SEC
#define AWSIOT_CMD_TIMEOUT_MS   DEFAULT_CMD_TIMEOUT_MS

#define AWSIOT_PUBLISH_TOPIC    "$aws/things/" AWSIOT_DEVICE_ID "/shadow/update"
#define AWSIOT_SUBSCRIBE_TOPIC  AWSIOT_PUBLISH_TOPIC


#define AWSIOT_PUBLISH_MSG_SZ   400

/* Demo Certificates */
WOLFMQTT_EXAMPLE_CERT const char* root_ca =
"-----BEGIN CERTIFICATE-----\n"
"MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\n"
"yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n"
"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\n"
"U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\n"
"ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\n"
"aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\n"
"MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\n"
"ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\n"
"biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\n"
"U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\n"
"aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\n"
"nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\n"
"t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\n"
"SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\n"
"BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\n"
"rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\n"
"NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\n"
"BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\n"
"BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\n"
"aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\n"
"MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\n"
"p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\n"
"5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\n"
"WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\n"
"4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\n"
"hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\n"
"-----END CERTIFICATE-----";

#if 0
static const char* device_pub_key =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqsAKVhbfQEWblC8Pvgub\n"
"qpJasVoCEsSfvLF4b5DIAsoMeieP26y6Vyd3njRyuigSQ6jP+mo3GyqSfeCbqfJ2\n"
"dx3BNICEk7P46Bu37ewoI24pScnT+5Rcfw//dh8WHDq0d0933i4vOKEKA6ft51Ax\n"
"Y6KzvNrwxo6bml0Vi2DBx3WLGw+MDiHXk2L0geSYSNjFz/u9dkgEUPhEGbNZuw2y\n"
"xhwbNfaiPe2ld5Fir6iUybuj93xfWqqNls77V6Qj7mI8pamdGFtQnkP+6l2XTa6J\n"
"bunCqZo1PURtUXch5db6rMq/6rRZrlJM7NngPI1vv8jF4T3G4mjyT8I4KxQK1s90\n"
"9QIDAQAB\n"
"-----END PUBLIC KEY-----";
#endif

WOLFMQTT_EXAMPLE_CERT const char* device_priv_key =
#ifndef WOLFSSL_ENCRYPTED_KEYS
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEAqsAKVhbfQEWblC8PvgubqpJasVoCEsSfvLF4b5DIAsoMeieP\n"
"26y6Vyd3njRyuigSQ6jP+mo3GyqSfeCbqfJ2dx3BNICEk7P46Bu37ewoI24pScnT\n"
"+5Rcfw//dh8WHDq0d0933i4vOKEKA6ft51AxY6KzvNrwxo6bml0Vi2DBx3WLGw+M\n"
"DiHXk2L0geSYSNjFz/u9dkgEUPhEGbNZuw2yxhwbNfaiPe2ld5Fir6iUybuj93xf\n"
"WqqNls77V6Qj7mI8pamdGFtQnkP+6l2XTa6JbunCqZo1PURtUXch5db6rMq/6rRZ\n"
"rlJM7NngPI1vv8jF4T3G4mjyT8I4KxQK1s909QIDAQABAoIBAQCAkkI2ONq6Rq+z\n"
"kQxFifAZLELmMGRHRY8SQn/xYg95KjLi+E82loVpguprUgrhabL3B3IzmS8NYa0U\n"
"47/S5COX5evJYMxze5z9CYIhwSUoKJcmXLcmRLyxYJZ3l0jK0Nl6zXfw8M3V0kz8\n"
"G8Lj3lqSL70vg5yxpkg8n8LNRHoleXvz/57HzllIUx2S6Dopc29ALJiR1lVFdPc1\n"
"z5vs6O+2e0TDmPpVTNKQMI8E+02i/W5BfJ21A7VJW0OFx9ozQU43E95VT9U3/pOz\n"
"NLjdIKXmr3Miw7+TWljwF0Ak7SL0AN/nLKHYt6PIIgs9YU1xqP44u/rtqBCeSSVE\n"
"2OBmAUcxAoGBAOo6CfZER7tLayhFNSw1Zt3UBsru+xZnCR1DBuPYn+qMJbbv/LAf\n"
"4zy14vQO9lY2d3k5Vd/zZSpIcXS12adqn7kN2d5PI4XZEVMH3O1aRcGxl1UETiQE\n"
"wiEeB5u4OdjoRxKk59MzMrGLYUaZMuyyhaw6t18ujw7DeS2IRoPgsYjzAoGBALqf\n"
"bnG0yMcwmcmsmsURB5OX9eXmSBld2ypaDUDComxTOKGo0reWwE8/tEm0VcQn2GcX\n"
"Uk5sbjvf3ZgOnDvBuUBr3yfXEW6OOw5mOaJeBJn3mncDcsaV5bujwfG6QS/KA6Ad\n"
"1JzdJDtT1Be+DoeEwInBx6WNMrCH5dXWC7CChwR3AoGAXjPVidxQVT2x7VJYXl1j\n"
"79e0m62eApaSDdjFTqHzPyv6hybiJBvPEr28d5gE7wuc5X5v0VBc4bKdHul8jl7N\n"
"ummdtFFz4gM5eoFxE2z5HTvFt4Wxv77CLPuc574iVeClpRP5wPGYc9uw1eoLlzL9\n"
"nBVJZtic5L0tYWiro6KdBI0CgYBE3zWpLOiz6hG3RcXQWFqNc5VCBNwy0FpjpNwj\n"
"PDEo/QV3U5CARFgwZvgoAy9rtrC8SvULECUWX6WtyiaKPxIY3jZ6w3ohbMgKpls6\n"
"uqvEDoaoyVMASq1/tA2NIgmQk2MHIjsmsM4APw2UvYUrKijMLgF57UP5tg1x/w5N\n"
"U750PQKBgQC9zAxKw4cNqNBCqySmdIFmfhYwpiAqHpUX1XcjjEY9b4Ym9OwQbK+f\n"
"5aGgRkmSW/Fc1ab33Gj2liLXCDN8bziri3KfMW6n9Dxhk8ppue7N5vNpjaoMLU2e\n"
"tT/aucPRjdDp9JPzZQaewIDz7OG8bJtwLfx25FiR2oWDz2kD02joag==\n"
"-----END RSA PRIVATE KEY-----";
#else
"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIpsU/SSIa4OoCAggA\n"
"MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDvD4YFDn8hY+f4s88K0duqBIIE\n"
"0E4TFcEYQYD1ltbYf5xHbEA3j0Vjs/5w9YL4K7JqrR9R7HTlxCFavNl/l7Rga3rk\n"
"IiAz5cuSYxusUnIkDlBqcB3XQefKkl1G2E1DtExCdo02eDI4EdJ4N4zDLt5wmnL8\n"
"w10WWMU3ZkRfrD4XPz0cuuBWD5LFI9QKLJ93tUhBQtjtrZSxPG7x2tmD9YotjIiV\n"
"/PQ5Vd6agIoHyfXdRz9CIMZU25iV1tm5s2WN0JiLW3MH4Zw1bpyGDEoN8EwtnQjc\n"
"/GN6Z384o4jr+ut8z356ilSESvr6mcxTcDZoO64xWvbIRjWIyRmtv8tMd1Qtamfo\n"
"6bQCpV3I/dxBfshqPDWk/S1g9NxoPETm/yDz98Jukj8+NoJ2r4w0+y9CWyObBBUX\n"
"cAiwxluYrP7xKRMunC77WxgD2P1N29N+8QK23YcJnUQJ/TcMXSXb/W/3GbnoHhS+\n"
"KyUk05fWpswFXxtglGGjxN5wh7uOXSFY3bq/KbO/riHZ++Fwe9vSAUUaRvZUF948\n"
"alfAMRUBG2r4cIi/kQRdsQQ5icwZwsCTo2W8xvKqw26x145egEx0Jsb27Eoapcvr\n"
"vOutbe4JXMhKhrGwZohDZ4EgcM5ue7zobYwIo8DKnqTbb6UtgaVoYJm1m/YtCavy\n"
"X9xz8eXruwI00BXf+9Aj1Ryn7wn0Pcw/EoNjYAHAQB2J8yvI97FPDtwFeXm+abZg\n"
"sMMoYhQbFRd2G+xPmqltEgMv88C/cYXJGufTvYdBZNmqyZSMVu8YTxpHnM/fOODw\n"
"yB6sx5VriEkMvh5So7X1xH0UXJ1HI8LGzJKEKNPrSQKZW0KofPsCZsAbgkoDZ/HV\n"
"ji6uMHgXYbZRJEhYbTnQNE26elniTMkQXa0tw9atbjsFwk609Nbz63KeQWyvnAC+\n"
"Q3IoXWWt42APNmOBGdg1xRIWolXtmWFMCI58eY9YCJkwUQjWy4vS85waWY2kA8tq\n"
"4W15XEXYwuhWoyOqNubhkEs+PT+CaEh2M9C4exfBAnTy9fYYx2lm1OC8CX+L8OZU\n"
"mhOU7EdRuah5wnTEATUu4i2Zm5+R7oF+12QHk5vaoZAbkl4xChVdD44UneREzDLb\n"
"WV27YlN0RApeFCoYf+BQi8YzBXZahxG4g74Yu7sfjOKJj+VAT3ilLlhKelLBqjlw\n"
"ZUV9F+mLKo91k3omAr+M4mp72DqH8OiWnhvQaBY1QADrez4kA0krfewHcKosKMMK\n"
"EIc9zD0FAsBgFCGgmOxyPD9Xu8tbkD7rxJZsEfHxXj3LgO8AYC2e/743D5WivqWR\n"
"8wNlSn53ED7BuNBTbnaWhfElqqpyPYtUDi3G+R87dv48Yec1xMdUu0aRb65QeerT\n"
"O2TL6F+KOlKWklBSzibCLBNLTBkXsf1aQb1FxQtGJjrTkA0FEqEvGgGtHHfMoRFq\n"
"T1kvzEocWJGQv78eCpREl35vho4Aj+0MgUvGPfBlijoWFYHCm2LRGOLv1yWLRrOS\n"
"LHaxJ2tK/0sXxIoxUQqLcwrobnA4l2drdPB+EeBpYBlYhhsp/F3IRQ3ylOpIPBgd\n"
"AOaroBlSDin5rLfa7T0YvzcAcNvodVjszIGrSeECx1l4VdiL+M73MvvW4GyfIE2S\n"
"P7wyuvA665ZFyqsV1ZerHCKyhX3G0xCj+V6wMjAWyHlh\n"
"-----END ENCRYPTED PRIVATE KEY-----";
#endif

WOLFMQTT_EXAMPLE_CERT const char* device_cert =
"-----BEGIN CERTIFICATE-----\n"
"MIIDWjCCAkKgAwIBAgIVANIzUucLFUREa2BiJUXoRv6Z4XaIMA0GCSqGSIb3DQEB\n"
"CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n"
"IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0xNjExMzAxODIz\n"
"MzNaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\n"
"dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqwApWFt9ARZuULw++\n"
"C5uqklqxWgISxJ+8sXhvkMgCygx6J4/brLpXJ3eeNHK6KBJDqM/6ajcbKpJ94Jup\n"
"8nZ3HcE0gISTs/joG7ft7CgjbilJydP7lFx/D/92HxYcOrR3T3feLi84oQoDp+3n\n"
"UDFjorO82vDGjpuaXRWLYMHHdYsbD4wOIdeTYvSB5JhI2MXP+712SARQ+EQZs1m7\n"
"DbLGHBs19qI97aV3kWKvqJTJu6P3fF9aqo2WzvtXpCPuYjylqZ0YW1CeQ/7qXZdN\n"
"rolu6cKpmjU9RG1RdyHl1vqsyr/qtFmuUkzs2eA8jW+/yMXhPcbiaPJPwjgrFArW\n"
"z3T1AgMBAAGjYDBeMB8GA1UdIwQYMBaAFJZuFLsbLnLXbHrfXutsILjrIB5qMB0G\n"
"A1UdDgQWBBTHoiSGnE/lSskzSaWXWflJWIC/szAMBgNVHRMBAf8EAjAAMA4GA1Ud\n"
"DwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAlchZ7iW3kr6ny20ySEUhc9Dl\n"
"gEcihl6gcY7Oew0xWoUzuXBkSoOVbjPRiy9RbaLA94QgoxtZCpkF0F81Jro878+m\n"
"a5Cx0Ifj66ZAaeR3FSCtjSyLgg12peZux+VXchq3MwNb8iTD1nruIJ8kLPM+7fQy\n"
"nbGM69r7lUZ1539t9O44OB0aIRDRC+ZpYINnWjiuO7hK27oZs3HCk484C+OjRusJ\n"
"jKrLFSjEdbaUj3ukMv0sGO693Z5DqTL2t9ylM2LuE9iyiWF7DBHhuDLHsZfirjk3\n"
"7/MBDwfbv7td8GOy6C2BennS5tWOL06+8lYErP4ECEQqW6izI2Cup+O01rrjkQ==\n"
"-----END CERTIFICATE-----";

static int mqtt_aws_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    PRINTF("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)", preverify,
        store->error, store->error != 0 ?
            wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
static int mqtt_aws_tls_cb(MqttClient* client)
{
    int rc = WOLFSSL_FAILURE;

    /* Use highest available and allow downgrade. If wolfSSL is built with
     * old TLS support, it is possible for a server to force a downgrade to
     * an insecure version. */
    client->tls.ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER,
                               mqtt_aws_tls_verify_cb);

        /* Load CA certificate buffer */
        rc = wolfSSL_CTX_load_verify_buffer(client->tls.ctx,
            (const byte*)root_ca, (long)XSTRLEN(root_ca), WOLFSSL_FILETYPE_PEM);

        /* Load Client Cert */
        if (rc == WOLFSSL_SUCCESS)
            rc = wolfSSL_CTX_use_certificate_buffer(client->tls.ctx,
                (const byte*)device_cert, (long)XSTRLEN(device_cert),
                WOLFSSL_FILETYPE_PEM);

        #ifdef WOLFSSL_ENCRYPTED_KEYS
            /* Setup password callback for pkcs8 key */
            wolfSSL_CTX_set_default_passwd_cb(client->tls.ctx,
                    mqtt_password_cb);
        #endif

        /* Load Private Key */
        if (rc == WOLFSSL_SUCCESS)
            rc = wolfSSL_CTX_use_PrivateKey_buffer(client->tls.ctx,
                (const byte*)device_priv_key, (long)XSTRLEN(device_priv_key),
                WOLFSSL_FILETYPE_PEM);
    }

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

    (void)mqttCtx;

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("Payload (%d - %d) printing %d bytes:" LINE_END "%s",
        msg->buffer_pos, msg->buffer_pos + msg->buffer_len, len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
        if (mqttCtx->test_mode) {
            mTestDone = 1;
        }
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_PROPERTY_CB
/* The property callback is called after decoding a packet that contains at
   least one property. The property list is deallocated after returning from
   the callback. */
static int mqtt_property_cb(MqttClient *client, MqttProp *head, void *ctx)
{
    MqttProp *prop = head;
    int rc = 0;
    MQTTCtx* mqttCtx;

    if ((client == NULL) || (client->ctx == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    mqttCtx = (MQTTCtx*)client->ctx;

    while (prop != NULL) {
        PRINTF("Property CB: Type %d", prop->type);
        switch (prop->type) {
            case MQTT_PROP_SUBSCRIPTION_ID_AVAIL:
                mqttCtx->subId_not_avail =
                        prop->data_byte == 0;
                break;

            case MQTT_PROP_TOPIC_ALIAS_MAX:
                mqttCtx->topic_alias_max =
                 (mqttCtx->topic_alias_max < prop->data_short) ?
                 mqttCtx->topic_alias_max : prop->data_short;
                break;

            case MQTT_PROP_MAX_PACKET_SZ:
                if ((prop->data_int > 0) &&
                    (prop->data_int <= MQTT_PACKET_SZ_MAX))
                {
                    client->packet_sz_max =
                        (client->packet_sz_max < prop->data_int) ?
                         client->packet_sz_max : prop->data_int;
                }
                else {
                    /* Protocol error */
                    rc = MQTT_CODE_ERROR_PROPERTY;
                }
                break;

            case MQTT_PROP_SERVER_KEEP_ALIVE:
                mqttCtx->keep_alive_sec = prop->data_short;
                break;

            case MQTT_PROP_MAX_QOS:
                client->max_qos = prop->data_byte;
                break;

            case MQTT_PROP_RETAIN_AVAIL:
                client->retain_avail = prop->data_byte;
                break;

            case MQTT_PROP_REASON_STR:
                PRINTF("Reason String: %.*s",
                        prop->data_str.len, prop->data_str.str);
                break;

            case MQTT_PROP_USER_PROP:
                PRINTF("User property: key=\"%.*s\", value=\"%.*s\"",
                        prop->data_str.len, prop->data_str.str,
                        prop->data_str2.len, prop->data_str2.str);
                break;

            case MQTT_PROP_ASSIGNED_CLIENT_ID:
            case MQTT_PROP_PAYLOAD_FORMAT_IND:
            case MQTT_PROP_MSG_EXPIRY_INTERVAL:
            case MQTT_PROP_CONTENT_TYPE:
            case MQTT_PROP_RESP_TOPIC:
            case MQTT_PROP_CORRELATION_DATA:
            case MQTT_PROP_SUBSCRIPTION_ID:
            case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
            case MQTT_PROP_TOPIC_ALIAS:
            case MQTT_PROP_TYPE_MAX:
            case MQTT_PROP_RECEIVE_MAX:
            case MQTT_PROP_WILDCARD_SUB_AVAIL:
            case MQTT_PROP_SHARED_SUBSCRIPTION_AVAIL:
            case MQTT_PROP_RESP_INFO:
            case MQTT_PROP_SERVER_REF:
            case MQTT_PROP_AUTH_METHOD:
            case MQTT_PROP_AUTH_DATA:
            case MQTT_PROP_NONE:
                break;
            case MQTT_PROP_REQ_PROB_INFO:
            case MQTT_PROP_WILL_DELAY_INTERVAL:
            case MQTT_PROP_REQ_RESP_INFO:
            default:
                /* Invalid */
                rc = MQTT_CODE_ERROR_PROPERTY;
                break;
        }
        prop = prop->next;
    }

    (void)ctx;

    return rc;
}
#endif /* WOLFMQTT_PROPERTY_CB */


int awsiot_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;

    switch (mqttCtx->stat)
    {
        case WMQ_BEGIN:
        {
            PRINTF("AwsIoT Client: QoS %d, Use TLS %d", mqttCtx->qos, mqttCtx->use_tls);

            /* Aws IoT requires TLS */
            if (!mqttCtx->use_tls) {
                return MQTT_CODE_ERROR_BAD_ARG;
            }
        }
        FALL_THROUGH;

        case WMQ_NET_INIT:
        {
            mqttCtx->stat = WMQ_NET_INIT;

            /* Initialize Network */
            rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Net Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* setup tx/rx buffers */
            mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
        }
        FALL_THROUGH;

        case WMQ_INIT:
        {
            mqttCtx->stat = WMQ_INIT;

            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net, mqtt_message_cb,
                mqttCtx->tx_buf, MAX_BUFFER_SIZE, mqttCtx->rx_buf, MAX_BUFFER_SIZE,
                mqttCtx->cmd_timeout_ms);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            mqttCtx->client.ctx = mqttCtx;
#ifdef WOLFMQTT_PROPERTY_CB
            rc = MqttClient_SetPropertyCallback(&mqttCtx->client,
                    mqtt_property_cb, NULL);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
#endif
        }
        FALL_THROUGH;

        case WMQ_TCP_CONN:
        {
            mqttCtx->stat = WMQ_TCP_CONN;

            /* Connect to broker */
            rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host, mqttCtx->port,
                DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqtt_aws_tls_cb);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Build connect packet */
            XMEMSET(&mqttCtx->connect, 0, sizeof(MqttConnect));
            mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
            mqttCtx->connect.clean_session = mqttCtx->clean_session;
            mqttCtx->connect.client_id = mqttCtx->client_id;

            /* Last will and testament sent by broker to subscribers
                of topic when broker connection is lost */
            XMEMSET(&mqttCtx->lwt_msg, 0, sizeof(mqttCtx->lwt_msg));
            mqttCtx->connect.lwt_msg = &mqttCtx->lwt_msg;
            mqttCtx->connect.enable_lwt = mqttCtx->enable_lwt;
            if (mqttCtx->enable_lwt) {
                /* Send client id in LWT payload */
                mqttCtx->lwt_msg.qos = mqttCtx->qos;
                mqttCtx->lwt_msg.retain = 0;
                mqttCtx->lwt_msg.topic_name = AWSIOT_PUBLISH_TOPIC"lwt";
                mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
                mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);
            }
            /* Optional authentication */
            mqttCtx->connect.username = mqttCtx->username;
            mqttCtx->connect.password = mqttCtx->password;
#ifdef WOLFMQTT_V5
            {
                /* Request Response Information */
                MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
                prop->type = MQTT_PROP_REQ_RESP_INFO;
                prop->data_byte = 1;
            }
            {
                /* Request Problem Information */
                MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
                prop->type = MQTT_PROP_REQ_PROB_INFO;
                prop->data_byte = 1;
            }
#endif
        }
        FALL_THROUGH;

        case WMQ_MQTT_CONN:
        {
            mqttCtx->stat = WMQ_MQTT_CONN;

            /* Send Connect and wait for Connect Ack */
            rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
#ifdef WOLFMQTT_V5
            if (mqttCtx->connect.props != NULL) {
                /* Release the allocated properties */
                MqttClient_PropsFree(mqttCtx->connect.props);
            }
#endif
            PRINTF("MQTT Connect: Proto (%s), %s (%d)",
                MqttClient_GetProtocolVersionString(&mqttCtx->client),
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags &
                    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topic_name;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Subscribe Topic */
            XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx->subscribe.packet_id = mqtt_get_packetid();
            mqttCtx->subscribe.topic_count = sizeof(mqttCtx->topics)/sizeof(MqttTopic);
            mqttCtx->subscribe.topics = mqttCtx->topics;
        }
        FALL_THROUGH;

        case WMQ_SUB:
        {
            mqttCtx->stat = WMQ_SUB;

            rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* show subscribe results */
            for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
                MqttTopic *topic = &mqttCtx->subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    topic->topic_filter,
                    topic->qos, topic->return_code);
            }

            /* Publish Topic */
            XSNPRINTF((char*)mqttCtx->app_ctx, AWSIOT_PUBLISH_MSG_SZ,
                "{\"state\":{\"reported\":{\"hardware\":{\"type\":\"%s\",\"firmware_version\":\"%s\"}}}}",
                APP_HARDWARE, APP_FIRMWARE_VERSION);

            XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
            mqttCtx->publish.retain = 0;
            mqttCtx->publish.qos = mqttCtx->qos;
            mqttCtx->publish.duplicate = 0;
            mqttCtx->publish.topic_name = AWSIOT_PUBLISH_TOPIC;
            mqttCtx->publish.packet_id = mqtt_get_packetid();
            mqttCtx->publish.buffer = (byte*)mqttCtx->app_ctx;
            mqttCtx->publish.total_len = (word32)XSTRLEN((char*)mqttCtx->app_ctx);
        }
        FALL_THROUGH;

        case WMQ_PUB:
        {
            mqttCtx->stat = WMQ_PUB;

            rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Publish: Topic %s, ID %d, %s (%d)",
                mqttCtx->publish.topic_name, mqttCtx->publish.packet_id,
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
        }
        FALL_THROUGH;

        case WMQ_WAIT_MSG:
        {
            mqttCtx->stat = WMQ_WAIT_MSG;

            do {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);

            #ifdef WOLFMQTT_NONBLOCK
                /* Track elapsed time with no activity and trigger timeout */
                rc = mqtt_check_timeout(rc, &mqttCtx->start_sec,
                    mqttCtx->cmd_timeout_ms/1000);
            #endif

                /* check return code */
                if (rc == MQTT_CODE_CONTINUE) {
                    return rc;
                }

                /* check for test mode or stop */
                if (mStopRead || mTestDone) {
                    rc = MQTT_CODE_SUCCESS;
                    mqttCtx->stat = WMQ_DISCONNECT;
                    PRINTF("MQTT Exiting...");
                    break;
                }

            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
                if (rc == MQTT_CODE_STDIN_WAKE) {
                    /* Get data from STDIO */
                    XMEMSET(mqttCtx->rx_buf, 0, MAX_BUFFER_SIZE);
                    if (XFGETS((char*)mqttCtx->rx_buf, MAX_BUFFER_SIZE - 1, stdin) != NULL) {
                        /* rc = (int)XSTRLEN((char*)mqttCtx->rx_buf); */

                        /* Publish Topic */
                        XSNPRINTF((char*)mqttCtx->app_ctx, AWSIOT_PUBLISH_MSG_SZ,
                            "{\"state\":{\"reported\":{\"msg\":\"%s\"}}}",
                            mqttCtx->rx_buf);
                        mqttCtx->stat = WMQ_PUB;
                        XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
                        mqttCtx->publish.retain = 0;
                        mqttCtx->publish.qos = mqttCtx->qos;
                        mqttCtx->publish.duplicate = 0;
                        mqttCtx->publish.topic_name = AWSIOT_PUBLISH_TOPIC;
                        mqttCtx->publish.packet_id = mqtt_get_packetid();
                        mqttCtx->publish.buffer = (byte*)mqttCtx->app_ctx;
                        mqttCtx->publish.total_len = (word32)XSTRLEN((char*)mqttCtx->app_ctx);
                        rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
                        PRINTF("MQTT Publish: Topic %s, ID %d, %s (%d)",
                            mqttCtx->publish.topic_name, mqttCtx->publish.packet_id,
                            MqttClient_ReturnCodeToString(rc), rc);
                    }
                }
                else
            #endif
                if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* Keep Alive */
                    PRINTF("Keep-alive timeout, sending ping");

                    rc = MqttClient_Ping_ex(&mqttCtx->client, &mqttCtx->ping);
                    if (rc == MQTT_CODE_CONTINUE) {
                        return rc;
                    }
                    else if (rc != MQTT_CODE_SUCCESS) {
                        PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }
                else if (rc != MQTT_CODE_SUCCESS) {
                    /* There was an error */
                    PRINTF("MQTT Message Wait: %s (%d)",
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }
            } while (1);

            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_DISCONNECT:
        {
            /* Disconnect */
            rc = MqttClient_Disconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

        case WMQ_NET_DISCONNECT:
        {
            mqttCtx->stat = WMQ_NET_DISCONNECT;

            rc = MqttClient_NetDisconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }
        FALL_THROUGH;

        case WMQ_DONE:
        {
            mqttCtx->stat = WMQ_DONE;
            rc = mqttCtx->return_code;
            goto exit;
        }

        case WMQ_UNSUB: /* not used */
        case WMQ_PING:
        default:
            rc = MQTT_CODE_ERROR_STAT;
            goto exit;
    } /* switch */

disconn:
    mqttCtx->stat = WMQ_NET_DISCONNECT;
    mqttCtx->return_code = rc;
    rc = MQTT_CODE_CONTINUE;

exit:

    if (rc != MQTT_CODE_CONTINUE) {
        /* Free resources */
        if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
        if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

        /* Cleanup network */
        MqttClientNet_DeInit(&mqttCtx->net);

        MqttClient_DeInit(&mqttCtx->client);
    }

    return rc;
}
#endif /* ENABLE_AWSIOT_EXAMPLE */


/* so overall tests can pull in test function */
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
            #ifdef ENABLE_AWSIOT_EXAMPLE
                mStopRead = 1;
            #endif
                PRINTF("Received Ctrl+c");
                return TRUE;
            }
            return FALSE;
        }
    #elif HAVE_SIGNAL
        #include <signal.h>
        static void sig_handler(int signo)
        {
            if (signo == SIGINT) {
            #ifdef ENABLE_AWSIOT_EXAMPLE
                mStopRead = 1;
            #endif
                PRINTF("Received SIGINT");
            }
        }
    #endif

#ifdef NO_MAIN_DRIVER
    int awsiot_main(int argc, char** argv)
#else
    int main(int argc, char** argv)
#endif /* NO_MAIN_DRIVER */
    {
        int rc;
    #ifdef ENABLE_AWSIOT_EXAMPLE
        MQTTCtx mqttCtx;
        char pubMsg[AWSIOT_PUBLISH_MSG_SZ] = {0};

        /* init defaults */
        mqtt_init_ctx(&mqttCtx);
        mqttCtx.app_name = "awsiot";
        mqttCtx.host = AWSIOT_HOST;
        mqttCtx.qos = AWSIOT_QOS;
        mqttCtx.keep_alive_sec = AWSIOT_KEEP_ALIVE_SEC;
        mqttCtx.client_id = AWSIOT_DEVICE_ID;
        mqttCtx.topic_name = AWSIOT_SUBSCRIBE_TOPIC;
        mqttCtx.cmd_timeout_ms = AWSIOT_CMD_TIMEOUT_MS;
        mqttCtx.use_tls = 1;
        mqttCtx.app_ctx = pubMsg;

        /* parse arguments */
        rc = mqtt_parse_args(&mqttCtx, argc, argv);
        if (rc != 0) {
            return rc;
        }
    #endif

    #ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
    #elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
    #endif

    #ifdef ENABLE_AWSIOT_EXAMPLE
        do {
            rc = awsiot_test(&mqttCtx);
        } while (!mStopRead && rc == MQTT_CODE_CONTINUE);

        mqtt_free_ctx(&mqttCtx);
    #else
        (void)argc;
        (void)argv;

        /* This example requires wolfSSL 3.9.1 or later with base64encode enabled */
        PRINTF("Example not compiled in!");
        rc = 0; /* return success, so make check passes with TLS disabled */
    #endif

        return (rc == 0) ? 0 : EXIT_FAILURE;
    }
