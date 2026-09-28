/* client.c
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

#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttclient/mqttclient.h"

#if defined(WOLFMQTT_DEFAULT_TLS) && (WOLFMQTT_DEFAULT_TLS == 1)
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/rtc.h>
#include <zephyr/posix/time.h>
#include <zephyr/sys/timeutil.h>

static int mqtt_init_tls_clock(void)
{
    const struct device* rtc = DEVICE_DT_GET(DT_ALIAS(rtc));
    struct rtc_time date;
    struct timespec now;

    if (!device_is_ready(rtc) || rtc_get_time(rtc, &date) != 0) {
        return -1;
    }
    /* The QEMU CMOS RTC stores a two-digit year. Its test certificates are
     * issued in 2026, so interpret that value in the 2000s. */
    if (date.tm_year < 100) {
        date.tm_year += 100;
    }
    now.tv_sec = timeutil_timegm(rtc_time_to_tm(&date));
    now.tv_nsec = date.tm_nsec;
    if (now.tv_sec == (time_t)-1) {
        return -1;
    }
    return clock_settime(CLOCK_REALTIME, &now);
}
#endif

int main(void)
{
    int rc;
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);

#if defined(WOLFMQTT_DEFAULT_TLS) && (WOLFMQTT_DEFAULT_TLS == 1)
    if (mqtt_init_tls_clock() != 0) {
        PRINTF("Could not set the clock for TLS certificate validation");
        return EXIT_FAILURE;
    }

    /* QEMU reaches the broker at 192.0.2.2, while the test certificate
     * identifies it as localhost. Select that DNS identity for SNI and
     * certificate verification before sending MQTT credentials. */
    {
        static char app_name[] = "mqttclient";
        static char sni_option[] = "-S";
        static char peer_name[] = "localhost";
        char* tls_args[] = { app_name, sni_option, peer_name };

        if (mqtt_parse_args(&mqttCtx, 3, tls_args) != 0) {
            return EXIT_FAILURE;
        }
    }
#endif

    mqttCtx.test_mode = 1;

    /* Set port as configured in scripts/broker_test/mosquitto.conf */
#if defined(WOLFMQTT_DEFAULT_TLS) && (WOLFMQTT_DEFAULT_TLS == 1)
    mqttCtx.port = 18883;
#else
    mqttCtx.port = 11883;
#endif

    rc = mqttclient_test(&mqttCtx);

    mqtt_free_ctx(&mqttCtx);

    if (rc == 0)
        PRINTF("Zephyr MQTT test passed");

    return (rc == 0) ? 0 : EXIT_FAILURE;
}
