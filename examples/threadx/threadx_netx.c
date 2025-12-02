/* threadx_netx.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


/* This is a start to an example use with ThreadX. It currently is being used
 * to confirm that compiling with all necessary NetX ThreadX API's succeds */

#ifdef HAVE_NETX

#include <stdio.h>
#include "tx_api.h"
#include "nx_api.h"
#include "nxd_dns.h"

#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttnet.h"
#include "examples/mqttexample.h"

#define DEMO_STACK_SIZE         40000
#define DEMO_IP_ADDRESS         IP_ADDRESS(192,168,1,129)
#define DEMO_NET_MASK           0xFFFFFF00
#define DEMO_GATEWAY_ADDRESS    IP_ADDRESS(192,168,1,1)
#define DEMO_DNS_SERVER         IP_ADDRESS(8,8,8,8)
#define DEMO_HOSTNAME           "test.mosquitto.org"
#define DEMO_PORT               1883
#define DEMO_TIMEOUT_MS         5000

/* ThreadX/NetX objects */
TX_THREAD       demo_thread;
ULONG           demo_thread_stack[DEMO_STACK_SIZE / sizeof(ULONG)];
NX_PACKET_POOL  pool_0;
NX_IP           ip_0;
NX_DNS          dns_0;
void *first_unused_memory;

/* Forward declaration */
void demo_thread_entry(ULONG thread_input);
void nx_driver_placeholder(NX_IP_DRIVER *driver_req);

#ifdef __linux__
int main(int argc, char** argv)
{
    tx_kernel_enter();
    return 0;
}
#endif

void tx_application_define(void *memory_ptr)
{
    first_unused_memory = memory_ptr;

    /* Create the main demo thread. */
    tx_thread_create(&demo_thread, "Demo Thread", demo_thread_entry, 0,
                    demo_thread_stack, DEMO_STACK_SIZE, 1, 1,
                    TX_NO_TIME_SLICE, TX_AUTO_START);
}

void demo_thread_entry(ULONG thread_input)
{
    UINT status;
    NXD_ADDRESS dns_server;
    MQTTCtx mqttCtx;
    MqttNet net;
    SocketContext *sockCtx;
    int rc;
    UCHAR* pointer = (UCHAR*)first_unused_memory;

    /* Initialize NetX system */
    nx_system_initialize();

    /* Create a packet pool. */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool",
                            1536, pointer, 16*1536);
    if (status != NX_SUCCESS) {
        printf("Packet pool create failed: %u\n", status);
        return;
    }
    pointer += 16*1536;

    /* Create an IP instance. */
    status = nx_ip_create(&ip_0, "NetX IP Instance",
                         DEMO_IP_ADDRESS, DEMO_NET_MASK,
                         &pool_0, nx_driver_placeholder,
                         pointer, 2048, 1);
    if (status != NX_SUCCESS) {
        printf("IP create failed: %u\n", status);
        return;
    }
    pointer += 2048;

    /* Enable ARP, ICMP, TCP, UDP */
    nx_arp_enable(&ip_0, pointer, 1024);
    pointer += 1024;
    nx_icmp_enable(&ip_0);
    nx_tcp_enable(&ip_0);
    nx_udp_enable(&ip_0);

    /* Create DNS instance */
    status = nx_dns_create(&dns_0, &ip_0, (UCHAR*)"DNS Client");
    if (status != NX_SUCCESS) {
        printf("DNS create failed: %u\n", status);
        return;
    }
    dns_server.nxd_ip_version = NX_IP_VERSION_V4;
    dns_server.nxd_ip_address.v4 = DEMO_DNS_SERVER;
    nxd_dns_server_add(&dns_0, &dns_server);

    /* Initialize MQTT context and network */
    mqtt_init_ctx(&mqttCtx);
    MqttClientNet_Init(&net, &mqttCtx);
    sockCtx = (SocketContext*)net.context;
    sockCtx->ipPtr  = &ip_0;
    sockCtx->dnsPtr = &dns_0;

    /* Use NetConnect to connect to the MQTT broker */
    rc = net.connect(sockCtx, DEMO_HOSTNAME, DEMO_PORT, DEMO_TIMEOUT_MS);
    if (rc == 0) {
        printf("NetConnect succeeded!\n");
        net.disconnect(sockCtx);
    } else {
        printf("NetConnect failed: %d\n", rc);
    }

    /* Cleanup (not strictly necessary in a demo) */
    nx_dns_delete(&dns_0);
    nx_ip_delete(&ip_0);
    nx_packet_pool_delete(&pool_0);
    /* Thread exits */
    tx_thread_terminate(&demo_thread);
}

/* Placeholder driver for demo purposes */
void nx_driver_placeholder(NX_IP_DRIVER *driver_req)
{
    NX_PARAMETER_NOT_USED(driver_req);
}
#endif /* HAVE_NETX */
