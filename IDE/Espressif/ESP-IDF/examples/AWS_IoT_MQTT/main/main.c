/* main.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include "sdkconfig.h"
#include "main.h"

/* ESP specific */
#include <nvs_flash.h>
#include <esp_log.h>
#include <esp_event.h>

/* wolfSSL */
#include <wolfssl/wolfcrypt/settings.h> /* includes wolfSSL user-settings.h */
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#ifndef WOLFSSL_ESPIDF
    #warning "Problem with wolfSSL user_settings."
    #warning "Check components/wolfssl/include"
#endif

/* this project */
#include "wifi_connect.h"
#include "time_helper.h"

static const char* const TAG = "wolfmqtt main";

void app_main(void)
{
    int ret = 0;
    ESP_LOGI(TAG, "------------- wolfSSL wolfMQTT AWS IoT Example ---------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "---------------------- BEGIN MAIN ----------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "--------------------------------------------------------");
#ifdef HAVE_VERSION_EXTENDED_INFO
    esp_ShowExtendedSystemInfo();
#endif

    /* Set time for cert validation.
     * Some lwIP APIs, including SNTP functions, are not thread safe. */
    ret = set_time(); /* need to setup NTP before WiFi */

    /* Optionally erase flash */
    /* ESP_ERROR_CHECK(nvs_flash_erase()); */

#ifdef FOUND_PROTOCOL_EXAMPLES_DIR
    ESP_LOGI(TAG, "FOUND_PROTOCOL_EXAMPLES_DIR active, using example code.");
    ESP_ERROR_CHECK(nvs_flash_init());

    #if defined(CONFIG_IDF_TARGET_ESP32H2)
        ESP_LOGE(TAG, "There's no WiFi on ESP32-H2.");
    #else
        #ifdef CONFIG_EXAMPLE_WIFI_SSID
            if (XSTRCMP(CONFIG_EXAMPLE_WIFI_SSID, "myssid") == 0) {
                ESP_LOGW(TAG, "WARNING: CONFIG_EXAMPLE_WIFI_SSID is myssid.");
                ESP_LOGW(TAG, "  Do you have a WiFi AP called myssid, or ");
                ESP_LOGW(TAG, "  did you forget the ESP-IDF configuration?");
            }
        #else
            #define CONFIG_EXAMPLE_WIFI_SSID "myssid"
            ESP_LOGW(TAG, "WARNING: CONFIG_EXAMPLE_WIFI_SSID not defined.");
        #endif
        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());
        ESP_ERROR_CHECK(example_connect());
    #endif
#else
    ESP_ERROR_CHECK(nvs_flash_init());

    /* Initialize NVS */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    #if defined(CONFIG_IDF_TARGET_ESP32H2)
        ESP_LOGE(TAG, "There's no WiFi on ESP32-H2. ");
    #else
        /* Initialize WiFi */
        ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
        ret = wifi_init_sta();
        while (ret != 0) {
            ESP_LOGI(TAG, "Waiting...");
            vTaskDelay(60000 / portTICK_PERIOD_MS);
            ESP_LOGI(TAG, "Trying WiFi again...");
            ret = wifi_init_sta();
        }
    #endif
#endif

    /* Once we are connected to the network, start & wait for NTP time */
    ret = set_time_wait_for_ntp();

    if (ret < -1) {
        /* a value of -1 means there was no NTP server, so no need to wait */
        ESP_LOGI(TAG, "Waiting 10 more seconds for NTP to complete." );
        vTaskDelay(10000 / portTICK_PERIOD_MS); /* brute-force solution */
        esp_show_current_datetime();
    }

    /* HWM is maximum amount of stack space that has been unused, in bytes
     * not words (unlike vanilla freeRTOS). */
    ESP_LOGI(TAG, "Initial Stack Used (before wolfSSL Server): %d bytes",
                   CONFIG_ESP_MAIN_TASK_STACK_SIZE
                   - (uxTaskGetStackHighWaterMark(NULL))
            );
    ESP_LOGI(TAG, "Starting awsiot_main...\n");

    awsiot_main((int)NULL, (char**)NULL);
    ESP_LOGI(TAG, "\n\nDone!"
                  "If running from idf.py monitor, press twice: Ctrl+]");

    ESP_LOGV(TAG, "\n\nLoop...\n\n");
    ESP_LOGI(TAG, "Stack used: %d", CONFIG_ESP_MAIN_TASK_STACK_SIZE
                                    - uxTaskGetStackHighWaterMark(NULL));

    while (1) {
#if defined(SINGLE_THREADED)
        ESP_LOGV(TAG, "\n\nSINGLE_THREADED end loop.\n\n");
        while (1) {
            vTaskDelay(1000);
        }
#else
        vTaskDelay(60000);
#endif
    }
}
