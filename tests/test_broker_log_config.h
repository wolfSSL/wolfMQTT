/* Prototypes for the hooks test_broker_log builds the broker against: PRINTF
 * is redirected to wolfmqtt_test_log and the broker clock to
 * wolfmqtt_test_broker_time_s. */
#ifndef WOLFMQTT_TEST_BROKER_LOG_CONFIG_H
#define WOLFMQTT_TEST_BROKER_LOG_CONFIG_H

void wolfmqtt_test_log(const char* fmt, ...);
unsigned long wolfmqtt_test_broker_time_s(void);

#endif
