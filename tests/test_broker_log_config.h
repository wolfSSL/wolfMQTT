/* Prototypes for the hooks test_broker_log builds the broker against: PRINTF
 * is redirected to wolfmqtt_test_log and the broker clock to
 * wolfmqtt_test_broker_time_s. */
#ifndef WOLFMQTT_TEST_BROKER_LOG_CONFIG_H
#define WOLFMQTT_TEST_BROKER_LOG_CONFIG_H

/* Declared printf-like so a non-literal fmt can be passed on to vsnprintf
 * (clang -Wformat-nonliteral) and the broker's PRINTF calls are checked. */
#if defined(__GNUC__) || defined(__clang__)
void wolfmqtt_test_log(const char* fmt, ...)
    __attribute__((format(printf, 1, 2)));
#else
void wolfmqtt_test_log(const char* fmt, ...);
#endif
unsigned long wolfmqtt_test_broker_time_s(void);

#endif
