#ifndef MQTT_EXAMPLE_FIRMWARE_H
#define MQTT_EXAMPLE_FIRMWARE_H


#define FIRMWARE_TOPIC_NAME     "wolfmqttfw"
#define FIRMWARE_MAX_BUFFER     2048
#define FIRMWARE_MAX_PACKET     (FIRMWARE_MAX_BUFFER + sizeof(MqttPacket) + strlen(FIRMWARE_TOPIC_NAME) + MQTT_DATA_LEN_SIZE)

#define FIRMWARE_HASH_TYPE      WC_HASH_TYPE_SHA512
#define FIRMWARE_SIG_TYPE       WC_SIGNATURE_TYPE_ECC


/* Signature Len, Public Key Len, Firmware Len, Signature, Public Key, Data */
typedef struct _FirmwareHeader {
    uint16_t sigLen;
    uint16_t pubKeyLen;
    uint32_t fwLen;
} __attribute__ ((packed)) FirmwareHeader;


#endif /* MQTT_EXAMPLE_FIRMWARE_H */
