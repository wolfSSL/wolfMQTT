#!/usr/bin/env python3
# gen_corpus.py - Generate seed corpus for wolfMQTT broker fuzzer
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# Creates minimal valid (and intentionally malformed) MQTT packets as
# seed files in tests/fuzz/corpus/. These bootstrap libFuzzer with
# meaningful starting inputs that exercise different broker code paths.
#
# Usage: python3 tests/fuzz/gen_corpus.py

import os
import struct

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def encode_remaining_length(length):
    """Encode MQTT remaining length as variable byte integer."""
    encoded = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        encoded.append(byte)
        if length == 0:
            break
    return bytes(encoded)


def mqtt_packet(pkt_type, flags, payload):
    """Build an MQTT packet: fixed header + remaining length + payload."""
    header = bytes([(pkt_type << 4) | (flags & 0x0F)])
    return header + encode_remaining_length(len(payload)) + payload


def mqtt_string(s):
    """Encode an MQTT UTF-8 string (2-byte length prefix + data)."""
    encoded = s.encode("utf-8")
    return struct.pack("!H", len(encoded)) + encoded


def write_seed(name, data):
    """Write a seed corpus file."""
    path = os.path.join(CORPUS_DIR, name)
    with open(path, "wb") as f:
        f.write(data)


def gen_connect_v311(client_id="fuzz", clean=True, keepalive=60):
    """CONNECT v3.1.1 packet."""
    var_header = mqtt_string("MQTT")           # protocol name
    var_header += bytes([4])                    # protocol level (v3.1.1)
    flags = 0x02 if clean else 0x00            # connect flags (clean session)
    var_header += bytes([flags])
    var_header += struct.pack("!H", keepalive)  # keep alive
    payload = mqtt_string(client_id)
    return mqtt_packet(1, 0, var_header + payload)


def gen_connect_v5(client_id="fuzz", clean=True, keepalive=60):
    """CONNECT v5.0 packet."""
    var_header = mqtt_string("MQTT")
    var_header += bytes([5])                    # protocol level (v5.0)
    flags = 0x02 if clean else 0x00
    var_header += bytes([flags])
    var_header += struct.pack("!H", keepalive)
    var_header += bytes([0])                    # properties length = 0
    payload = mqtt_string(client_id)
    return mqtt_packet(1, 0, var_header + payload)


def gen_connect_lwt():
    """CONNECT v3.1.1 with Last Will & Testament."""
    var_header = mqtt_string("MQTT")
    var_header += bytes([4])                    # v3.1.1
    # flags: clean=1, will=1, will_qos=1, will_retain=0
    var_header += bytes([0x0E])
    var_header += struct.pack("!H", 60)
    payload = mqtt_string("fuzz")               # client ID
    payload += mqtt_string("will/topic")        # will topic
    payload += mqtt_string("will payload")      # will message
    return mqtt_packet(1, 0, var_header + payload)


def gen_connect_auth():
    """CONNECT v3.1.1 with username and password."""
    var_header = mqtt_string("MQTT")
    var_header += bytes([4])
    var_header += bytes([0xC2])                 # clean + username + password
    var_header += struct.pack("!H", 60)
    payload = mqtt_string("fuzz")
    payload += mqtt_string("testuser")
    payload += mqtt_string("testpass")
    return mqtt_packet(1, 0, var_header + payload)


def gen_publish(topic, msg, qos=0, packet_id=1):
    """PUBLISH packet."""
    flags = (qos & 0x03) << 1
    var_header = mqtt_string(topic)
    if qos > 0:
        var_header += struct.pack("!H", packet_id)
    payload = msg.encode("utf-8") if isinstance(msg, str) else msg
    return mqtt_packet(3, flags, var_header + payload)


def gen_subscribe(topic_filter, qos=1, packet_id=1):
    """SUBSCRIBE packet."""
    var_header = struct.pack("!H", packet_id)
    payload = mqtt_string(topic_filter) + bytes([qos])
    return mqtt_packet(8, 0x02, var_header + payload)


def gen_unsubscribe(topic_filter, packet_id=1):
    """UNSUBSCRIBE packet."""
    var_header = struct.pack("!H", packet_id)
    payload = mqtt_string(topic_filter)
    return mqtt_packet(10, 0x02, var_header + payload)


def gen_ack(pkt_type, packet_id=1, flags=0):
    """Generic ACK packet (PUBACK, PUBREC, PUBREL, PUBCOMP)."""
    return mqtt_packet(pkt_type, flags, struct.pack("!H", packet_id))


def main():
    os.makedirs(CORPUS_DIR, exist_ok=True)

    # CONNECT variants
    write_seed("connect_v311.bin", gen_connect_v311())
    write_seed("connect_v5.bin", gen_connect_v5())
    write_seed("connect_lwt.bin", gen_connect_lwt())
    write_seed("connect_auth.bin", gen_connect_auth())
    write_seed("connect_empty_id.bin", gen_connect_v311(client_id=""))
    write_seed("connect_long_id.bin", gen_connect_v311(client_id="A" * 64))

    # PUBLISH variants
    write_seed("publish_qos0.bin", gen_publish("test", "hello", qos=0))
    write_seed("publish_qos1.bin", gen_publish("test", "hello", qos=1))
    write_seed("publish_qos2.bin", gen_publish("test", "hello", qos=2))
    write_seed("publish_long_topic.bin",
               gen_publish("a/" * 64, "data", qos=0))
    write_seed("publish_empty_payload.bin",
               gen_publish("test", "", qos=0))

    # SUBSCRIBE / UNSUBSCRIBE
    write_seed("subscribe.bin", gen_subscribe("test/#"))
    write_seed("subscribe_wildcard_plus.bin", gen_subscribe("test/+/data"))
    write_seed("subscribe_multi_level.bin", gen_subscribe("#"))
    write_seed("unsubscribe.bin", gen_unsubscribe("test/#"))

    # QoS handshake packets
    write_seed("puback.bin", gen_ack(4, packet_id=1))
    write_seed("pubrec.bin", gen_ack(5, packet_id=1))
    write_seed("pubrel.bin", gen_ack(6, packet_id=1, flags=0x02))
    write_seed("pubcomp.bin", gen_ack(7, packet_id=1))

    # Control packets
    write_seed("pingreq.bin", b"\xC0\x00")
    write_seed("disconnect.bin", b"\xE0\x00")
    write_seed("disconnect_v5.bin", b"\xE0\x02\x00\x00")  # reason=0, props=0

    # Multi-packet sequences: CONNECT followed by another packet.
    # The broker requires CONNECT before accepting other packet types,
    # so these seeds teach the fuzzer that CONNECT-first gets deeper coverage.
    connect = gen_connect_v5(client_id="fuzz", keepalive=0)
    connect_v4 = gen_connect_v311(client_id="fuzz", keepalive=0)

    write_seed("seq_connect_publish_qos0.bin",
               connect + gen_publish("test", "hello", qos=0))
    write_seed("seq_connect_publish_qos1.bin",
               connect + gen_publish("test", "hello", qos=1))
    write_seed("seq_connect_publish_qos2.bin",
               connect + gen_publish("test", "hello", qos=2))
    write_seed("seq_connect_publish_retain.bin",
               connect + mqtt_packet(3, 0x01, mqtt_string("test") + b"retained"))
    write_seed("seq_connect_subscribe.bin",
               connect + gen_subscribe("test/#"))
    write_seed("seq_connect_subscribe_wildcard.bin",
               connect + gen_subscribe("+/data/#"))
    write_seed("seq_connect_unsubscribe.bin",
               connect + gen_unsubscribe("test/#"))
    write_seed("seq_connect_pingreq.bin",
               connect + b"\xC0\x00")
    write_seed("seq_connect_disconnect.bin",
               connect + b"\xE0\x00")
    write_seed("seq_connect_puback.bin",
               connect + gen_ack(4, packet_id=1))
    write_seed("seq_connect_pubrel.bin",
               connect + gen_ack(6, packet_id=1, flags=0x02))

    # Multi-packet: CONNECT + SUBSCRIBE + PUBLISH (to subscribed topic)
    write_seed("seq_connect_sub_pub.bin",
               connect + gen_subscribe("test/#")
               + gen_publish("test/hello", "world", qos=1, packet_id=2))

    # v3.1.1 multi-packet sequences
    write_seed("seq_v311_connect_publish.bin",
               connect_v4 + gen_publish("test", "hello", qos=0))
    write_seed("seq_v311_connect_subscribe.bin",
               connect_v4 + gen_subscribe("test/#"))

    # CONNECT with LWT, then disconnect without clean (triggers will)
    write_seed("seq_lwt_disconnect.bin",
               gen_connect_lwt() + b"\xE0\x00")

    # Edge cases / malformed
    write_seed("truncated_header.bin", b"\x10")
    write_seed("bad_type.bin", b"\xF0\x00")
    write_seed("zero_remaining.bin", b"\x30\x00")
    write_seed("oversized_remaining.bin",
               b"\x10\xFF\xFF\xFF\x7F" + b"\x00" * 10)
    write_seed("bad_protocol.bin",
               b"\x10\x0C" + mqtt_string("NOPE") + b"\x04\x02\x00\x3C"
               + mqtt_string(""))
    write_seed("min_header.bin", b"\x10\x00")

    count = len([f for f in os.listdir(CORPUS_DIR) if f.endswith(".bin")])
    print(f"Generated {count} seed corpus files in {CORPUS_DIR}")


if __name__ == "__main__":
    main()
