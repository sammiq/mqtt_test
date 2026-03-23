//! Malformed packet handling compliance tests.
//!
//! The MQTT v5 spec requires the server to disconnect with reason code 0x81
//! (Malformed Packet) when it receives packets that violate protocol rules.
//! These tests send intentionally broken packets and verify the server
//! terminates the connection.

use std::time::Duration;


use crate::client::{self, RawClient};
use crate::codec::{ConnectParams, Packet};
use crate::types::{Compliance, SuiteRunner, TestConfig, TestContext, TestResult};


pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("MALFORMED PACKETS");

    suite.add(RESERVED_FLAGS, reserved_connect_flags(config));
    suite.add(BAD_REMAINING_LEN, malformed_remaining_length(config));
    suite.add(EMPTY_TOPIC_NO_ALIAS, publish_empty_topic_no_alias(config));
    suite.add(TOPIC_ALIAS_ZERO, publish_topic_alias_zero(config));
    suite.add(SUB_NO_FILTERS, subscribe_no_filters(config));
    suite.add(SUB_INVALID_QOS, subscribe_invalid_qos(config));
    suite.add(INVALID_WILDCARD, subscribe_invalid_wildcard(config));
    suite.add(UNSUB_NO_FILTERS, unsubscribe_no_filters(config));
    suite.add(UNSUB_RESERVED_BITS, unsubscribe_reserved_bits(config));
    suite.add(TOPIC_ALIAS_EXCEEDS_MAX, topic_alias_exceeds_maximum(config));
    suite.add(INVALID_PLUS_WILDCARD, subscribe_invalid_plus_wildcard(config));
    suite.add(NULL_IN_TOPIC, publish_topic_with_null_char(config));
    suite.add(SUB_WRONG_FIXED, subscribe_wrong_fixed_header_bits(config));
    suite.add(USERNAME_TRUNCATED, username_flag_truncated_payload(config));
    suite.add(PASSWORD_TRUNCATED, password_flag_truncated_payload(config));
    suite.add(UTF8_SURROGATE, utf8_surrogate_pair_in_topic(config));
    suite.add(PUBACK_BAD_FLAGS, puback_invalid_fixed_header_flags(config));
    suite.add(WILL_QOS_THREE, will_qos_three(config));
    suite.add(DISCONNECT_BAD_RESERVED, disconnect_reserved_bits(config));

    suite
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Expect the broker to either send DISCONNECT or close the connection.
async fn expect_disconnect(client: &mut RawClient, recv_timeout: Duration, ctx: &TestContext) -> TestResult {
    match client.recv(recv_timeout).await {
        Err(_) => TestResult::pass(ctx),
        Ok(Packet::Disconnect(_)) => TestResult::pass(ctx),
        Ok(other) => TestResult::fail_packet(ctx, "disconnect or connection close", &other),
    }
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-3.1.4-1"],
    description: "Server MUST validate CONNECT reserved flag is zero",
    compliance: Compliance::Must,
};

/// The CONNECT packet's connect-flags byte has a reserved bit (bit 0) that
/// MUST be 0. Sending it as 1 is a malformed packet [MQTT-3.1.2-3].
async fn reserved_connect_flags(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = RESERVED_FLAGS;

    let mut client = RawClient::connect_tcp(config.addr).await?;

    // Hand-craft a CONNECT with reserved flag bit 0 = 1.
    // Protocol Name "MQTT", Protocol Level 5, Connect Flags 0x03 (Clean Start + reserved=1).
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT fixed header
        0x11,                                           // remaining length = 17
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x03,                                           // connect flags: Clean Start=1, reserved=1 (bit 0)
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const BAD_REMAINING_LEN: TestContext = TestContext {
    refs: &["MQTT-2.1.4-1"],
    description: "Server MUST close connection on malformed remaining length",
    compliance: Compliance::Must,
};

/// A packet with a remaining-length field that uses more than 4 bytes
/// (continuation bit set on all 4 bytes) is malformed [MQTT-1.5.5-1].
async fn malformed_remaining_length(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = BAD_REMAINING_LEN;

    let mut client = RawClient::connect_tcp(config.addr).await?;

    // Send a CONNECT-like packet with a 5-byte remaining length (all continuation bits set).
    // This violates the VBI encoding limit of 4 bytes.
    #[rustfmt::skip]
    let bad_packet: &[u8] = &[
        0x10,                               // CONNECT fixed header
        0x80, 0x80, 0x80, 0x80, 0x01,       // malformed VBI: 5 continuation bytes
    ];
    client.send_raw(bad_packet).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const EMPTY_TOPIC_NO_ALIAS: TestContext = TestContext {
    refs: &["MQTT-3.3.2-1"],
    description: "PUBLISH with empty topic and no Topic Alias MUST be rejected",
    compliance: Compliance::Must,
};

/// A PUBLISH with an empty topic string and no Topic Alias property is
/// a protocol error [MQTT-3.3.2-8].
async fn publish_empty_topic_no_alias(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = EMPTY_TOPIC_NO_ALIAS;

    let params = ConnectParams::new("mqtt-test-empty-topic");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with zero-length topic, QoS 0, no topic alias.
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,               // PUBLISH | QoS=0 | RETAIN=0
        0x05,               // remaining length = 5
        0x00, 0x00,         // topic length = 0 (empty!)
        0x00,               // properties length = 0
        0x48, 0x49,         // payload "HI"
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const TOPIC_ALIAS_ZERO: TestContext = TestContext {
    refs: &["MQTT-3.3.2-2"],
    description: "PUBLISH with Topic Alias of 0 MUST be a protocol error",
    compliance: Compliance::Must,
};

/// A Topic Alias of 0 is not permitted — the server MUST disconnect [MQTT-3.3.2-8].
async fn publish_topic_alias_zero(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = TOPIC_ALIAS_ZERO;

    let params = ConnectParams::new("mqtt-test-alias-zero");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with Topic Alias property = 0 (protocol error).
    // Properties: 0x23 (Topic Alias ID), 0x00 0x00 (value = 0).
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,                                       // PUBLISH | QoS=0
        0x0C,                                       // remaining length = 12
        0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/"
        0x03,                                       // properties length = 3
        0x23, 0x00, 0x00,                           // Topic Alias = 0
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const SUB_NO_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.8.3-1"],
    description: "SUBSCRIBE with no topic filters MUST be rejected",
    compliance: Compliance::Must,
};

/// A SUBSCRIBE packet MUST contain at least one topic filter [MQTT-3.8.3-3].
/// The payload must be non-empty.
async fn subscribe_no_filters(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SUB_NO_FILTERS;

    let params = ConnectParams::new("mqtt-test-sub-empty");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with packet ID but zero topic filters.
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,               // SUBSCRIBE fixed header
        0x03,               // remaining length = 3
        0x00, 0x01,         // packet ID = 1
        0x00,               // properties length = 0
        // no topic filters follow — this is a protocol error
    ];
    client.send_raw(bad_subscribe).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const SUB_INVALID_QOS: TestContext = TestContext {
    refs: &["MQTT-3.8.3-2"],
    description: "SUBSCRIBE with reserved QoS bits set MUST be rejected",
    compliance: Compliance::Must,
};

/// The subscription options byte's upper 2 QoS bits (6-7) are reserved and
/// MUST be 0. Setting them is a protocol error [MQTT-3.8.3-5].
async fn subscribe_invalid_qos(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SUB_INVALID_QOS;

    let params = ConnectParams::new("mqtt-test-sub-bad-qos");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with one filter, but subscription options byte has reserved bits set.
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,                                               // SUBSCRIBE fixed header
        0x0C,                                               // remaining length = 12
        0x00, 0x01,                                         // packet ID = 1
        0x00,                                               // properties length = 0
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/"
        0xC0,                                               // options: reserved bits 6-7 set
    ];
    client.send_raw(bad_subscribe).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const INVALID_WILDCARD: TestContext = TestContext {
    refs: &["MQTT-4.7.1-1"],
    description: "'#' wildcard MUST only be the last character in a topic filter",
    compliance: Compliance::Must,
};

/// '#' wildcard not at the end of a topic filter is a protocol error [MQTT-4.7.1-1].
/// The server MUST treat a SUBSCRIBE with such a filter as a protocol error.
async fn subscribe_invalid_wildcard(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = INVALID_WILDCARD;

    let params = ConnectParams::new("mqtt-test-bad-wildcard");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with topic filter "mqtt/#/invalid" — '#' not at end.
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,                                                           // SUBSCRIBE fixed header
        0x15,                                                           // remaining length = 21
        0x00, 0x01,                                                     // packet ID = 1
        0x00,                                                           // properties length = 0
        0x00, 0x0E, b'm', b'q', b't', b't', b'/', b'#', b'/', b'i',   // topic "mqtt/#/i"
        b'n', b'v', b'a', b'l', b'i', b'd',                            // "nvalid"
        0x00,                                                           // subscription options: QoS 0
    ];
    client.send_raw(bad_subscribe).await?;

    // Server should either disconnect or return SUBACK with error reason code (0x80+).
    match client.recv(config.recv_timeout).await {
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::SubAck(ack)) => {
            if ack.reason_codes.iter().all(|&c| c >= 0x80) {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!("SUBACK accepted invalid wildcard filter: reason codes {:?}", ack.reason_codes),
                ))
            }
        }
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "disconnect or error SUBACK", &other)),
    }
    
}

const UNSUB_NO_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.10.3-1"],
    description: "UNSUBSCRIBE with no topic filters MUST be rejected",
    compliance: Compliance::Must,
};

/// An UNSUBSCRIBE packet MUST contain at least one topic filter [MQTT-3.10.3-2].
async fn unsubscribe_no_filters(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUB_NO_FILTERS;

    let params = ConnectParams::new("mqtt-test-unsub-empty");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // UNSUBSCRIBE with packet ID but zero topic filters.
    #[rustfmt::skip]
    let bad_unsubscribe: &[u8] = &[
        0xA2,               // UNSUBSCRIBE fixed header (0xA2 = type 10, reserved bits 0010)
        0x03,               // remaining length = 3
        0x00, 0x01,         // packet ID = 1
        0x00,               // properties length = 0
        // no topic filters follow — this is a protocol error
    ];
    client.send_raw(bad_unsubscribe).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const UNSUB_RESERVED_BITS: TestContext = TestContext {
    refs: &["MQTT-3.10.1-1"],
    description: "UNSUBSCRIBE fixed header reserved bits MUST be 0010",
    compliance: Compliance::Must,
};

/// The UNSUBSCRIBE fixed header byte must have bits 3-0 = 0010.
/// Sending wrong reserved bits is a malformed packet [MQTT-3.10.1-1].
async fn unsubscribe_reserved_bits(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUB_RESERVED_BITS;

    let params = ConnectParams::new("mqtt-test-unsub-reserved");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // UNSUBSCRIBE with reserved bits = 0000 instead of 0010.
    // Correct first byte is 0xA2 (1010_0010); we send 0xA0 (1010_0000).
    #[rustfmt::skip]
    let bad_unsubscribe: &[u8] = &[
        0xA0,                                               // UNSUBSCRIBE with wrong reserved bits
        0x0C,                                               // remaining length = 12
        0x00, 0x01,                                         // packet ID = 1
        0x00,                                               // properties length = 0
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/"
    ];
    client.send_raw(bad_unsubscribe).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const TOPIC_ALIAS_EXCEEDS_MAX: TestContext = TestContext {
    refs: &["MQTT-3.3.2-4"],
    description: "Topic Alias exceeding server's maximum MUST be a protocol error",
    compliance: Compliance::Must,
};

/// A Topic Alias value that exceeds the server's Topic Alias Maximum is a
/// protocol error — the server MUST disconnect [MQTT-3.3.2-9].
async fn topic_alias_exceeds_maximum(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = TOPIC_ALIAS_EXCEEDS_MAX;

    let params = ConnectParams::new("mqtt-test-alias-exceed");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let max_alias = connack.properties.topic_alias_maximum.unwrap_or(0);
    if max_alias == 0 {
        // Topic aliases not supported — send alias=1 which exceeds max of 0.
    }

    // Send a PUBLISH with Topic Alias = max + 1 (always exceeds the maximum).
    let bad_alias = max_alias.saturating_add(1);
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,                                       // PUBLISH | QoS=0
        0x0C,                                       // remaining length = 12
        0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/"
        0x03,                                       // properties length = 3
        0x23,                                       // Topic Alias property ID
        (bad_alias >> 8) as u8, (bad_alias & 0xFF) as u8,
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const INVALID_PLUS_WILDCARD: TestContext = TestContext {
    refs: &["MQTT-4.7.1-4"],
    description: "'+' wildcard MUST occupy an entire level of a topic filter",
    compliance: Compliance::Must,
};

/// '+' wildcard not occupying an entire topic level is a protocol error [MQTT-4.7.1-1].
/// E.g., "mqtt/te+st" is invalid.
async fn subscribe_invalid_plus_wildcard(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = INVALID_PLUS_WILDCARD;

    let params = ConnectParams::new("mqtt-test-bad-plus");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with topic filter "mqtt/te+st" — '+' not occupying entire level.
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,                                                       // SUBSCRIBE fixed header
        0x10,                                                       // remaining length = 16
        0x00, 0x01,                                                 // packet ID = 1
        0x00,                                                       // properties length = 0
        0x00, 0x0A, b'm', b'q', b't', b't', b'/', b't', b'e',     // topic "mqtt/te"
        b'+', b's', b't',                                           // "+st"
        0x00,                                                       // subscription options: QoS 0
    ];
    client.send_raw(bad_subscribe).await?;

    // Server should either disconnect or return SUBACK with error reason code (0x80+).
    match client.recv(config.recv_timeout).await {
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::SubAck(ack)) => {
            if ack.reason_codes.iter().all(|&c| c >= 0x80) {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!("SUBACK accepted invalid '+' wildcard filter: reason codes {:?}", ack.reason_codes),
                ))
            }
        }
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "disconnect or error SUBACK", &other)),
    }
    
}

const NULL_IN_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-2"],
    description: "PUBLISH with null character in topic name MUST be rejected",
    compliance: Compliance::Must,
};

/// A UTF-8 Encoded String MUST NOT include an encoding of the null character
/// U+0000 [MQTT-1.5.4-2]. A topic containing \0 is malformed.
async fn publish_topic_with_null_char(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = NULL_IN_TOPIC;

    let params = ConnectParams::new("mqtt-test-null-topic");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with topic "mqtt/\0test" — contains null character.
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,                                               // PUBLISH | QoS=0
        0x0F,                                               // remaining length = 15
        0x00, 0x0A,                                         // topic length = 10
        b'm', b'q', b't', b't', b'/', 0x00, b't', b'e',   // "mqtt/\0te"
        b's', b't',                                         // "st"
        0x00,                                               // properties length = 0
        0x48, 0x49,                                         // payload "HI"
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const SUB_WRONG_FIXED: TestContext = TestContext {
    refs: &["MQTT-3.8.1-1"],
    description: "SUBSCRIBE fixed header reserved bits MUST be 0010",
    compliance: Compliance::Must,
};

/// The SUBSCRIBE fixed header byte MUST have bits 3-0 set to 0010.
/// Sending 0x80 (bits = 0000) instead of 0x82 is malformed [MQTT-3.8.1-1].
async fn subscribe_wrong_fixed_header_bits(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SUB_WRONG_FIXED;

    let params = ConnectParams::new("mqtt-test-sub-fixed-bits");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with first byte 0x80 (reserved bits = 0000) instead of 0x82 (0010).
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x80,                                               // SUBSCRIBE with wrong reserved bits
        0x0C,                                               // remaining length = 12
        0x00, 0x01,                                         // packet ID = 1
        0x00,                                               // properties length = 0
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/"
        0x00,                                               // subscription options: QoS 0
    ];
    client.send_raw(bad_subscribe).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

// ── Username / Password ─────────────────────────────────────────────────────

const USERNAME_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.3-3"],
    description: "CONNECT with Username flag set but truncated payload MUST be rejected",
    compliance: Compliance::Must,
};

/// Username flag is set but the payload ends before the username field.
/// The broker MUST treat this as a malformed packet [MQTT-3.1.2-15].
async fn username_flag_truncated_payload(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = USERNAME_TRUNCATED;

    let mut client = RawClient::connect_tcp(config.addr).await?;

    // CONNECT with Username flag (0x82 = clean_start + username) but payload
    // contains only a client ID — no username bytes.
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x11,                                           // remaining length = 17
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x82,                                           // flags: clean_start=1, username=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const UTF8_SURROGATE: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject ill-formed UTF-8 (surrogate pairs D800-DFFF) in strings",
    compliance: Compliance::Must,
};

/// A UTF-8 Encoded String MUST NOT include encodings of UTF-16 surrogates
/// (U+D800..U+DFFF) [MQTT-1.5.4-1]. Send a PUBLISH with a topic containing
/// the ill-formed byte sequence 0xED 0xA0 0x80 (surrogate U+D800).
async fn utf8_surrogate_pair_in_topic(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UTF8_SURROGATE;

    let params = ConnectParams::new("mqtt-test-utf8-surrogate");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with topic "mqtt/\xED\xA0\x80" — contains surrogate U+D800.
    // Topic is 8 bytes: "mqtt/" (5) + 0xED 0xA0 0x80 (3).
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,                                               // PUBLISH | QoS=0
        0x0D,                                               // remaining length = 13
        0x00, 0x08,                                         // topic length = 8
        b'm', b'q', b't', b't', b'/',                      // "mqtt/"
        0xED, 0xA0, 0x80,                                   // ill-formed: surrogate U+D800
        0x00,                                               // properties length = 0
        0x48, 0x49,                                         // payload "HI"
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const PUBACK_BAD_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "Server MUST reject PUBACK with non-zero reserved fixed header flags",
    compliance: Compliance::Must,
};

/// The fixed header flags for PUBACK (packet type 4) MUST be 0000 [MQTT-2.1.3-1].
/// Sending 0x41 (flags = 0001) instead of 0x40 is a malformed packet.
async fn puback_invalid_fixed_header_flags(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = PUBACK_BAD_FLAGS;

    let params = ConnectParams::new("mqtt-test-puback-flags");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBACK with non-zero reserved flags: 0x41 instead of 0x40.
    // Packet ID = 1, reason code = 0x00 (Success).
    #[rustfmt::skip]
    let bad_puback: &[u8] = &[
        0x41,               // PUBACK with reserved bit 0 set (should be 0x40)
        0x02,               // remaining length = 2
        0x00, 0x01,         // packet ID = 1
    ];
    client.send_raw(bad_puback).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const WILL_QOS_THREE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-12"],
    description: "CONNECT with Will QoS=3 MUST be rejected as malformed",
    compliance: Compliance::Must,
};

/// If Will QoS bits are both set (value 3), the CONNECT is malformed [MQTT-3.1.2-12].
/// Connect flags byte: will_flag=1, will_qos=3, clean_start=1 → 0b_0001_1110 = 0x1E.
async fn will_qos_three(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILL_QOS_THREE;

    let mut client = RawClient::connect_tcp(config.addr).await?;

    // CONNECT with Will Flag=1, Will QoS=3 (both bits set), Clean Start=1.
    // Connect flags = 0x1E = 0b_0001_1110.
    // Payload: client ID "test", will properties (empty), will topic "w", will payload "x".
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT fixed header
        0x18,                                           // remaining length = 24
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x1E,                                           // flags: clean_start=1, will=1, will_qos=3
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // connect properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
        0x00,                                           // will properties length = 0
        0x00, 0x01, b'w',                               // will topic "w"
        0x00, 0x01, b'x',                               // will payload "x"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const DISCONNECT_BAD_RESERVED: TestContext = TestContext {
    refs: &["MQTT-3.14.0-1"],
    description: "DISCONNECT reserved bits MUST be zero; non-zero is malformed",
    compliance: Compliance::Must,
};

/// The DISCONNECT fixed header byte MUST have reserved bits 3-0 = 0000 [MQTT-3.14.0-1].
/// Sending 0xE1 (reserved bit 0 set) instead of 0xE0 is a malformed packet.
async fn disconnect_reserved_bits(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = DISCONNECT_BAD_RESERVED;

    let params = ConnectParams::new("mqtt-test-disc-reserved");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // DISCONNECT with non-zero reserved bits: 0xE1 instead of 0xE0.
    #[rustfmt::skip]
    let bad_disconnect: &[u8] = &[
        0xE1,               // DISCONNECT with reserved bit 0 set (should be 0xE0)
        0x00,               // remaining length = 0
    ];
    client.send_raw(bad_disconnect).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}

const PASSWORD_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.3-5a"],
    description: "CONNECT with Password flag set but truncated payload MUST be rejected",
    compliance: Compliance::Must,
};

/// Password flag is set (along with username flag) but the payload ends
/// after the username — no password bytes present.
async fn password_flag_truncated_payload(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = PASSWORD_TRUNCATED;

    let mut client = RawClient::connect_tcp(config.addr).await?;

    // CONNECT with Username + Password flags but only client ID + username in payload.
    // Remaining length claims 27 bytes but we only provide enough for client ID + username.
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x1B,                                           // remaining length = 27
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0xC2,                                           // flags: clean_start=1, username=1, password=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
        0x00, 0x08, b't', b'e', b's', b't',            // username "test" (but length says 8 — overshoots)
        b'u', b's', b'e', b'r',
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_disconnect(&mut client, config.recv_timeout, &ctx).await)
    
}
