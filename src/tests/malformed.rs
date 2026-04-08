//! Malformed packet handling compliance tests.
//!
//! The MQTT v5 spec requires the server to disconnect with reason code 0x81
//! (Malformed Packet) when it receives packets that violate protocol rules.
//! These tests send intentionally broken packets and verify the server
//! terminates the connection.

use anyhow::Result;

use crate::client::{self, RawClient, RecvError};
use crate::codec::{ConnectParams, Packet};
use crate::helpers::{expect_connect_reject, expect_disconnect};
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

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
    suite.add(
        INVALID_PLUS_WILDCARD,
        subscribe_invalid_plus_wildcard(config),
    );
    suite.add(NULL_IN_TOPIC, publish_topic_with_null_char(config));
    suite.add(SUB_WRONG_FIXED, subscribe_wrong_fixed_header_bits(config));
    suite.add(NO_CLIENT_ID, connect_missing_client_id(config));
    suite.add(USERNAME_TRUNCATED, username_flag_truncated_payload(config));
    suite.add(PASSWORD_TRUNCATED, password_flag_truncated_payload(config));
    suite.add(WILL_TRUNCATED, will_flag_truncated_payload(config));
    suite.add(
        USERNAME_FLAG_MISMATCH,
        username_flag_clear_but_data_present(config),
    );
    suite.add(
        PASSWORD_FLAG_MISMATCH,
        password_flag_clear_but_data_present(config),
    );
    suite.add(WILL_TOPIC_BAD_UTF8, will_topic_invalid_utf8(config));
    suite.add(USERNAME_BAD_UTF8, username_invalid_utf8(config));
    suite.add(USER_PROP_BAD_UTF8, user_property_invalid_utf8(config));
    suite.add(UTF8_SURROGATE, utf8_surrogate_pair_in_topic(config));
    suite.add(PUBACK_BAD_FLAGS, puback_invalid_fixed_header_flags(config));
    suite.add(WILL_QOS_THREE, will_qos_three(config));
    suite.add(DISCONNECT_BAD_RESERVED, disconnect_reserved_bits(config));

    suite
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-3.1.4-1", "MQTT-3.1.2-3"],
    description: "Server MUST validate that the CONNECT packet matches the format described in section 3.1 and close the Network Connection if it does not match",
    compliance: Compliance::Must,
};

/// The CONNECT packet's connect-flags byte has a reserved bit (bit 0) that
/// The Server MUST validate that the CONNECT packet matches the format described in section 3.1 and close the Network Connection if it does not match. [MQTT-3.1.4-1].
async fn reserved_connect_flags(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

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

    Ok(expect_connect_reject(&mut client).await)
}

const BAD_REMAINING_LEN: TestContext = TestContext {
    refs: &["MQTT-1.5.5-1"],
    description: "encoded value MUST use the minimum number of bytes necessary to represent the value",
    compliance: Compliance::Must,
};

/// A packet with a remaining-length field that uses more than 4 bytes
/// The encoded value MUST use the minimum number of bytes necessary to represent the value. [MQTT-1.5.5-1].
async fn malformed_remaining_length(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Send a CONNECT-like packet with a 5-byte remaining length (all continuation bits set).
    // This violates the VBI encoding limit of 4 bytes.
    #[rustfmt::skip]
    let bad_packet: &[u8] = &[
        0x10,                               // CONNECT fixed header
        0x80, 0x80, 0x80, 0x80, 0x01,       // malformed VBI: 5 continuation bytes
    ];
    client.send_raw(bad_packet).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const EMPTY_TOPIC_NO_ALIAS: TestContext = TestContext {
    refs: &["MQTT-3.3.2-1"],
    description: "Topic Name MUST be present as the first field in the PUBLISH packet Variable Header",
    compliance: Compliance::Must,
};

/// A PUBLISH with an empty topic string and no Topic Alias property is
/// The Topic Name MUST be present as the first field in the PUBLISH packet Variable Header. It MUST be a UTF-8 Encoded String. [MQTT-3.3.2-1].
async fn publish_empty_topic_no_alias(config: TestConfig<'_>) -> Result<Outcome> {
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

    Ok(expect_disconnect(&mut client).await)
}

const TOPIC_ALIAS_ZERO: TestContext = TestContext {
    refs: &["MQTT-3.3.2-2"],
    description: "Topic Name in the PUBLISH packet MUST NOT contain wildcard characters",
    compliance: Compliance::Must,
};

/// The Topic Name in the PUBLISH packet MUST NOT contain wildcard characters. [MQTT-3.3.2-2].
async fn publish_topic_alias_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-alias-zero");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with Topic Alias property = 0 (protocol error).
    // Properties: 0x23 (Topic Alias ID), 0x00 0x00 (value = 0).
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,                                       // PUBLISH | QoS=0
        0x0B,                                       // remaining length = 11
        0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/" (7)
        0x03,                                       // properties length = 3 (1)
        0x23, 0x00, 0x00,                           // Topic Alias = 0 (3)
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client).await)
}

const SUB_NO_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.8.3-1"],
    description: "Topic Filters MUST be a UTF-8 Encoded String",
    compliance: Compliance::Must,
};

/// The Topic Filters MUST be a UTF-8 Encoded String. [MQTT-3.8.3-1].
/// The payload must be non-empty.
async fn subscribe_no_filters(config: TestConfig<'_>) -> Result<Outcome> {
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

    Ok(expect_disconnect(&mut client).await)
}

const SUB_INVALID_QOS: TestContext = TestContext {
    refs: &["MQTT-3.8.3-2"],
    description: "Payload MUST contain at least one Topic Filter and Subscription Options pair",
    compliance: Compliance::Must,
};

/// The subscription options byte's upper 2 QoS bits (6-7) are reserved and
/// The Payload MUST contain at least one Topic Filter and Subscription Options pair. [MQTT-3.8.3-2].
async fn subscribe_invalid_qos(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-sub-bad-qos");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with one filter, but subscription options byte has reserved bits set.
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,                                               // SUBSCRIBE fixed header
        0x0B,                                               // remaining length = 11
        0x00, 0x01,                                         // packet ID = 1 (2)
        0x00,                                               // properties length = 0 (1)
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/" (7)
        0xC0,                                               // options: reserved bits 6-7 set (1)
    ];
    client.send_raw(bad_subscribe).await?;

    Ok(expect_disconnect(&mut client).await)
}

const INVALID_WILDCARD: TestContext = TestContext {
    refs: &["MQTT-4.7.1-1"],
    description: "multi-level wildcard character MUST be specified either on its own or following a topic level separator",
    compliance: Compliance::Must,
};

/// The multi-level wildcard character MUST be specified either on its own or following a topic level separator. In either case it MUST be the last character specified in the Topic Filter. [MQTT-4.7.1-1].
/// The server MUST treat a SUBSCRIBE with such a filter as a protocol error.
async fn subscribe_invalid_wildcard(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-bad-wildcard");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with topic filter "mqtt/#/invalid" — '#' not at end.
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,                                                           // SUBSCRIBE fixed header
        0x14,                                                           // remaining length = 20
        0x00, 0x01,                                                     // packet ID = 1 (2)
        0x00,                                                           // properties length = 0 (1)
        0x00, 0x0E, b'm', b'q', b't', b't', b'/', b'#', b'/', b'i',   // topic "mqtt/#/i" (10)
        b'n', b'v', b'a', b'l', b'i', b'd',                            // "nvalid" (6)
        0x00,                                                           // subscription options: QoS 0 (1)
    ];
    client.send_raw(bad_subscribe).await?;

    // Server should either disconnect or return SUBACK with error reason code (0x80+).
    match client.recv().await {
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::SubAck(ack)) => {
            if ack.reason_codes.iter().all(|&c| c >= 0x80) {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "SUBACK accepted invalid wildcard filter: reason codes {:?}",
                    ack.reason_codes
                )))
            }
        }
        Ok(other) => Ok(Outcome::fail_packet("disconnect or error SUBACK", &other)),
    }
}

const UNSUB_NO_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.10.3-1", "MQTT-3.10.3-2"],
    description: "Topic Filters in an UNSUBSCRIBE packet MUST be UTF-8 Encoded Strings",
    compliance: Compliance::Must,
};

/// The Topic Filters in an UNSUBSCRIBE packet MUST be UTF-8 Encoded Strings. [MQTT-3.10.3-1].
async fn unsubscribe_no_filters(config: TestConfig<'_>) -> Result<Outcome> {
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

    Ok(expect_disconnect(&mut client).await)
}

const UNSUB_RESERVED_BITS: TestContext = TestContext {
    refs: &["MQTT-3.10.1-1"],
    description: "Bits 3,2,1 and 0 of the Fixed Header of the UNSUBSCRIBE packet are reserved and MUST be set to 0,0,1 and 0 respectively",
    compliance: Compliance::Must,
};

/// The UNSUBSCRIBE fixed header byte must have bits 3-0 = 0010.
/// Bits 3,2,1 and 0 of the Fixed Header of the UNSUBSCRIBE packet are reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.10.1-1].
async fn unsubscribe_reserved_bits(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-unsub-reserved");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // UNSUBSCRIBE with reserved bits = 0000 instead of 0010.
    // Correct first byte is 0xA2 (1010_0010); we send 0xA0 (1010_0000).
    #[rustfmt::skip]
    let bad_unsubscribe: &[u8] = &[
        0xA0,                                               // UNSUBSCRIBE with wrong reserved bits
        0x0A,                                               // remaining length = 10
        0x00, 0x01,                                         // packet ID = 1 (2)
        0x00,                                               // properties length = 0 (1)
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/" (7)
    ];
    client.send_raw(bad_unsubscribe).await?;

    Ok(expect_disconnect(&mut client).await)
}

const TOPIC_ALIAS_EXCEEDS_MAX: TestContext = TestContext {
    refs: &["MQTT-3.3.2-4"],
    description: "A Server MUST send the Payload Format Indicator unaltered to all subscribers receiving the message",
    compliance: Compliance::Must,
};

/// A Topic Alias value that exceeds the server's Topic Alias Maximum is a
/// A Server MUST send the Payload Format Indicator unaltered to all subscribers receiving the message. [MQTT-3.3.2-4].
async fn topic_alias_exceeds_maximum(config: TestConfig<'_>) -> Result<Outcome> {
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
        0x0B,                                       // remaining length = 11
        0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/" (7)
        0x03,                                       // properties length = 3 (1)
        0x23,                                       // Topic Alias property ID (1)
        (bad_alias >> 8) as u8, (bad_alias & 0xFF) as u8, // (2)
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client).await)
}

const INVALID_PLUS_WILDCARD: TestContext = TestContext {
    refs: &["MQTT-4.7.1-2"],
    description: "single-level wildcard can be used at any level in the Topic Filter, including first and last levels",
    compliance: Compliance::Must,
};

/// The single-level wildcard can be used at any level in the Topic Filter, including first and last levels. Where it is used, it MUST occupy an entire level of the filter. [MQTT-4.7.1-2].
/// E.g., "mqtt/te+st" is invalid.
async fn subscribe_invalid_plus_wildcard(config: TestConfig<'_>) -> Result<Outcome> {
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
    match client.recv().await {
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::SubAck(ack)) => {
            if ack.reason_codes.iter().all(|&c| c >= 0x80) {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "SUBACK accepted invalid '+' wildcard filter: reason codes {:?}",
                    ack.reason_codes
                )))
            }
        }
        Ok(other) => Ok(Outcome::fail_packet("disconnect or error SUBACK", &other)),
    }
}

const NULL_IN_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-2"],
    description: "A UTF-8 Encoded String MUST NOT include an encoding of the null character U+0000",
    compliance: Compliance::Must,
};

/// A UTF-8 Encoded String MUST NOT include an encoding of the null character
/// A UTF-8 Encoded String MUST NOT include an encoding of the null character U+0000. [MQTT-1.5.4-2].
async fn publish_topic_with_null_char(config: TestConfig<'_>) -> Result<Outcome> {
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

    Ok(expect_disconnect(&mut client).await)
}

const SUB_WRONG_FIXED: TestContext = TestContext {
    refs: &["MQTT-3.8.1-1"],
    description: "Bits 3,2,1 and 0 of the Fixed Header of the SUBSCRIBE packet are reserved and MUST be set to 0,0,1 and 0 respectively",
    compliance: Compliance::Must,
};

/// The SUBSCRIBE fixed header byte MUST have bits 3-0 set to 0010.
/// Bits 3,2,1 and 0 of the Fixed Header of the SUBSCRIBE packet are reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any other value as malformed and close the Network Connection [MQTT-3.8.1-1].
async fn subscribe_wrong_fixed_header_bits(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-sub-fixed-bits");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with first byte 0x80 (reserved bits = 0000) instead of 0x82 (0010).
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x80,                                               // SUBSCRIBE with wrong reserved bits
        0x0B,                                               // remaining length = 11
        0x00, 0x01,                                         // packet ID = 1 (2)
        0x00,                                               // properties length = 0 (1)
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/" (7)
        0x00,                                               // subscription options: QoS 0 (1)
    ];
    client.send_raw(bad_subscribe).await?;

    Ok(expect_disconnect(&mut client).await)
}

// ── Client ID ───────────────────────────────────────────────────────────────

const NO_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.1.3-3"],
    description: "ClientID MUST be present and is the first field in the CONNECT packet Payload",
    compliance: Compliance::Must,
};

/// The Client Identifier MUST be present and is the first field in the
/// The ClientID MUST be present and is the first field in the CONNECT packet Payload. [MQTT-3.1.3-3].
/// (remaining length only covers the variable header) is malformed.
async fn connect_missing_client_id(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with an empty payload — no client ID at all.
    // Remaining length = 11 covers only the variable header.
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x0B,                                           // remaining length = 11
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x02,                                           // flags: clean_start=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        // no payload — client ID missing
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

// ── Username / Password ─────────────────────────────────────────────────────

const USERNAME_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-17"],
    description: "If the User Name Flag is set to 1, a User Name MUST be present in the Payload",
    compliance: Compliance::Must,
};

/// Username flag is set but the payload ends before the username field.
/// If the User Name Flag is set to 1, a User Name MUST be present in the Payload. [MQTT-3.1.2-17].
async fn username_flag_truncated_payload(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

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

    Ok(expect_connect_reject(&mut client).await)
}

const UTF8_SURROGATE: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode specification [Unicode] and restated in RFC 3629 [RFC3629]",
    compliance: Compliance::Must,
};

/// A UTF-8 Encoded String MUST NOT include encodings of UTF-16 surrogates
/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1].
/// the ill-formed byte sequence 0xED 0xA0 0x80 (surrogate U+D800).
async fn utf8_surrogate_pair_in_topic(config: TestConfig<'_>) -> Result<Outcome> {
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

    Ok(expect_disconnect(&mut client).await)
}

const PUBACK_BAD_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "Where a flag bit is marked as �Reserved� it is reserved for future use and MUST be set to the value listed",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as �Reserved� it is reserved for future use and MUST be set to the value listed. [MQTT-2.1.3-1].
/// Sending 0x41 (flags = 0001) instead of 0x40 is a malformed packet.
async fn puback_invalid_fixed_header_flags(config: TestConfig<'_>) -> Result<Outcome> {
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

    Ok(expect_disconnect(&mut client).await)
}

const WILL_QOS_THREE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-12"],
    description: "If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00), 1 (0x01), or 2 (0x02)",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00), 1 (0x01), or 2 (0x02). [MQTT-3.1.2-12].
/// Connect flags byte: will_flag=1, will_qos=3, clean_start=1 → 0b_0001_1110 = 0x1E.
async fn will_qos_three(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

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

    Ok(expect_connect_reject(&mut client).await)
}

const DISCONNECT_BAD_RESERVED: TestContext = TestContext {
    refs: &["MQTT-3.14.0-1"],
    description: "A Server MUST NOT send a DISCONNECT until after it has sent a CONNACK with Reason Code of less than 0x80",
    compliance: Compliance::Must,
};

/// A Server MUST NOT send a DISCONNECT until after it has sent a CONNACK with Reason Code of less than 0x80. [MQTT-3.14.0-1].
/// Sending 0xE1 (reserved bit 0 set) instead of 0xE0 is a malformed packet.
async fn disconnect_reserved_bits(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-disc-reserved");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // DISCONNECT with non-zero reserved bits: 0xE1 instead of 0xE0.
    #[rustfmt::skip]
    let bad_disconnect: &[u8] = &[
        0xE1,               // DISCONNECT with reserved bit 0 set (should be 0xE0)
        0x00,               // remaining length = 0
    ];
    client.send_raw(bad_disconnect).await?;

    Ok(expect_disconnect(&mut client).await)
}

const PASSWORD_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-19"],
    description: "If the Password Flag is set to 1, a Password MUST be present in the Payload",
    compliance: Compliance::Must,
};

/// Password flag is set (along with username flag) but the payload ends
/// after the username — no password bytes present.
async fn password_flag_truncated_payload(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

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

    Ok(expect_connect_reject(&mut client).await)
}

// ── Structural (flag/payload mismatch) ──────────────────────────────────────

const WILL_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-9"],
    description: "If the Will Flag is set to 1, the Will QoS and Will Retain fields in the Connect Flags will be used by server",
    compliance: Compliance::Must,
};

/// Will Flag is set but the payload contains only the client ID — no will
/// properties, will topic, or will payload. The broker MUST reject this as
/// If the Will Flag is set to 1, the Will QoS and Will Retain fields in the Connect Flags will be used by the Server, and the Will Properties, Will Topic and Will Message fields MUST be present in the Payload. [MQTT-3.1.2-9].
async fn will_flag_truncated_payload(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with Will Flag=1, Clean Start=1, but payload ends after client ID.
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x11,                                           // remaining length = 17
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x06,                                           // flags: clean_start=1, will=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
        // will properties, will topic, will payload MISSING
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const USERNAME_FLAG_MISMATCH: TestContext = TestContext {
    refs: &["MQTT-3.1.2-16"],
    description: "If the User Name Flag is set to 0, a User Name MUST NOT be present in the Payload",
    compliance: Compliance::Must,
};

/// Username Flag is 0 but the remaining length includes extra bytes beyond the
/// client ID. The server should detect unconsumed payload bytes and reject the
/// If the User Name Flag is set to 0, a User Name MUST NOT be present in the Payload. [MQTT-3.1.2-16].
async fn username_flag_clear_but_data_present(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with Username Flag=0 but remaining length includes 6 extra bytes
    // after the client ID (looks like a username "user" but flag says none).
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x17,                                           // remaining length = 23
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x02,                                           // flags: clean_start=1 (username=0)
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
        0x00, 0x04, b'u', b's', b'e', b'r',            // extra data not indicated by flags
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const PASSWORD_FLAG_MISMATCH: TestContext = TestContext {
    refs: &["MQTT-3.1.2-18"],
    description: "If the Password Flag is set to 0, a Password MUST NOT be present in the Payload",
    compliance: Compliance::Must,
};

/// Password Flag is 0 but the remaining length includes extra bytes after the
/// username. The server should detect unconsumed payload bytes and reject the
/// If the Password Flag is set to 0, a Password MUST NOT be present in the Payload. [MQTT-3.1.2-18].
async fn password_flag_clear_but_data_present(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with Username Flag=1, Password Flag=0 but remaining length
    // includes 6 extra bytes after username (looks like password "pass").
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x1D,                                           // remaining length = 29
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x82,                                           // flags: clean_start=1, username=1 (password=0)
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
        0x00, 0x04, b'u', b's', b'e', b'r',            // username "user"
        0x00, 0x04, b'p', b'a', b's', b's',            // extra data not indicated by flags
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

// ── Structural (invalid UTF-8 in CONNECT fields) ───────────────────────────

const WILL_TOPIC_BAD_UTF8: TestContext = TestContext {
    refs: &["MQTT-3.1.3-11"],
    description: "Will Topic MUST be a UTF-8 Encoded String",
    compliance: Compliance::Must,
};

/// The Will Topic MUST be a UTF-8 Encoded String. [MQTT-3.1.3-11].
/// containing a UTF-16 surrogate (U+D800) is ill-formed and MUST be rejected.
async fn will_topic_invalid_utf8(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with Will Flag=1, will topic contains surrogate U+D800 (0xED 0xA0 0x80).
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x1A,                                           // remaining length = 26
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x06,                                           // flags: clean_start=1, will=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // connect properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
        0x00,                                           // will properties length = 0
        0x00, 0x03, 0xED, 0xA0, 0x80,                  // will topic: surrogate U+D800
        0x00, 0x01, b'x',                              // will payload "x"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const USERNAME_BAD_UTF8: TestContext = TestContext {
    refs: &["MQTT-3.1.3-12"],
    description: "If the User Name Flag is set to 1, the User Name is the next field in the Payload",
    compliance: Compliance::Must,
};

/// If the User Name Flag is set to 1, the User Name is the next field in the Payload. The User Name MUST be a UTF-8 Encoded String. [MQTT-3.1.3-12].
/// containing a UTF-16 surrogate (U+D800) is ill-formed and MUST be rejected.
async fn username_invalid_utf8(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with Username Flag=1, username contains surrogate U+D800.
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x16,                                           // remaining length = 22
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x82,                                           // flags: clean_start=1, username=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
        0x00, 0x03, 0xED, 0xA0, 0x80,                  // username: surrogate U+D800
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const USER_PROP_BAD_UTF8: TestContext = TestContext {
    refs: &["MQTT-1.5.7-1"],
    description: "Both strings MUST comply with the requirements for UTF-8 Encoded Strings",
    compliance: Compliance::Must,
};

/// Both strings MUST comply with the requirements for UTF-8 Encoded Strings. [MQTT-1.5.7-1].
/// Send a CONNECT with a User Property whose key contains surrogate U+D800.
async fn user_property_invalid_utf8(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with a User Property (0x26) whose key is ill-formed UTF-8.
    // Property: 0x26, key_len=3 (surrogate), value_len=1 ("v").
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT
        0x1A,                                           // remaining length = 26
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x02,                                           // flags: clean_start=1
        0x00, 0x3C,                                     // keep alive = 60
        0x09,                                           // properties length = 9
        0x26,                                           // User Property ID
        0x00, 0x03, 0xED, 0xA0, 0x80,                  // key: surrogate U+D800
        0x00, 0x01, b'v',                              // value: "v"
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}
