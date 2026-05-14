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

    // MQTT-2.1.3-1 — fixed header reserved bits
    suite.add(CONNECT_RESERVED_FLAGS, connect_reserved_flags(config));
    suite.add(PUBACK_RESERVED_FLAGS, puback_reserved_flags(config));
    suite.add(PUBREC_RESERVED_FLAGS, pubrec_reserved_flags(config));
    suite.add(PUBREL_RESERVED_FLAGS, pubrel_reserved_flags(config));
    suite.add(PUBCOMP_RESERVED_FLAGS, pubcomp_reserved_flags(config));
    suite.add(SUBSCRIBE_RESERVED_FLAGS, subscribe_reserved_flags(config));
    suite.add(
        UNSUBSCRIBE_RESERVED_FLAGS,
        unsubscribe_reserved_flags(config),
    );
    suite.add(PINGREQ_RESERVED_FLAGS, pingreq_reserved_flags(config));
    suite.add(DISCONNECT_RESERVED_FLAGS, disconnect_reserved_flags(config));
    suite.add(AUTH_RESERVED_FLAGS, auth_reserved_flags(config));

    // MQTT-2.2.1-2 — Packet Identifier in QoS 0 PUBLISH
    suite.add(
        PUBLISH_QOS0_PACKET_ID,
        publish_qos0_with_packet_identifier(config),
    );

    // MQTT-2.2.1-3 — zero Packet Identifier violations
    suite.add(PUBLISH_PACKET_ID_ZERO, publish_qos1_packet_id_zero(config));
    suite.add(SUBSCRIBE_PACKET_ID_ZERO, subscribe_packet_id_zero(config));
    suite.add(
        UNSUBSCRIBE_PACKET_ID_ZERO,
        unsubscribe_packet_id_zero(config),
    );

    // MQTT-3.1.2-3 — Connect Flags reserved bit MUST be 0
    suite.add(CONNECT_FLAGS_RESERVED, connect_flags_reserved_bit(config));

    // MQTT-3.1.2-9 — Will Flag=1 requires Will Properties, Will Topic, and Will Payload
    suite.add(WILL_TRUNCATED, will_flag_truncated_payload(config));

    // MQTT-3.1.2-11 — Will Flag=0 forces Will QoS=0
    suite.add(WILL_FLAG0_QOS_NONZERO, will_flag_zero_qos_nonzero(config));

    // MQTT-3.1.2-12 — Will Flag=1 forbids Will QoS=3
    suite.add(WILL_QOS_THREE, will_qos_three(config));

    // MQTT-3.1.2-13 — Will Flag=0 forces Will Retain=0
    suite.add(WILL_FLAG0_RETAIN_SET, will_flag_zero_retain_set(config));

    // MQTT-3.1.2-16 — User Name Flag=0 forbids a User Name in the Payload
    suite.add(
        USERNAME_FLAG_MISMATCH,
        username_flag_clear_but_data_present(config),
    );

    // MQTT-3.1.2-17 — User Name Flag=1 requires a User Name in the Payload
    suite.add(USERNAME_TRUNCATED, username_flag_truncated_payload(config));

    // MQTT-3.1.2-18 — Password Flag=0 forbids a Password in the Payload
    suite.add(
        PASSWORD_FLAG_MISMATCH,
        password_flag_clear_but_data_present(config),
    );

    // MQTT-3.1.2-19 — Password Flag=1 requires a Password in the Payload
    suite.add(PASSWORD_TRUNCATED, password_flag_truncated_payload(config));

    // MQTT-3.1.3-3 — ClientID MUST be present in the CONNECT Payload
    suite.add(NO_CLIENT_ID, connect_missing_client_id(config));

    // ── reviewed up to here ─────────────────────────────────────────────────

    // MQTT-3.3 — PUBLISH validation
    suite.add(EMPTY_TOPIC_NO_ALIAS, publish_empty_topic_no_alias(config));
    suite.add(TOPIC_ALIAS_ZERO, publish_topic_alias_zero(config));
    suite.add(TOPIC_ALIAS_EXCEEDS_MAX, topic_alias_exceeds_maximum(config));

    // MQTT-3.8 — SUBSCRIBE validation
    suite.add(SUB_NO_FILTERS, subscribe_no_filters(config));
    suite.add(SUB_INVALID_QOS, subscribe_invalid_qos(config));
    suite.add(INVALID_WILDCARD, subscribe_invalid_wildcard(config));
    suite.add(
        INVALID_PLUS_WILDCARD,
        subscribe_invalid_plus_wildcard(config),
    );

    // MQTT-3.10 — UNSUBSCRIBE validation
    suite.add(UNSUB_NO_FILTERS, unsubscribe_no_filters(config));

    suite
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Send a post-connection control packet with invalid fixed header flags, then expect disconnect.
///
/// Constructs a minimal packet with the given `bad_first_byte` and `body`. The caller must
/// first establish a connection; this helper is for packet types sent after CONNECT (PUBACK,
/// PUBREC, PUBREL, PUBCOMP, PINGREQ, DISCONNECT, etc.).
async fn bad_fixed_header_flags(
    config: TestConfig<'_>,
    client_id: &str,
    bad_first_byte: u8,
    body: &[u8],
) -> Result<Outcome> {
    let params = ConnectParams::new(client_id);
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let mut packet = Vec::with_capacity(2 + body.len());
    packet.push(bad_first_byte);
    packet.push(body.len() as u8);
    packet.extend_from_slice(body);

    client.send_raw(&packet).await?;
    Ok(expect_disconnect(&mut client).await)
}

// ── MQTT-2.1.3-1: Fixed header reserved bits ────────────────────────────────

const CONNECT_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "CONNECT fixed header reserved bits MUST be 0000",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// This test sends a CONNECT with non-zero fixed header reserved flags (0x11 instead of 0x10).
/// CONNECT fixed header bits 3-0 must be 0000. Note: this is the fixed header byte, not the
/// Connect Flags byte (which is tested separately under MQTT-3.1.2-3).
async fn connect_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT 0x11 (bit 0 set, should be 0x10), otherwise valid CONNECT packet.
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x11,                                           // CONNECT with bad fixed header flags
        0x11,                                           // remaining length = 17
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x02,                                           // connect flags: Clean Start=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const PUBACK_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "PUBACK fixed header reserved bits MUST be 0000",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// This test sends a PUBACK with non-zero reserved flags (0x41 instead of 0x40). PUBACK fixed
/// header bits 3-0 must be 0000.
async fn puback_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    // PUBACK 0x41 (bit 0 set, should be 0x40), packet ID = 1.
    bad_fixed_header_flags(config, "mqtt-test-puback-flags", 0x41, &[0x00, 0x01]).await
}

const PUBREC_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "PUBREC fixed header reserved bits MUST be 0000",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// This test sends a PUBREC with non-zero reserved flags (0x51 instead of 0x50). PUBREC fixed
/// header bits 3-0 must be 0000.
async fn pubrec_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    // PUBREC 0x51 (bit 0 set, should be 0x50), packet ID = 1.
    bad_fixed_header_flags(config, "mqtt-test-pubrec-flags", 0x51, &[0x00, 0x01]).await
}

const PUBREL_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1", "MQTT-3.6.1-1"],
    description: "PUBREL fixed header reserved bits MUST be 0010",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// Bits 3,2,1 and 0 of the Fixed Header of the PUBREL packet are reserved and MUST be set to
/// 0,0,1,0 respectively. The Server MUST treat any other value as malformed and close the Network
/// Connection. [MQTT-3.6.1-1]
///
/// This test sends a PUBREL with reserved bits 0000 (0x60 instead of 0x62). PUBREL fixed header
/// bits 3-0 must be 0010.
async fn pubrel_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    // PUBREL 0x60 (bits 0000, should be 0x62 = 0010), packet ID = 1.
    bad_fixed_header_flags(config, "mqtt-test-pubrel-flags", 0x60, &[0x00, 0x01]).await
}

const PUBCOMP_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "PUBCOMP fixed header reserved bits MUST be 0000",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// This test sends a PUBCOMP with non-zero reserved flags (0x71 instead of 0x70). PUBCOMP fixed
/// header bits 3-0 must be 0000.
async fn pubcomp_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    // PUBCOMP 0x71 (bit 0 set, should be 0x70), packet ID = 1.
    bad_fixed_header_flags(config, "mqtt-test-pubcomp-flags", 0x71, &[0x00, 0x01]).await
}

const SUBSCRIBE_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1", "MQTT-3.8.1-1"],
    description: "SUBSCRIBE fixed header reserved bits MUST be 0010",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// Bits 3,2,1 and 0 of the Fixed Header of the SUBSCRIBE packet are reserved and MUST be set to
/// 0,0,1 and 0 respectively. The Server MUST treat any other value as malformed and close the
/// Network Connection. [MQTT-3.8.1-1]
///
/// This test sends a SUBSCRIBE with first byte 0x80 (reserved bits 0000) instead of 0x82 (0010).
async fn subscribe_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-sub-reserved");
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

const UNSUBSCRIBE_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1", "MQTT-3.10.1-1"],
    description: "UNSUBSCRIBE fixed header reserved bits MUST be 0010",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// Bits 3,2,1 and 0 of the Fixed Header of the UNSUBSCRIBE packet are reserved and MUST be set to
/// 0,0,1 and 0 respectively. The Server MUST treat any other value as malformed and close the
/// Network Connection. [MQTT-3.10.1-1]
///
/// This test sends an UNSUBSCRIBE with reserved bits 0000 instead of 0010 (0xA0 instead of 0xA2).
async fn unsubscribe_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
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

const PINGREQ_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "PINGREQ fixed header reserved bits MUST be 0000",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// This test sends a PINGREQ with non-zero reserved flags (0xC1 instead of 0xC0). PINGREQ fixed
/// header bits 3-0 must be 0000 and remaining length must be 0.
async fn pingreq_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    // PINGREQ 0xC1 (bit 0 set, should be 0xC0), empty body.
    bad_fixed_header_flags(config, "mqtt-test-ping-flags", 0xC1, &[]).await
}

const DISCONNECT_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1", "MQTT-3.14.1-1"],
    description: "DISCONNECT fixed header reserved bits MUST be 0000",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// The Client or Server MUST validate that reserved bits are set to 0. If they are not zero it
/// sends a DISCONNECT packet with a Reason code of 0x81 (Malformed Packet). [MQTT-3.14.1-1]
///
/// This test sends a DISCONNECT with reserved bit 0 set (0xE1 instead of 0xE0).
async fn disconnect_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    // DISCONNECT 0xE1 (bit 0 set, should be 0xE0), empty body.
    bad_fixed_header_flags(config, "mqtt-test-disc-reserved", 0xE1, &[]).await
}

const AUTH_RESERVED_FLAGS: TestContext = TestContext {
    refs: &["MQTT-2.1.3-1"],
    description: "AUTH fixed header reserved bits MUST be 0000",
    compliance: Compliance::Must,
};

/// Where a flag bit is marked as "Reserved", it is reserved for future use and MUST be set to the
/// value listed. [MQTT-2.1.3-1]
///
/// This test sends an AUTH with non-zero reserved flags (0xF1 instead of 0xF0). AUTH fixed header
/// bits 3-0 must be 0000.
async fn auth_reserved_flags(config: TestConfig<'_>) -> Result<Outcome> {
    // AUTH 0xF1 (bit 0 set, should be 0xF0), empty body.
    bad_fixed_header_flags(config, "mqtt-test-auth-flags", 0xF1, &[]).await
}

// ── MQTT-2.2.1-2: Packet Identifier in QoS 0 PUBLISH ────────────────────────

const PUBLISH_QOS0_PACKET_ID: TestContext = TestContext {
    refs: &["MQTT-2.2.1-2"],
    description: "PUBLISH QoS 0 MUST NOT contain a Packet Identifier",
    compliance: Compliance::Must,
};

/// A PUBLISH packet MUST NOT contain a Packet Identifier if its QoS value is set to 0.
/// [MQTT-2.2.1-2]
///
/// This test sends a QoS 0 PUBLISH that includes a 2-byte Packet Identifier between the topic
/// and properties, which is only valid for QoS 1 and QoS 2. The broker should treat this as a
/// Malformed Packet and disconnect.
async fn publish_qos0_with_packet_identifier(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-qos0-pktid");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with QoS 0 (fixed header 0x30) but with a Packet Identifier inserted.
    // Normal QoS 0 PUBLISH: topic_len(2) + topic + props_len + payload
    // Malformed:             topic_len(2) + topic + packet_id(2) + props_len + payload
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,                                               // PUBLISH, QoS 0, no DUP/RETAIN
        0x0E,                                               // remaining length = 14
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic "mqtt/" (7)
        0x00, 0x01,                                         // Packet Identifier = 1 (ILLEGAL for QoS 0)
        0x00,                                               // properties length = 0
        b't', b'e', b's', b't',                             // payload "test" (4)
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client).await)
}

// ── MQTT-2.2.1-3: Zero Packet Identifier ─────────────────────────────────────

const PUBLISH_PACKET_ID_ZERO: TestContext = TestContext {
    refs: &["MQTT-2.2.1-3"],
    description: "PUBLISH QoS 1 with Packet Identifier 0 MUST be rejected",
    compliance: Compliance::Must,
};

/// Each time a Client sends a new SUBSCRIBE, UNSUBSCRIBE, or PUBLISH (where QoS > 0) MQTT
/// Control Packet it MUST assign it a non-zero Packet Identifier that is currently unused.
/// [MQTT-2.2.1-3]
///
/// This test sends a QoS 1 PUBLISH with Packet Identifier set to 0. The broker should treat
/// this as a Protocol Error and disconnect.
async fn publish_qos1_packet_id_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-pub-pid0");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH QoS 1 (fixed header 0x32) with Packet Identifier = 0.
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x32,                                               // PUBLISH, QoS 1
        0x0E,                                               // remaining length = 14
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic "mqtt/" (7)
        0x00, 0x00,                                         // Packet Identifier = 0 (ILLEGAL)
        0x00,                                               // properties length = 0
        b't', b'e', b's', b't',                             // payload "test" (4)
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client).await)
}

const SUBSCRIBE_PACKET_ID_ZERO: TestContext = TestContext {
    refs: &["MQTT-2.2.1-3"],
    description: "SUBSCRIBE with Packet Identifier 0 MUST be rejected",
    compliance: Compliance::Must,
};

/// Each time a Client sends a new SUBSCRIBE, UNSUBSCRIBE, or PUBLISH (where QoS > 0) MQTT
/// Control Packet it MUST assign it a non-zero Packet Identifier that is currently unused.
/// [MQTT-2.2.1-3]
///
/// This test sends a SUBSCRIBE with Packet Identifier set to 0. The broker should treat this
/// as a Protocol Error and disconnect.
async fn subscribe_packet_id_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-sub-pid0");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,                                               // SUBSCRIBE
        0x0B,                                               // remaining length = 11
        0x00, 0x00,                                         // Packet Identifier = 0 (ILLEGAL)
        0x00,                                               // properties length = 0
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/" (7)
        0x00,                                               // subscription options: QoS 0
    ];
    client.send_raw(bad_subscribe).await?;

    Ok(expect_disconnect(&mut client).await)
}

const UNSUBSCRIBE_PACKET_ID_ZERO: TestContext = TestContext {
    refs: &["MQTT-2.2.1-3"],
    description: "UNSUBSCRIBE with Packet Identifier 0 MUST be rejected",
    compliance: Compliance::Must,
};

/// Each time a Client sends a new SUBSCRIBE, UNSUBSCRIBE, or PUBLISH (where QoS > 0) MQTT
/// Control Packet it MUST assign it a non-zero Packet Identifier that is currently unused.
/// [MQTT-2.2.1-3]
///
/// This test sends an UNSUBSCRIBE with Packet Identifier set to 0. The broker should treat
/// this as a Protocol Error and disconnect.
async fn unsubscribe_packet_id_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-unsub-pid0");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    #[rustfmt::skip]
    let bad_unsubscribe: &[u8] = &[
        0xA2,                                               // UNSUBSCRIBE
        0x0A,                                               // remaining length = 10
        0x00, 0x00,                                         // Packet Identifier = 0 (ILLEGAL)
        0x00,                                               // properties length = 0
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/" (7)
    ];
    client.send_raw(bad_unsubscribe).await?;

    Ok(expect_disconnect(&mut client).await)
}

// ── MQTT-3.1: CONNECT validation ─────────────────────────────────────────────

const CONNECT_FLAGS_RESERVED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-3"],
    description: "Server MUST validate that the reserved flag in the CONNECT packet is set to 0",
    compliance: Compliance::Must,
};

/// The Server MUST validate that the reserved flag in the CONNECT packet is set to 0.
/// [MQTT-3.1.2-3]
///
/// This test sends a CONNECT with the reserved bit (bit 0) of the Connect Flags byte set to 1
/// (flags = 0x03) and verifies the broker rejects the connection.
async fn connect_flags_reserved_bit(config: TestConfig<'_>) -> Result<Outcome> {
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

const NO_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.1.3-3"],
    description: "CONNECT with no Client ID in payload MUST be rejected",
    compliance: Compliance::Must,
};

/// The ClientID MUST be present and is the first field in the CONNECT packet Payload. [MQTT-3.1.3-3]
///
/// This test sends a CONNECT with an empty payload — no client ID at all.
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

const WILL_FLAG0_QOS_NONZERO: TestContext = TestContext {
    refs: &["MQTT-3.1.2-11"],
    description: "CONNECT with Will Flag=0 and Will QoS != 0 MUST be rejected as malformed",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 0, then the Will QoS MUST be set to 0 (0x00). [MQTT-3.1.2-11]
///
/// This test sends a CONNECT with Will Flag=0 but Will QoS=1 (Connect Flags byte = 0x0A,
/// Clean Start=1 + Will QoS bits set), and verifies the broker rejects it as a malformed packet.
/// Payload contains only the Client ID (no Will fields, as required when Will Flag=0).
async fn will_flag_zero_qos_nonzero(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Connect Flags = 0x0A = 0b_0000_1010 — Clean Start=1, Will Flag=0, Will QoS=1.
    // Payload contains only the Client ID — no Will fields (Will Flag=0).
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT fixed header
        0x11,                                           // remaining length = 17
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x0A,                                           // flags: clean_start=1, will=0, will_qos=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // connect properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const WILL_QOS_THREE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-12"],
    description: "CONNECT with Will QoS=3 MUST be rejected as malformed",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00), 1 (0x01), or 2 (0x02). A
/// value of 3 (0x03) is a Malformed Packet. [MQTT-3.1.2-12]
///
/// This test sends a CONNECT with Will Flag=1 and Will QoS=3 (both Will QoS bits set; Connect
/// Flags byte = 0x1E), with a complete Will payload (Will Properties, Will Topic "w", Will Payload
/// "x"), and verifies the broker rejects it as a malformed packet.
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

const WILL_FLAG0_RETAIN_SET: TestContext = TestContext {
    refs: &["MQTT-3.1.2-13"],
    description: "CONNECT with Will Flag=0 and Will Retain=1 MUST be rejected as malformed",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 0, then Will Retain MUST be set to 0. [MQTT-3.1.2-13]
///
/// This test sends a CONNECT with Will Flag=0 but Will Retain=1 (Connect Flags byte = 0x22,
/// Clean Start=1 + Will Retain bit set), and verifies the broker rejects it as a malformed packet.
/// Payload contains only the Client ID (no Will fields, as required when Will Flag=0).
async fn will_flag_zero_retain_set(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Connect Flags = 0x22 = 0b_0010_0010 — Clean Start=1, Will Flag=0, Will Retain=1.
    // Payload contains only the Client ID — no Will fields (Will Flag=0).
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT fixed header
        0x11,                                           // remaining length = 17
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x22,                                           // flags: clean_start=1, will=0, will_retain=1
        0x00, 0x3C,                                     // keep alive = 60
        0x00,                                           // connect properties length = 0
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const WILL_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-9"],
    description: "Will Flag=1: Will Properties, Will Topic, and Will Payload MUST be in Payload",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 1, the Will QoS and Will Retain fields in the Connect Flags will be
/// used by the Server, and the Will Properties, Will Topic and Will Message fields MUST be present
/// in the Payload. [MQTT-3.1.2-9]
///
/// This test sends a CONNECT with Will Flag=1 but a payload that contains only the Client ID
/// (Will Properties, Will Topic and Will Payload all missing), and verifies the broker rejects the
/// connection as malformed.
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

const USERNAME_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-17"],
    description: "CONNECT with Username flag set but truncated payload MUST be rejected",
    compliance: Compliance::Must,
};

/// If the User Name Flag is set to 1, a User Name MUST be present in the Payload. [MQTT-3.1.2-17]
///
/// This test sends a CONNECT with the Username flag set but the payload ends after the client
/// ID — no username bytes.
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

const PASSWORD_TRUNCATED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-19"],
    description: "CONNECT with Password flag set but truncated payload MUST be rejected",
    compliance: Compliance::Must,
};

/// If the Password Flag is set to 1, a Password MUST be present in the Payload. [MQTT-3.1.2-19]
///
/// This test sends a CONNECT with Username + Password flags set but the payload ends after the
/// username — no password.
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

const USERNAME_FLAG_MISMATCH: TestContext = TestContext {
    refs: &["MQTT-3.1.2-16"],
    description: "CONNECT with Username Flag=0 but extra payload data MUST be rejected",
    compliance: Compliance::Must,
};

/// If the User Name Flag is set to 0, a User Name MUST NOT be present in the
/// Payload. [MQTT-3.1.2-16]
///
/// This test sends a CONNECT with Username Flag=0 but extra payload bytes beyond the client ID.
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
    description: "CONNECT with Password Flag=0 but extra payload data MUST be rejected",
    compliance: Compliance::Must,
};

/// If the Password Flag is set to 0, a Password MUST NOT be present in the
/// Payload. [MQTT-3.1.2-18]
///
/// This test sends a CONNECT with Username Flag=1, Password Flag=0, but extra payload bytes after
/// the username.
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

// ── MQTT-3.3: PUBLISH validation ─────────────────────────────────────────────

const EMPTY_TOPIC_NO_ALIAS: TestContext = TestContext {
    refs: &["MQTT-3.3.2-1"],
    description: "PUBLISH with empty topic and no Topic Alias MUST be rejected",
    compliance: Compliance::Must,
};

/// The Topic Name MUST be present as the first field in the PUBLISH packet Variable Header. It
/// MUST be a UTF-8 Encoded String. [MQTT-3.3.2-1]
///
/// This test sends a PUBLISH with a zero-length topic and no Topic Alias, which is a protocol
/// error.
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
    refs: &["MQTT-3.3.2-8"],
    description: "PUBLISH with Topic Alias of 0 MUST be a protocol error",
    compliance: Compliance::Must,
};

/// A sender MUST NOT send a PUBLISH packet containing a Topic Alias which has the value
/// 0. [MQTT-3.3.2-8]
///
/// This test sends a PUBLISH with Topic Alias property set to 0.
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

const TOPIC_ALIAS_EXCEEDS_MAX: TestContext = TestContext {
    refs: &["MQTT-3.3.2-9"],
    description: "Topic Alias exceeding server's maximum MUST be a protocol error",
    compliance: Compliance::Must,
};

/// A Client MUST NOT send a PUBLISH packet with a Topic Alias greater than the Topic Alias
/// Maximum value returned by the Server in the CONNACK packet. [MQTT-3.3.2-9]
///
/// This test sends a PUBLISH with Topic Alias set to one more than the server's advertised
/// maximum.
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

// ── MQTT-3.8: SUBSCRIBE validation ───────────────────────────────────────────

const SUB_NO_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.8.3-2"],
    description: "SUBSCRIBE with no topic filters MUST be rejected",
    compliance: Compliance::Must,
};

/// The Payload MUST contain at least one Topic Filter and Subscription Options
/// pair. [MQTT-3.8.3-2]
///
/// This test sends a SUBSCRIBE with a packet ID but no topic filters.
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
    refs: &["MQTT-3.8.3-5"],
    description: "SUBSCRIBE with reserved QoS bits set MUST be rejected",
    compliance: Compliance::Must,
};

/// The Server MUST treat a SUBSCRIBE packet as malformed if any of Reserved bits in the Payload
/// are non-zero. [MQTT-3.8.3-5]
///
/// This test sends a SUBSCRIBE with reserved bits 6-7 set in the subscription options byte.
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
    description: "'#' wildcard MUST only be the last character in a topic filter",
    compliance: Compliance::Must,
};

/// The multi-level wildcard character MUST be specified either on its own or following a topic
/// level separator. In either case it MUST be the last character specified in the Topic
/// Filter. [MQTT-4.7.1-1]
///
/// This test sends a SUBSCRIBE with topic filter "mqtt/#/invalid" where '#' is not the last
/// character.
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

const INVALID_PLUS_WILDCARD: TestContext = TestContext {
    refs: &["MQTT-4.7.1-2"],
    description: "'+' wildcard MUST occupy an entire level of a topic filter",
    compliance: Compliance::Must,
};

/// Where it is used, it MUST occupy an entire level of the filter. [MQTT-4.7.1-2]
///
/// This test sends a SUBSCRIBE with topic filter "mqtt/te+st" where '+' does not occupy an entire
/// level.
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

// ── MQTT-3.10: UNSUBSCRIBE validation ────────────────────────────────────────

const UNSUB_NO_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.10.3-1", "MQTT-3.10.3-2"],
    description: "UNSUBSCRIBE with no topic filters MUST be rejected",
    compliance: Compliance::Must,
};

/// The Payload of an UNSUBSCRIBE packet MUST contain at least one Topic Filter. [MQTT-3.10.3-2]
///
/// This test sends an UNSUBSCRIBE with a packet ID but no topic filters.
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
