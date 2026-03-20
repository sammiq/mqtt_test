//! Malformed packet handling compliance tests.
//!
//! The MQTT v5 spec requires the server to disconnect with reason code 0x81
//! (Malformed Packet) when it receives packets that violate protocol rules.
//! These tests send intentionally broken packets and verify the server
//! terminates the connection.

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client::{self, RawClient};
use crate::codec::{ConnectParams, Packet};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 11;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "MALFORMED PACKETS",
        results: vec![
            reserved_connect_flags(addr, recv_timeout, pb).await,
            malformed_remaining_length(addr, recv_timeout, pb).await,
            publish_empty_topic_no_alias(addr, recv_timeout, pb).await,
            publish_topic_alias_zero(addr, recv_timeout, pb).await,
            subscribe_no_filters(addr, recv_timeout, pb).await,
            subscribe_invalid_qos(addr, recv_timeout, pb).await,
            subscribe_invalid_wildcard(addr, recv_timeout, pb).await,
            unsubscribe_no_filters(addr, recv_timeout, pb).await,
            unsubscribe_reserved_bits(addr, recv_timeout, pb).await,
            topic_alias_exceeds_maximum(addr, recv_timeout, pb).await,
            subscribe_invalid_plus_wildcard(addr, recv_timeout, pb).await,
        ],
    }
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
    id: "MQTT-3.1.4-1",
    description: "Server MUST validate CONNECT reserved flag is zero",
    compliance: Compliance::Must,
};

/// The CONNECT packet's connect-flags byte has a reserved bit (bit 0) that
/// MUST be 0. Sending it as 1 is a malformed packet [MQTT-3.1.2-3].
async fn reserved_connect_flags(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = RESERVED_FLAGS;
    run_test(ctx, pb, async {
        let mut client = RawClient::connect_tcp(addr).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const BAD_REMAINING_LEN: TestContext = TestContext {
    id: "MQTT-2.1.4-1",
    description: "Server MUST close connection on malformed remaining length",
    compliance: Compliance::Must,
};

/// A packet with a remaining-length field that uses more than 4 bytes
/// (continuation bit set on all 4 bytes) is malformed [MQTT-1.5.5-1].
async fn malformed_remaining_length(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = BAD_REMAINING_LEN;
    run_test(ctx, pb, async {
        let mut client = RawClient::connect_tcp(addr).await?;

        // Send a CONNECT-like packet with a 5-byte remaining length (all continuation bits set).
        // This violates the VBI encoding limit of 4 bytes.
        #[rustfmt::skip]
        let bad_packet: &[u8] = &[
            0x10,                               // CONNECT fixed header
            0x80, 0x80, 0x80, 0x80, 0x01,       // malformed VBI: 5 continuation bytes
        ];
        client.send_raw(bad_packet).await?;

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const EMPTY_TOPIC_NO_ALIAS: TestContext = TestContext {
    id: "MQTT-3.3.2-1",
    description: "PUBLISH with empty topic and no Topic Alias MUST be rejected",
    compliance: Compliance::Must,
};

/// A PUBLISH with an empty topic string and no Topic Alias property is
/// a protocol error [MQTT-3.3.2-8].
async fn publish_empty_topic_no_alias(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = EMPTY_TOPIC_NO_ALIAS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-empty-topic");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const TOPIC_ALIAS_ZERO: TestContext = TestContext {
    id: "MQTT-3.3.2-2",
    description: "PUBLISH with Topic Alias of 0 MUST be a protocol error",
    compliance: Compliance::Must,
};

/// A Topic Alias of 0 is not permitted — the server MUST disconnect [MQTT-3.3.2-8].
async fn publish_topic_alias_zero(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TOPIC_ALIAS_ZERO;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-alias-zero");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const SUB_NO_FILTERS: TestContext = TestContext {
    id: "MQTT-3.8.3-1",
    description: "SUBSCRIBE with no topic filters MUST be rejected",
    compliance: Compliance::Must,
};

/// A SUBSCRIBE packet MUST contain at least one topic filter [MQTT-3.8.3-3].
/// The payload must be non-empty.
async fn subscribe_no_filters(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUB_NO_FILTERS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-sub-empty");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const SUB_INVALID_QOS: TestContext = TestContext {
    id: "MQTT-3.8.3-2",
    description: "SUBSCRIBE with reserved QoS bits set MUST be rejected",
    compliance: Compliance::Must,
};

/// The subscription options byte's upper 2 QoS bits (6-7) are reserved and
/// MUST be 0. Setting them is a protocol error [MQTT-3.8.3-5].
async fn subscribe_invalid_qos(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUB_INVALID_QOS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-sub-bad-qos");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const INVALID_WILDCARD: TestContext = TestContext {
    id: "MQTT-4.7.1-1",
    description: "'#' wildcard MUST only be the last character in a topic filter",
    compliance: Compliance::Must,
};

/// '#' wildcard not at the end of a topic filter is a protocol error [MQTT-4.7.1-1].
/// The server MUST treat a SUBSCRIBE with such a filter as a protocol error.
async fn subscribe_invalid_wildcard(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = INVALID_WILDCARD;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-bad-wildcard");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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
        match client.recv(recv_timeout).await {
            Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::SubAck(ack)) => {
                let _ = client.send_disconnect(0x00).await;
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
    })
    .await
}

const UNSUB_NO_FILTERS: TestContext = TestContext {
    id: "MQTT-3.10.3-1",
    description: "UNSUBSCRIBE with no topic filters MUST be rejected",
    compliance: Compliance::Must,
};

/// An UNSUBSCRIBE packet MUST contain at least one topic filter [MQTT-3.10.3-2].
async fn unsubscribe_no_filters(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = UNSUB_NO_FILTERS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-unsub-empty");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const UNSUB_RESERVED_BITS: TestContext = TestContext {
    id: "MQTT-3.10.1-1",
    description: "UNSUBSCRIBE fixed header reserved bits MUST be 0010",
    compliance: Compliance::Must,
};

/// The UNSUBSCRIBE fixed header byte must have bits 3-0 = 0010.
/// Sending wrong reserved bits is a malformed packet [MQTT-3.10.1-1].
async fn unsubscribe_reserved_bits(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = UNSUB_RESERVED_BITS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-unsub-reserved");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const TOPIC_ALIAS_EXCEEDS_MAX: TestContext = TestContext {
    id: "MQTT-3.3.2-4",
    description: "Topic Alias exceeding server's maximum MUST be a protocol error",
    compliance: Compliance::Must,
};

/// A Topic Alias value that exceeds the server's Topic Alias Maximum is a
/// protocol error — the server MUST disconnect [MQTT-3.3.2-9].
async fn topic_alias_exceeds_maximum(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TOPIC_ALIAS_EXCEEDS_MAX;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-alias-exceed");
        let (mut client, connack) = client::connect(addr, &params, recv_timeout).await?;

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

        Ok(expect_disconnect(&mut client, recv_timeout, &ctx).await)
    })
    .await
}

const INVALID_PLUS_WILDCARD: TestContext = TestContext {
    id: "MQTT-4.7.1-4",
    description: "'+' wildcard MUST occupy an entire level of a topic filter",
    compliance: Compliance::Must,
};

/// '+' wildcard not occupying an entire topic level is a protocol error [MQTT-4.7.1-1].
/// E.g., "mqtt/te+st" is invalid.
async fn subscribe_invalid_plus_wildcard(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = INVALID_PLUS_WILDCARD;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-bad-plus");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

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
        match client.recv(recv_timeout).await {
            Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::SubAck(ack)) => {
                let _ = client.send_disconnect(0x00).await;
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
    })
    .await
}
