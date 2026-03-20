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

pub const TEST_COUNT: usize = 5;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "MALFORMED PACKETS",
        results: vec![
            reserved_connect_flags(addr, recv_timeout, pb).await,
            malformed_remaining_length(addr, recv_timeout, pb).await,
            publish_empty_topic_no_alias(addr, recv_timeout, pb).await,
            subscribe_no_filters(addr, recv_timeout, pb).await,
            subscribe_invalid_qos(addr, recv_timeout, pb).await,
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
    run_test(ctx, pb, || async move {
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
    run_test(ctx, pb, || async move {
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
    run_test(ctx, pb, || async move {
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

const SUB_NO_FILTERS: TestContext = TestContext {
    id: "MQTT-3.8.3-1",
    description: "SUBSCRIBE with no topic filters MUST be rejected",
    compliance: Compliance::Must,
};

/// A SUBSCRIBE packet MUST contain at least one topic filter [MQTT-3.8.3-3].
/// The payload must be non-empty.
async fn subscribe_no_filters(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUB_NO_FILTERS;
    run_test(ctx, pb, || async move {
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
    run_test(ctx, pb, || async move {
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
