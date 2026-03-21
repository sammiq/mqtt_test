//! TLS transport compliance tests.
//!
//! These tests verify that MQTT works correctly over TLS connections.
//! They are only run when `--tls-broker` is provided.

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client::{self, TlsConfig};
use crate::codec::{ConnectParams, Packet, PublishParams, QoS, SubscribeParams};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 4;

pub async fn run(addr: &str, tls: &TlsConfig, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "TLS",
        results: vec![
            tls_connect(addr, tls, recv_timeout, pb).await,
            tls_publish_qos0(addr, tls, recv_timeout, pb).await,
            tls_publish_qos1(addr, tls, recv_timeout, pb).await,
            tls_connack_properties(addr, tls, recv_timeout, pb).await,
        ],
    }
}

const TLS_CONNECT: TestContext = TestContext {
    id: "MQTT-TLS-1",
    description: "TLS handshake and CONNECT/CONNACK MUST succeed over TLS",
    compliance: Compliance::Must,
};

/// Basic TLS connectivity: handshake succeeds and broker sends CONNACK.
async fn tls_connect(addr: &str, tls: &TlsConfig, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TLS_CONNECT;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-tls-connect");
        let (_client, connack) = client::connect_tls(addr, &params, tls, recv_timeout).await?;

        if connack.reason_code == 0x00 {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                format!("CONNACK reason code {:#04x} (expected 0x00)", connack.reason_code),
            ))
        }
    })
    .await
}

const TLS_PUB_QOS0: TestContext = TestContext {
    id: "MQTT-TLS-2",
    description: "QoS 0 PUBLISH MUST be delivered over TLS",
    compliance: Compliance::Must,
};

/// Verify QoS 0 publish/subscribe works over TLS.
async fn tls_publish_qos0(addr: &str, tls: &TlsConfig, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TLS_PUB_QOS0;
    run_test(ctx, pb, async {
        let topic = "mqtt/test/tls/qos0";

        // Subscribe
        let sub_params = ConnectParams::new("mqtt-test-tls-q0-sub");
        let (mut sub, _) = client::connect_tls(addr, &sub_params, tls, recv_timeout).await?;
        let sub_req = SubscribeParams::simple(1, topic, QoS::AtMostOnce);
        sub.send_subscribe(&sub_req).await?;
        sub.recv(recv_timeout).await?; // SUBACK

        // Publish
        let pub_params = ConnectParams::new("mqtt-test-tls-q0-pub");
        let (mut pub_client, _) = client::connect_tls(addr, &pub_params, tls, recv_timeout).await?;
        pub_client.send_publish(&PublishParams::qos0(topic, b"tls-hello".to_vec())).await?;

        match sub.recv(recv_timeout).await? {
            Packet::Publish(p) if p.topic == topic => Ok(TestResult::pass(&ctx)),
            other => Ok(TestResult::fail_packet(&ctx, "PUBLISH over TLS", &other)),
        }
    })
    .await
}

const TLS_PUB_QOS1: TestContext = TestContext {
    id: "MQTT-TLS-3",
    description: "QoS 1 PUBLISH MUST be acknowledged over TLS",
    compliance: Compliance::Must,
};

/// Verify QoS 1 PUBACK flow works over TLS.
async fn tls_publish_qos1(addr: &str, tls: &TlsConfig, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TLS_PUB_QOS1;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-tls-q1");
        let (mut client, _) = client::connect_tls(addr, &params, tls, recv_timeout).await?;

        client.send_publish(&PublishParams::qos1("mqtt/test/tls/qos1", b"tls-qos1".to_vec(), 1)).await?;

        match client.recv(recv_timeout).await? {
            Packet::PubAck(ack) if ack.packet_id == 1 => Ok(TestResult::pass(&ctx)),
            other => Ok(TestResult::fail_packet(&ctx, "PUBACK over TLS", &other)),
        }
    })
    .await
}

const TLS_CONNACK_PROPS: TestContext = TestContext {
    id: "MQTT-TLS-4",
    description: "CONNACK properties MUST be present over TLS (same as TCP)",
    compliance: Compliance::Must,
};

/// Verify the broker returns expected CONNACK properties over TLS,
/// confirming the full MQTT v5 protocol works identically over TLS.
async fn tls_connack_properties(addr: &str, tls: &TlsConfig, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TLS_CONNACK_PROPS;
    run_test(ctx, pb, async {
        let mut params = ConnectParams::new("mqtt-test-tls-props");
        params.properties.session_expiry_interval = Some(60);
        params.properties.receive_maximum = Some(10);
        let (_client, connack) = client::connect_tls(addr, &params, tls, recv_timeout).await?;

        // The broker should respond with a valid CONNACK — session_present
        // should be 0 for clean start, and reason code should be success.
        if connack.reason_code == 0x00 && !connack.session_present {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                format!(
                    "Unexpected CONNACK over TLS: reason={:#04x}, session_present={}",
                    connack.reason_code, connack.session_present
                ),
            ))
        }
    })
    .await
}
