//! DISCONNECT compliance tests [MQTT-3.14].

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client;
use crate::codec::{ConnectParams, Packet, Properties, QoS, SubscribeOptions, SubscribeParams, WillParams};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 2;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "DISCONNECT",
        results: vec![
            server_closes_after_disconnect(addr, recv_timeout, pb).await,
            disconnect_with_will(addr, recv_timeout, pb).await,
        ],
    }
}

const DISCONNECT_CLOSE: TestContext = TestContext {
    id: "MQTT-3.14.4-1",
    description: "After receiving DISCONNECT, server MUST close the network connection",
    compliance: Compliance::Must,
};

/// After receiving DISCONNECT from the client, the server MUST close the connection [MQTT-3.14.4-1].
async fn server_closes_after_disconnect(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = DISCONNECT_CLOSE;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-disconnect");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        client.send_disconnect(0x00).await?;

        // After DISCONNECT, any further recv should fail (connection closed)
        match client.recv(recv_timeout).await {
            Err(_) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
            Ok(other) => Ok(TestResult::fail_packet(
                &ctx,
                "connection close after DISCONNECT",
                &other,
            )),
        }
    })
    .await
}

const DISCONNECT_WITH_WILL: TestContext = TestContext {
    id: "MQTT-3.14.1-1",
    description: "DISCONNECT with reason 0x04 MUST trigger will message publication",
    compliance: Compliance::Must,
};

/// DISCONNECT with reason code 0x04 (Disconnect with Will Message) MUST cause
/// the server to publish the will message [MQTT-3.14.2-3].
async fn disconnect_with_will(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = DISCONNECT_WITH_WILL;
    run_test(ctx, pb, || async move {
        let will_topic = "mqtt/test/disconnect/will04";

        // Set up a subscriber
        let sub_params = ConnectParams::new("mqtt-test-dc-will-sub");
        let (mut sub_client, _) = client::connect(addr, &sub_params, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                will_topic.to_string(),
                SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
            )],
            properties: Properties::default(),
        };
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        // Connect with a will message
        let mut will_params = ConnectParams::new("mqtt-test-dc-will-pub");
        will_params.will = Some(WillParams {
            topic:      will_topic.to_string(),
            payload:    b"will-on-0x04".to_vec(),
            qos:        QoS::AtMostOnce,
            retain:     false,
            properties: Properties::default(),
        });
        let (mut will_client, _) = client::connect(addr, &will_params, recv_timeout).await?;

        // Disconnect with reason 0x04 — will message should still be published
        will_client.send_disconnect(0x04).await?;

        match sub_client.recv(Duration::from_secs(5)).await {
            Ok(Packet::Publish(p)) if p.topic == will_topic => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::pass(&ctx))
            }
            Ok(other) => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::fail_packet(&ctx, "PUBLISH (will message)", &other))
            }
            Err(_) => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::fail(
                    &ctx,
                    "Will message not received after DISCONNECT with reason 0x04",
                ))
            }
        }
    })
    .await
}
