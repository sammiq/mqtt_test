//! PINGREQ / PINGRESP compliance tests [MQTT-3.12 / MQTT-3.13].

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client;
use crate::codec::{ConnectParams, Packet};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 2;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "PINGREQ / PINGRESP",
        results: vec![
            pingreq_gets_pingresp(addr, recv_timeout, pb).await,
            multiple_pings(addr, recv_timeout, pb).await,
        ],
    }
}

const PINGRESP: TestContext = TestContext {
    id: "MQTT-3.12.4-1",
    description: "Server MUST send PINGRESP in response to PINGREQ",
    compliance: Compliance::Must,
};

/// Server MUST send PINGRESP in response to PINGREQ [MQTT-3.12.4-1].
async fn pingreq_gets_pingresp(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = PINGRESP;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-ping");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        client.send_pingreq().await?;

        match client.recv(recv_timeout).await? {
            Packet::PingResp => Ok(TestResult::pass(&ctx)),
            other => Ok(TestResult::fail_packet(&ctx, "PINGRESP", &other)),
        }
    })
    .await
}

const MULTI_PING: TestContext = TestContext {
    id: "MQTT-3.12.4-1b",
    description: "Server MUST respond to each successive PINGREQ",
    compliance: Compliance::Must,
};

/// Server MUST respond to each PINGREQ [MQTT-3.12.4-1] (multiple pings).
async fn multiple_pings(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = MULTI_PING;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-multi-ping");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        for i in 0..3u8 {
            client.send_pingreq().await?;
            match client.recv(recv_timeout).await? {
                Packet::PingResp => {}
                other => {
                    return Ok(TestResult::fail_packet(
                        &ctx,
                        format!("Ping {i}: expected PINGRESP").as_str(),
                        &other,
                    ));
                }
            }
        }

        Ok(TestResult::pass(&ctx))
    })
    .await
}
