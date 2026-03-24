//! PINGREQ / PINGRESP compliance tests [MQTT-3.12 / MQTT-3.13].

use crate::client;
use crate::codec::{ConnectParams, Packet};
use crate::types::{Compliance, SuiteRunner, TestConfig, TestContext, TestResult};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("PINGREQ / PINGRESP");

    suite.add(PINGRESP, pingreq_gets_pingresp(config));
    suite.add(MULTI_PING, multiple_pings(config));

    suite
}

const PINGRESP: TestContext = TestContext {
    refs: &["MQTT-3.12.4-1"],
    description: "Server MUST send PINGRESP in response to PINGREQ",
    compliance: Compliance::Must,
};

/// Server MUST send PINGRESP in response to PINGREQ [MQTT-3.12.4-1].
async fn pingreq_gets_pingresp(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = PINGRESP;
    let params = ConnectParams::new("mqtt-test-ping");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    client.send_pingreq().await?;

    match client.recv().await? {
        Packet::PingResp => Ok(TestResult::pass(&ctx)),
        other => Ok(TestResult::fail_packet(&ctx, "PINGRESP", &other)),
    }
}

const MULTI_PING: TestContext = TestContext {
    refs: &["MQTT-3.12.4-1b"],
    description: "Server MUST respond to each successive PINGREQ",
    compliance: Compliance::Must,
};

/// Server MUST respond to each PINGREQ [MQTT-3.12.4-1] (multiple pings).
async fn multiple_pings(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = MULTI_PING;
    let params = ConnectParams::new("mqtt-test-multi-ping");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    for i in 0..3u8 {
        client.send_pingreq().await?;
        match client.recv().await? {
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
}
