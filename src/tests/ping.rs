//! PINGREQ / PINGRESP compliance tests [MQTT-3.12 / MQTT-3.13].

use anyhow::Result;

use crate::client;
use crate::codec::{ConnectParams, Packet};
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

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

/// The Server MUST send a PINGRESP packet in response to a PINGREQ packet [MQTT-3.12.4-1].
///
/// This test sends a single PINGREQ and verifies the server responds with PINGRESP.
async fn pingreq_gets_pingresp(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-ping");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    client.send_pingreq().await?;

    match client.recv().await? {
        Packet::PingResp => Ok(Outcome::Pass),
        other => Ok(Outcome::fail_packet("PINGRESP", &other)),
    }
}

const MULTI_PING: TestContext = TestContext {
    refs: &["MQTT-3.12.4-1"],
    description: "Server MUST respond to each successive PINGREQ",
    compliance: Compliance::Must,
};

/// The Server MUST send a PINGRESP packet in response to a PINGREQ packet [MQTT-3.12.4-1].
///
/// This test sends three successive PINGREQs and verifies the server responds to each one with PINGRESP.
async fn multiple_pings(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-multi-ping");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    for i in 0..3u8 {
        client.send_pingreq().await?;
        match client.recv().await? {
            Packet::PingResp => {}
            other => {
                return Ok(Outcome::fail_packet(
                    format!("Ping {i}: expected PINGRESP").as_str(),
                    &other,
                ));
            }
        }
    }

    Ok(Outcome::Pass)
}
