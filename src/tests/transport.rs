//! Transport compliance tests (MQTT §4.2).
//!
//! The MQTT protocol requires an underlying transport that provides an ordered,
//! lossless, stream of bytes [MQTT-4.2-1].  These tests verify that the broker
//! accepts CONNECT and returns CONNACK over each available transport.

use anyhow::Result;

use crate::client;
use crate::codec::ConnectParams;
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("TRANSPORT");

    suite.add(TCP_TRANSPORT, tcp_connect(config));
    suite.add(TLS_TRANSPORT, tls_connect(config));

    suite
}

const TCP_TRANSPORT: TestContext = TestContext {
    refs: &["MQTT-4.2-1"],
    description: "TCP transport MUST provide ordered, lossless byte stream (CONNECT/CONNACK)",
    compliance: Compliance::Must,
};

/// Verify the broker accepts an MQTT connection over plain TCP.
async fn tcp_connect(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-tcp-transport");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "CONNACK reason code {:#04x} (expected 0x00)",
            connack.reason_code
        )))
    }
}

const TLS_TRANSPORT: TestContext = TestContext {
    refs: &["MQTT-4.2-1"],
    description: "TLS transport MUST provide ordered, lossless byte stream (CONNECT/CONNACK)",
    compliance: Compliance::Must,
};

/// Verify the broker accepts an MQTT connection over TLS.
async fn tls_connect(config: TestConfig<'_>) -> Result<Outcome> {
    let Some((tls_addr, tls)) = config.tls_info else {
        return Ok(Outcome::skip("TLS not configured"));
    };
    let params = ConnectParams::new("mqtt-test-tls-transport");
    let (_client, connack) =
        client::connect_tls(tls_addr, &params, tls, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "CONNACK reason code {:#04x} (expected 0x00)",
            connack.reason_code
        )))
    }
}
