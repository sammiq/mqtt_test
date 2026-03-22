//! Transport compliance tests (MQTT §4.2).
//!
//! The MQTT protocol requires an underlying transport that provides an ordered,
//! lossless, stream of bytes [MQTT-4.2-1].  These tests verify that the broker
//! accepts CONNECT and returns CONNACK over each available transport.

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client::{self, TlsConfig};
use crate::codec::ConnectParams;
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TCP_TEST_COUNT: usize = 1;
pub const TLS_TEST_COUNT: usize = 1;

pub async fn run_tcp(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "TRANSPORT",
        results: vec![
            tcp_connect(addr, recv_timeout, pb).await,
        ],
    }
}

pub async fn run_tls(addr: &str, tls: &TlsConfig, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "TRANSPORT (TLS)",
        results: vec![
            tls_connect(addr, tls, recv_timeout, pb).await,
        ],
    }
}

const TCP_TRANSPORT: TestContext = TestContext {
    refs: &["MQTT-4.2-1"],
    description: "TCP transport MUST provide ordered, lossless byte stream (CONNECT/CONNACK)",
    compliance: Compliance::Must,
};

/// Verify the broker accepts an MQTT connection over plain TCP.
async fn tcp_connect(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TCP_TRANSPORT;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-tcp-transport");
        let (_client, connack) = client::connect(addr, &params, recv_timeout).await?;

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

const TLS_TRANSPORT: TestContext = TestContext {
    refs: &["MQTT-4.2-1"],
    description: "TLS transport MUST provide ordered, lossless byte stream (CONNECT/CONNACK)",
    compliance: Compliance::Must,
};

/// Verify the broker accepts an MQTT connection over TLS.
async fn tls_connect(addr: &str, tls: &TlsConfig, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TLS_TRANSPORT;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-tls-transport");
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
