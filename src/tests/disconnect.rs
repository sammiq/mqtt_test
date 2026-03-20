//! DISCONNECT compliance tests [MQTT-3.14].

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client;
use crate::codec::{ConnectParams, Packet};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 1;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "DISCONNECT",
        results: vec![
            server_closes_after_disconnect(addr, recv_timeout, pb).await,
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
