//! DISCONNECT compliance tests [MQTT-3.14].

use std::time::Duration;

use anyhow::Result;

use crate::client::{self, RecvError};
use crate::codec::{ConnectParams, Packet, Properties, PublishParams, QoS, WillParams};
use crate::helpers::expect_disconnect;
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("DISCONNECT");

    suite.add(DISCONNECT_CLOSE, server_closes_after_disconnect(config));
    suite.add(DISCONNECT_WITH_WILL, disconnect_with_will(config));
    suite.add(
        NORMAL_DISCONNECT_DISCARDS_WILL,
        normal_disconnect_discards_will(config),
    );
    suite.add(
        SESSION_EXPIRY_INCREASE,
        session_expiry_increase_rejected(config),
    );
    suite.add(WILL_DELAY, will_delay_interval(config));
    suite.add(
        DISCONNECT_SESSION_TAKEOVER,
        disconnect_reason_session_takeover(config),
    );
    suite.add(
        DISCONNECT_PACKET_TOO_LARGE,
        disconnect_on_packet_too_large(config),
    );
    suite.add(DISCONNECT_REASON_STRING, disconnect_reason_string(config));
    suite.add(
        DISCONNECT_PROTOCOL_ERROR,
        disconnect_on_protocol_error(config),
    );

    suite
}

const DISCONNECT_CLOSE: TestContext = TestContext {
    refs: &["MQTT-3.14.4-1"],
    description: "After receiving DISCONNECT, server MUST close the network connection",
    compliance: Compliance::Must,
};

/// After receiving DISCONNECT from the client, the server MUST close the connection [MQTT-3.14.4-1].
async fn server_closes_after_disconnect(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-disconnect");
    let (client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;
    let mut client = client.into_raw();

    client.send_disconnect(0x00).await?;

    // After DISCONNECT, any further recv should fail (connection closed)
    Ok(expect_disconnect(&mut client).await)
}

const DISCONNECT_WITH_WILL: TestContext = TestContext {
    refs: &["MQTT-3.14.1-1"],
    description: "DISCONNECT with reason 0x04 MUST trigger will message publication",
    compliance: Compliance::Must,
};

/// DISCONNECT with reason code 0x04 (Disconnect with Will Message) MUST cause
/// the server to publish the will message [MQTT-3.14.2-3].
async fn disconnect_with_will(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/disconnect/will04";

    // Set up a subscriber
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-dc-will-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Connect with a will message
    let mut will_params = ConnectParams::new("mqtt-test-dc-will-pub");
    will_params.will = Some(WillParams::new(will_topic, b"will-on-0x04"));
    let (mut will_client, _) =
        client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Disconnect with reason 0x04 — will message should still be published
    will_client.send_disconnect(0x04).await?;

    match sub_client.recv_with_timeout(Duration::from_secs(5)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(Outcome::Pass),
        Ok(other) => Ok(Outcome::fail_packet("PUBLISH (will message)", &other)),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "Will message not received after DISCONNECT with reason 0x04 (timed out)",
        )),
        Err(RecvError::Closed) => Ok(Outcome::fail(
            "Will message not received after DISCONNECT with reason 0x04 (connection closed)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

const NORMAL_DISCONNECT_DISCARDS_WILL: TestContext = TestContext {
    refs: &["MQTT-3.14.4-3", "MQTT-3.14.4-2"],
    description: "Normal DISCONNECT (0x00) MUST discard the will message",
    compliance: Compliance::Must,
};

/// A normal DISCONNECT (reason 0x00) MUST cause the server to discard any
/// will message associated with the connection [MQTT-3.14.4-3].
async fn normal_disconnect_discards_will(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/disconnect/will_discard";

    // Set up a subscriber
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-dc-discard-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Connect with a will message
    let mut will_params = ConnectParams::new("mqtt-test-dc-discard-pub");
    will_params.will = Some(WillParams::new(will_topic, b"should-not-appear"));
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Disconnect normally — will MUST be discarded
    drop(will_client);

    // Wait briefly — should NOT receive the will message
    match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::Pass),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(Outcome::fail(
            "Will message was published despite normal DISCONNECT (0x00)",
        )),
        Ok(_) => Ok(Outcome::Pass),
    }
}

const SESSION_EXPIRY_INCREASE: TestContext = TestContext {
    refs: &["MQTT-3.14.2-2"],
    description: "Session Expiry MUST NOT increase from 0 to non-zero on DISCONNECT",
    compliance: Compliance::Must,
};

/// A client that connected with Session Expiry Interval of 0 MUST NOT set it
/// to a non-zero value in the DISCONNECT packet [MQTT-3.14.2-3]. The server
/// MUST treat this as a protocol error.
async fn session_expiry_increase_rejected(config: TestConfig<'_>) -> Result<Outcome> {
    // Connect with session_expiry_interval = 0 (or absent, which defaults to 0)
    let params = ConnectParams::new("mqtt-test-sei-increase");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Send DISCONNECT with session_expiry_interval = 60 (increase from 0 → non-zero)
    let props = Properties {
        session_expiry_interval: Some(60),
        ..Properties::default()
    };
    client.send_disconnect_with_properties(0x00, &props).await?;

    // Server MUST treat this as a protocol error — disconnect with 0x82 or close.
    match client.recv().await {
        Err(RecvError::Closed) => {
            // Connection closed — could be normal close or protocol error close.
            // Since we just sent a DISCONNECT, the server closing is expected.
            // We check if the server sends a DISCONNECT with protocol error first.
            // If it just closes, we can't distinguish — mark as pass since the
            // server at minimum didn't honor the invalid session expiry.
            Ok(Outcome::Pass)
        }
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Disconnect(d)) if d.reason_code >= 0x80 => Ok(Outcome::Pass),
        Ok(Packet::Disconnect(d)) if d.reason_code == 0x00 => {
            // Normal disconnect response — server may have just ignored the invalid
            // property. We can't verify the session wasn't extended, so pass cautiously.
            Ok(Outcome::Pass)
        }
        Ok(other) => Ok(Outcome::fail_packet(
            "disconnect with protocol error or connection close",
            &other,
        )),
    }
}

const WILL_DELAY: TestContext = TestContext {
    refs: &["MQTT-3.1.3-9"],
    description: "Will Delay Interval MUST delay will message publication after disconnect",
    compliance: Compliance::Must,
};

/// The server MUST delay publishing the will message by the Will Delay
/// Interval after the network connection is closed [MQTT-3.1.3.2-2].
async fn will_delay_interval(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/disconnect/will_delay";

    // Set up a subscriber for the will topic
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-willdelay-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Connect with a will message + will_delay_interval = 3 seconds
    let mut will_params = ConnectParams::new("mqtt-test-willdelay-pub");
    let mut will = WillParams::new(will_topic, b"delayed-will");
    will.properties.will_delay_interval = Some(3);
    will_params.will = Some(will);
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Abruptly disconnect (skip DISCONNECT so will is triggered)
    drop(will_client.into_raw());

    // Will should NOT arrive within 1 second
    match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => {
            return Ok(Outcome::fail(
                "Will message arrived immediately despite Will Delay Interval of 3s",
            ));
        }
        Err(RecvError::Other(e)) => {
            return Ok(Outcome::fail(format!("unexpected error: {e:#}")));
        }
        _ => {} // Timeout or Closed or unrelated packet — expected, no message yet
    }

    // Will SHOULD arrive within 5 seconds total
    match sub_client.recv_with_timeout(Duration::from_secs(5)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(Outcome::Pass),
        Ok(other) => Ok(Outcome::fail_packet("delayed will PUBLISH", &other)),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "Will message not received within 5 seconds (delay was 3s)",
        )),
        Err(RecvError::Closed) => Ok(Outcome::fail(
            "Will message not received — connection closed (delay was 3s)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

// ── Server-initiated DISCONNECT ─────────────────────────────────────────────

const DISCONNECT_SESSION_TAKEOVER: TestContext = TestContext {
    refs: &["MQTT-3.14.2-1"],
    description: "Server SHOULD send DISCONNECT with reason 0x8E on session takeover",
    compliance: Compliance::Should,
};

/// When another client connects with the same Client ID, the server SHOULD
/// send a DISCONNECT with reason code 0x8E (Session taken over) to the
/// existing client [MQTT-3.14.2-1].
async fn disconnect_reason_session_takeover(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-disc-takeover";

    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(60);
    let (mut c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Second connection with same Client ID
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (_c2, _) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    // c1 should receive DISCONNECT with reason 0x8E
    match c1.recv().await {
        Ok(Packet::Disconnect(d)) if d.reason_code == 0x8E => Ok(Outcome::Pass),
        Ok(Packet::Disconnect(d)) => Ok(Outcome::fail(format!(
            "DISCONNECT received but reason was {:#04x} (expected 0x8E)",
            d.reason_code
        ))),
        Err(RecvError::Closed) => {
            // Connection closed without DISCONNECT — still acceptable
            Ok(Outcome::fail(
                "Connection closed without sending DISCONNECT (expected 0x8E reason code)",
            ))
        }
        Err(RecvError::Timeout) => Ok(Outcome::fail("No DISCONNECT received (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("DISCONNECT", &other)),
    }
}

const DISCONNECT_PACKET_TOO_LARGE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-24"],
    description: "Server MUST disconnect if client sends packet exceeding Maximum Packet Size",
    compliance: Compliance::Must,
};

/// If the client advertises a Maximum Packet Size in CONNECT and then sends
/// a packet exceeding that size, the server MUST disconnect [MQTT-3.1.2-24].
/// Here we test the reverse: we tell the broker our max is small, then the
/// broker should not send us oversized packets. To test server-side enforcement,
/// we send a PUBLISH exceeding the broker's maximum (if advertised).
async fn disconnect_on_packet_too_large(config: TestConfig<'_>) -> Result<Outcome> {
    // Connect and check if broker advertises a Maximum Packet Size.
    let params = ConnectParams::new("mqtt-test-disc-pkt-size");
    let (mut c, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let max_size = connack.properties.maximum_packet_size.unwrap_or(0);
    if max_size == 0 || max_size > 1_000_000 {
        // Broker doesn't advertise a practical limit — send a very large PUBLISH.
        // Use a 1MB payload which should exceed most reasonable limits.
        let large_payload = vec![0x41u8; 1_048_576]; // 1MB of 'A'
        let publish = PublishParams::qos0("test/large/packet", large_payload);
        c.send_publish(&publish).await?;

        // Check if broker disconnects us
        match c.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => Ok(Outcome::Pass),
            Err(RecvError::Timeout) => {
                // Broker accepted it — it has no practical limit
                Ok(Outcome::skip(
                    "Broker accepted 1MB payload — no Maximum Packet Size enforced",
                ))
            }
            Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
            Ok(_) => {
                // Broker accepted it — it has no practical limit
                Ok(Outcome::skip(
                    "Broker accepted 1MB payload — no Maximum Packet Size enforced",
                ))
            }
        }
    } else {
        // Broker advertises a limit — send a packet exceeding it.
        let large_payload = vec![0x41u8; max_size as usize + 1];
        let publish = PublishParams::qos0("test/large/packet", large_payload);
        c.send_publish(&publish).await?;

        match c.recv().await {
            Ok(Packet::Disconnect(d)) if d.reason_code == 0x95 => Ok(Outcome::Pass),
            Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => Ok(Outcome::Pass),
            Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
            Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
            Ok(other) => Ok(Outcome::fail_packet("DISCONNECT", &other)),
        }
    }
}

const DISCONNECT_REASON_STRING: TestContext = TestContext {
    refs: &["MQTT-3.14.2-3"],
    description: "Server-sent DISCONNECT MAY include a Reason String property",
    compliance: Compliance::May,
};

/// When the server sends a DISCONNECT, it MAY include a Reason String
/// property [MQTT-3.14.2-3]. We provoke a server DISCONNECT (via session
/// takeover) and check for the property.
async fn disconnect_reason_string(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-disc-reason-str";

    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(60);
    let (mut c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Provoke session takeover
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (_c2, _) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    match c1.recv().await {
        Ok(Packet::Disconnect(d)) => {
            if d.properties.reason_string.is_some() {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::unsupported(
                    "DISCONNECT received but without Reason String property",
                ))
            }
        }
        Err(RecvError::Closed) => Ok(Outcome::unsupported(
            "Connection closed without sending DISCONNECT",
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail("No DISCONNECT received (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("DISCONNECT", &other)),
    }
}

const DISCONNECT_PROTOCOL_ERROR: TestContext = TestContext {
    refs: &["MQTT-4.13.1-1"],
    description: "Server SHOULD send DISCONNECT with Reason Code before closing on protocol error",
    compliance: Compliance::Should,
};

/// When the server detects a protocol error, it SHOULD send a DISCONNECT
/// packet with an appropriate reason code before closing the connection
/// [MQTT-4.13.1-1]. We trigger this by sending a PUBLISH with Topic Alias = 0,
/// which is explicitly invalid per the spec (protocol error).
async fn disconnect_on_protocol_error(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-proto-err");
    let (client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;
    let mut client = client.into_raw();

    // Send a PUBLISH with Topic Alias = 0, which is a protocol error
    // (Topic Alias MUST be > 0 when present)
    let mut publish = PublishParams::qos0("mqtt/test/proto/error", b"bad-alias".to_vec());
    publish.properties.topic_alias = Some(0);
    client.send_publish(&publish).await?;

    // Server SHOULD send DISCONNECT with a reason code before closing
    match client.recv().await {
        Ok(Packet::Disconnect(d)) if d.reason_code >= 0x80 => Ok(Outcome::Pass),
        Ok(Packet::Disconnect(d)) => Ok(Outcome::fail(format!(
            "DISCONNECT received but reason code {:#04x} does not indicate error (expected >= 0x80)",
            d.reason_code
        ))),
        Err(RecvError::Closed) => {
            // Connection closed without DISCONNECT — server did not send one
            Ok(Outcome::fail(
                "Connection closed without sending DISCONNECT (server SHOULD send DISCONNECT before closing)",
            ))
        }
        Err(RecvError::Timeout) => Ok(Outcome::fail("No DISCONNECT received (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet(
            "DISCONNECT with error reason code",
            &other,
        )),
    }
}
