//! Shared test-assertion helpers.
//!
//! These functions wrap common `recv()` → `Outcome` patterns so that
//! individual test functions only need to handle the success path.

use crate::client::{RawClient, RecvError};
use crate::codec::{ConnAck, Packet, Publish, PublishParams, SubAck};
use crate::types::Outcome;

/// Check that a CONNACK indicates success (reason code 0x00).
///
/// Returns `Ok(connack)` when the reason code is 0x00, allowing callers
/// to inspect further properties.  Returns `Err(Outcome)` otherwise.
///
/// This is a pure check — no I/O — unlike the async `expect_*` helpers.
pub fn expect_connack_success(connack: ConnAck) -> Result<ConnAck, Outcome> {
    if connack.reason_code == 0x00 {
        Ok(connack)
    } else {
        Err(Outcome::fail(format!(
            "CONNACK reason code {:#04x} (expected 0x00)",
            connack.reason_code
        )))
    }
}

/// Receive the next packet and expect a PUBLISH on `topic`.
///
/// Returns `Ok(publish)` when a PUBLISH with a matching topic arrives.
/// Returns `Err(Outcome)` with an appropriate failure for:
/// - wrong packet type / topic mismatch
/// - `RecvError::Timeout` (broker did not deliver)
/// - `RecvError::Closed` (broker disconnected)
/// - `RecvError::Other` (I/O error)
///
/// Callers inspect the returned [`Publish`] for test-specific assertions
/// and only need to handle the success path.
pub async fn expect_publish(client: &mut RawClient, topic: &str) -> Result<Publish, Outcome> {
    match client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(p),
        Ok(other) => Err(Outcome::fail_packet(
            &format!("PUBLISH on topic \"{topic}\""),
            &other,
        )),
        Err(RecvError::Timeout) => Err(Outcome::fail(format!(
            "no message on topic \"{topic}\" (timed out)"
        ))),
        Err(RecvError::Closed) => Err(Outcome::fail(format!(
            "no message on topic \"{topic}\" (connection closed)"
        ))),
        Err(RecvError::Other(e)) => Err(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

/// Publish a QoS 0 message and expect it back on the same client.
///
/// Shorthand for the common self-loopback pattern: send a PUBLISH, then
/// call [`expect_publish`] to receive the echoed message.  The topic
/// string is used exactly once, eliminating the duplicate-topic typo risk.
///
/// Returns `Ok(publish)` on success so callers can inspect fields
/// (payload, properties, retain, etc.).
pub async fn publish_and_expect(
    client: &mut RawClient,
    topic: &str,
    payload: &[u8],
) -> Result<Publish, Outcome> {
    client
        .send_publish(&PublishParams::qos0(topic, payload.to_vec()))
        .await
        .map_err(|e| Outcome::fail(format!("failed to send PUBLISH: {e:#}")))?;
    expect_publish(client, topic).await
}

/// Receive the next packet and expect a SUBACK with all-success reason codes.
///
/// Returns `Ok(suback)` when a SUBACK arrives with every reason code < 0x80.
/// Returns `Err(Outcome)` for:
/// - wrong packet type
/// - any reason code >= 0x80 (subscription rejected)
/// - `RecvError::Timeout` / `Closed` / `Other`
///
/// Callers that need to inspect the SUBACK further (e.g. granted QoS,
/// reason code count) can use the returned [`SubAck`].
pub async fn expect_suback(client: &mut RawClient) -> Result<SubAck, Outcome> {
    match client.recv().await {
        Ok(Packet::SubAck(ack)) => {
            if ack.reason_codes.iter().all(|&c| c < 0x80) {
                Ok(ack)
            } else {
                Err(Outcome::fail(format!(
                    "SUBACK reason code indicates failure: {:?}",
                    ack.reason_codes
                )))
            }
        }
        Ok(other) => Err(Outcome::fail_packet("SUBACK", &other)),
        Err(RecvError::Timeout) => Err(Outcome::fail("no SUBACK received (timed out)")),
        Err(RecvError::Closed) => Err(Outcome::fail("no SUBACK received (connection closed)")),
        Err(RecvError::Other(e)) => Err(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

/// Expect the broker to either send DISCONNECT or close the connection.
///
/// - Connection closed → pass (broker rejected the packet).
/// - DISCONNECT packet → pass.
/// - Timeout → fail (broker ignored the malformed packet).
/// - Other error → fail (unexpected).
pub async fn expect_disconnect(client: &mut RawClient) -> Outcome {
    match client.recv().await {
        Err(RecvError::Closed) => Outcome::Pass,
        Err(RecvError::Timeout) => Outcome::fail("broker did not disconnect (timed out)"),
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
        Ok(Packet::Disconnect(_)) => Outcome::Pass,
        Ok(other) => Outcome::fail_packet("disconnect or connection close", &other),
    }
}

/// Expect a protocol-error DISCONNECT (reason >= 0x80), with close treated as inconclusive.
///
/// This is stricter than [`expect_disconnect`]: some MUST tests require not only
/// a disconnect, but an explicit protocol-error signal from the broker.
///
/// - DISCONNECT with reason >= 0x80 -> pass.
/// - DISCONNECT with reason < 0x80 -> fail.
/// - Connection close without DISCONNECT -> skip (inconclusive for reason-code checks).
/// - Timeout / Other error / wrong packet -> fail.
pub async fn expect_protocol_error_disconnect(client: &mut RawClient, context: &str) -> Outcome {
    match client.recv().await {
        Ok(Packet::Disconnect(d)) if d.reason_code >= 0x80 => Outcome::Pass,
        Ok(Packet::Disconnect(d)) => Outcome::fail(format!(
            "{context}: expected DISCONNECT with error reason (>= 0x80), got {:#04x}",
            d.reason_code
        )),
        Err(RecvError::Closed) => Outcome::skip(format!(
            "{context}: connection closed without DISCONNECT; cannot verify reason code"
        )),
        Err(RecvError::Timeout) => {
            Outcome::fail(format!("{context}: broker did not disconnect (timed out)"))
        }
        Err(RecvError::Other(e)) => {
            Outcome::fail(format!("{context}: unexpected transport error: {e:#}"))
        }
        Ok(other) => Outcome::fail_packet("DISCONNECT with error reason code", &other),
    }
}

/// Expect the broker to reject a malformed CONNECT packet.
///
/// For malformed CONNECT packets, the server MUST close the Network Connection
/// [MQTT-3.1.4-1] and MAY send a CONNACK with Reason Code >= 0x80 before
/// closing [MQTT-3.1.4-2].
///
/// - Connection closed → pass.
/// - CONNACK with reason >= 0x80 → wait for connection close (MUST).
/// - CONNACK with reason 0x00 → fail (broker accepted malformed CONNECT).
/// - Timeout → fail (broker ignored the malformed packet).
pub async fn expect_connect_reject(client: &mut RawClient) -> Outcome {
    match client.recv().await {
        Err(RecvError::Closed) => Outcome::Pass,
        Err(RecvError::Timeout) => Outcome::fail("broker did not disconnect (timed out)"),
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
        Ok(Packet::ConnAck(ack)) if ack.reason_code >= 0x80 => {
            // Broker rejected — now verify it closes the connection [MQTT-3.1.4-1].
            match client.recv().await {
                Err(RecvError::Closed) => Outcome::Pass,
                Err(RecvError::Timeout) => Outcome::fail(format!(
                    "Broker sent CONNACK(reason=0x{:02X}) but did not close the connection",
                    ack.reason_code,
                )),
                Err(RecvError::Other(e)) => {
                    Outcome::fail(format!("unexpected error after CONNACK: {e:#}"))
                }
                Ok(other) => Outcome::fail_packet("connection close after error CONNACK", &other),
            }
        }
        Ok(Packet::ConnAck(ack)) => Outcome::fail(format!(
            "Expected connection close or error CONNACK, got CONNACK(reason=0x{:02X}, session_present={})",
            ack.reason_code, ack.session_present,
        )),
        Ok(other) => Outcome::fail_packet("connection close or error CONNACK", &other),
    }
}
