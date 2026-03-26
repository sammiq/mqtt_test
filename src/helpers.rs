//! Shared test-assertion helpers.
//!
//! These functions wrap common `recv()` → `Outcome` patterns so that
//! individual test functions only need to handle the success path.

use crate::client::{RawClient, RecvError};
use crate::codec::{Packet, Publish};
use crate::types::Outcome;

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
