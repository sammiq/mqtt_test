//! Broker capability discovery via CONNACK property inspection.
//!
//! These are not compliance checks — they describe what optional MQTT v5 features the broker
//! advertises. A single successful CONNECT yields all CONNACK properties; a second rejected
//! CONNECT exposes Reason String / Server Reference behaviour on rejection.

use std::time::Duration;

use anyhow::Result;

use crate::client::{self, RawClient};
use crate::codec::{ConnectParams, Packet};

pub struct BrokerCapabilities {
    pub maximum_qos: u8,
    pub topic_alias_maximum: u16,
    pub server_keep_alive: Option<u16>,
    pub server_receive_maximum: u16,
    pub maximum_packet_size: Option<u32>,
    pub wildcard_subscription_available: bool,
    pub subscription_ids_available: bool,
    pub shared_subscription_available: bool,
    pub retain_available: bool,
    pub assigned_client_id: bool,
    pub response_information: bool,
    pub reason_string_on_reject: bool,
    pub server_reference_on_reject: bool,
}

impl BrokerCapabilities {
    /// Probe the broker via two CONNECTs: one successful (with empty ClientID and
    /// Request Response Information=1) and one rejected (MQTT v3.1.1 protocol version) to inspect
    /// rejected-CONNACK properties. Returns `Ok(_)` even if either probe yields no useful data.
    pub async fn probe(addr: &str, recv_timeout: Duration) -> Result<Self> {
        let mut params = ConnectParams::new("");
        params.properties.request_response_information = Some(true);
        let (_c, connack) = client::connect(addr, &params, recv_timeout).await?;
        let p = &connack.properties;

        let (reason_string_on_reject, server_reference_on_reject) =
            probe_rejected_connack(addr, recv_timeout).await;

        Ok(Self {
            maximum_qos: p.maximum_qos.unwrap_or(2),
            topic_alias_maximum: p.topic_alias_maximum.unwrap_or(0),
            server_keep_alive: p.server_keep_alive,
            server_receive_maximum: p.receive_maximum.unwrap_or(65535),
            maximum_packet_size: p.maximum_packet_size,
            wildcard_subscription_available: p.wildcard_subscription_available.unwrap_or(true),
            subscription_ids_available: p.subscription_ids_available.unwrap_or(true),
            shared_subscription_available: p.shared_subscription_available.unwrap_or(true),
            retain_available: p.retain_available.unwrap_or(true),
            assigned_client_id: p.assigned_client_id.is_some(),
            response_information: p.response_information.is_some(),
            reason_string_on_reject,
            server_reference_on_reject,
        })
    }

    pub fn print(&self, color: bool) {
        println!("BROKER CAPABILITIES");
        println!("-------------------");
        println!("  Maximum QoS:                 {}", self.maximum_qos);
        println!(
            "  Topic Alias Maximum:         {}",
            self.topic_alias_maximum
        );
        match self.server_keep_alive {
            Some(v) => println!("  Server Keep Alive override:  {v}s"),
            None => println!("  Server Keep Alive override:  (not set)"),
        }
        println!(
            "  Server Receive Maximum:      {}",
            self.server_receive_maximum
        );
        match self.maximum_packet_size {
            Some(v) => println!("  Maximum Packet Size:         {v} bytes"),
            None => println!("  Maximum Packet Size:         unlimited"),
        }
        println!();
        let row = |b: bool, label: &str| println!("  [{}] {label}", yes_no(b, color));
        row(
            self.wildcard_subscription_available,
            "Wildcard Subscriptions",
        );
        row(self.subscription_ids_available, "Subscription Identifiers");
        row(self.shared_subscription_available, "Shared Subscriptions");
        row(self.retain_available, "Retain Available");
        row(
            self.assigned_client_id,
            "Assigned Client Identifier (for empty ClientID)",
        );
        row(
            self.response_information,
            "Response Information returned when requested",
        );
        row(
            self.reason_string_on_reject,
            "Reason String on rejected CONNACK",
        );
        row(
            self.server_reference_on_reject,
            "Server Reference on rejected CONNACK",
        );
    }
}

fn yes_no(b: bool, color: bool) -> String {
    let text = if b { " YES" } else { "  NO" };
    if !color {
        return text.to_string();
    }
    let code = if b { "\x1b[32m" } else { "\x1b[90m" };
    format!("{code}{text}\x1b[0m")
}

/// Send a CONNECT with protocol version 4 (3.1.1) — most v5 brokers reject with 0x84.
/// Returns (reason_string_present, server_reference_present) from the CONNACK if received.
async fn probe_rejected_connack(addr: &str, recv_timeout: Duration) -> (bool, bool) {
    let Ok(mut client) = RawClient::connect_tcp(addr, recv_timeout).await else {
        return (false, false);
    };
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                               // CONNECT fixed header
        0x0C,                               // remaining length = 12
        0x00, 0x04, b'M', b'Q', b'T', b'T', // protocol name "MQTT"
        0x04,                               // protocol version 4 (3.1.1)
        0x02,                               // connect flags: clean start
        0x00, 0x3C,                         // keep alive = 60
        0x00, 0x00,                         // client ID length = 0
    ];
    if client.send_raw(bad_connect).await.is_err() {
        return (false, false);
    }
    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code >= 0x80 => (
            connack.properties.reason_string.is_some(),
            connack.properties.server_reference.is_some(),
        ),
        _ => (false, false),
    }
}
