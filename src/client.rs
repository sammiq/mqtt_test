//! Raw MQTT v5 TCP client.
//!
//! Wraps a `tokio::net::TcpStream` and provides typed send / raw-bytes send /
//! receive-with-timeout methods. Each compliance test creates its own client
//! so that tests are fully isolated.

use std::ops::{Deref, DerefMut};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::codec::{
    self, ConnectParams, Packet, Properties, PublishParams, SubscribeParams, UnsubscribeParams,
};

pub struct RawClient {
    stream:   TcpStream,
    read_buf: BytesMut,
}

impl RawClient {
    /// Open a TCP connection. Does *not* send CONNECT.
    pub async fn connect_tcp(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {addr} failed"))?;
        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
        })
    }

    // ── Typed sends ──────────────────────────────────────────────────────────

    pub async fn send_connect(&mut self, params: &ConnectParams) -> Result<()> {
        self.send_raw(&codec::encode_connect(params)).await
    }

    pub async fn send_publish(&mut self, params: &PublishParams) -> Result<()> {
        self.send_raw(&codec::encode_publish(params)).await
    }

    /// Send PUBACK for a received QoS-1 PUBLISH.
    #[allow(dead_code)]
    pub async fn send_puback(&mut self, packet_id: u16, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_pub_response(4, packet_id, reason_code)).await
    }

    /// Send PUBREC for a received QoS-2 PUBLISH.
    #[allow(dead_code)]
    pub async fn send_pubrec(&mut self, packet_id: u16, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_pub_response(5, packet_id, reason_code)).await
    }

    /// Send PUBREL in response to a PUBREC.
    pub async fn send_pubrel(&mut self, packet_id: u16, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_pub_response(6, packet_id, reason_code)).await
    }

    pub async fn send_subscribe(&mut self, params: &SubscribeParams) -> Result<()> {
        self.send_raw(&codec::encode_subscribe(params)).await
    }

    pub async fn send_unsubscribe(&mut self, params: &UnsubscribeParams) -> Result<()> {
        self.send_raw(&codec::encode_unsubscribe(params)).await
    }

    pub async fn send_pingreq(&mut self) -> Result<()> {
        self.send_raw(&codec::encode_pingreq()).await
    }

    pub async fn send_disconnect(&mut self, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_disconnect(reason_code)).await
    }

    #[allow(dead_code)]
    pub async fn send_disconnect_with_properties(&mut self, reason_code: u8, properties: &Properties) -> Result<()> {
        self.send_raw(&codec::encode_disconnect_with_properties(reason_code, properties)).await
    }

    #[allow(dead_code)]
    pub async fn send_auth(&mut self, reason_code: u8, properties: &Properties) -> Result<()> {
        self.send_raw(&codec::encode_auth(reason_code, properties)).await
    }

    // ── Raw send (for negative / malformed-packet tests) ─────────────────────

    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        trace!(len = bytes.len(), "sending {} raw bytes", bytes.len());
        self.stream
            .write_all(bytes)
            .await
            .context("write to broker failed")?;
        Ok(())
    }

    // ── Receive ──────────────────────────────────────────────────────────────

    /// Wait up to `wait` for the next complete packet from the broker.
    pub async fn recv(&mut self, wait: Duration) -> Result<Packet> {
        trace!(timeout_ms = wait.as_millis() as u64, "waiting for packet");
        let packet = timeout(wait, self.recv_inner())
            .await
            .context("timed out waiting for broker packet")?;
        if let Ok(ref p) = packet {
            debug!(packet = %p, "received");
        }
        packet
    }

    async fn recv_inner(&mut self) -> Result<Packet> {
        loop {
            // Try to parse what we already have buffered.
            match codec::decode_packet(&self.read_buf) {
                Ok(Some((packet, consumed))) => {
                    let _ = self.read_buf.split_to(consumed);
                    return Ok(packet);
                }
                Ok(None) => {}
                Err(e) => bail!("decode error: {e}"),
            }

            // Need more bytes from the broker.
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await.context("read from broker failed")?;
            trace!(bytes = n, "read from socket");
            if n == 0 {
                debug!("broker closed the connection");
                bail!("broker closed the connection");
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
}

// ── AutoDisconnect wrapper ──────────────────────────────────────────────────

/// Wraps a [`RawClient`] and sends a DISCONNECT (reason 0x00) when dropped.
///
/// Use [`into_raw`](AutoDisconnect::into_raw) to take the inner client without
/// sending DISCONNECT — needed for tests that intentionally drop a connection
/// without a clean shutdown.
pub struct AutoDisconnect(Option<RawClient>);

impl AutoDisconnect {
    /// Take the inner [`RawClient`], preventing the automatic DISCONNECT.
    pub fn into_raw(mut self) -> RawClient {
        self.0.take().expect("AutoDisconnect already consumed")
    }
}

impl Deref for AutoDisconnect {
    type Target = RawClient;
    fn deref(&self) -> &RawClient {
        self.0.as_ref().expect("AutoDisconnect already consumed")
    }
}

impl DerefMut for AutoDisconnect {
    fn deref_mut(&mut self) -> &mut RawClient {
        self.0.as_mut().expect("AutoDisconnect already consumed")
    }
}

impl Drop for AutoDisconnect {
    fn drop(&mut self) {
        if let Some(ref inner) = self.0 {
            // DISCONNECT with reason 0x00: fixed two-byte packet.
            let _ = inner.stream.try_write(&[0xE0, 0x00]);
        }
    }
}

/// Convenience: open TCP, send CONNECT, return the client and the CONNACK.
///
/// Most tests call this rather than managing the handshake themselves.
pub async fn connect(
    addr: &str,
    params: &ConnectParams,
    recv_timeout: Duration,
) -> Result<(AutoDisconnect, crate::codec::ConnAck)> {
    debug!(addr, client_id = %params.client_id, "CONNECT");
    let mut client = RawClient::connect_tcp(addr).await?;
    client.send_connect(params).await?;

    match client.recv(recv_timeout).await? {
        Packet::ConnAck(connack) => Ok((AutoDisconnect(Some(client)), connack)),
        other => bail!("expected CONNACK, got {other}"),
    }
}

/// Convenience: connect with a simple client ID, subscribe to one topic,
/// consume the SUBACK, and return the ready client.
pub async fn connect_and_subscribe(
    addr: &str,
    client_id: &str,
    topic: &str,
    qos: codec::QoS,
    recv_timeout: Duration,
) -> Result<AutoDisconnect> {
    let params = ConnectParams::new(client_id);
    let (mut client, _) = connect(addr, &params, recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, qos);
    client.send_subscribe(&sub).await?;
    client.recv(recv_timeout).await?; // SUBACK

    Ok(client)
}
