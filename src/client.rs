//! Raw MQTT v5 client with TCP and TLS transport.
//!
//! Wraps a transport stream and provides typed send / raw-bytes send /
//! receive-with-timeout methods. Each compliance test creates its own client
//! so that tests are fully isolated.

use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types as rustls_pki_types;

use crate::codec::{
    self, ConnectParams, Packet, Properties, Publish, PublishParams, SubscribeParams,
    UnsubscribeParams,
};
use crate::types::Outcome;

// ── RecvError ────────────────────────────────────────────────────────────────

/// Distinguishes the reasons a [`RawClient::recv`] call can fail.
///
/// Tests match on these variants to decide whether an error counts as
/// "broker disconnected" (expected in malformed-packet tests) or
/// "timed out" (broker ignored the packet — a compliance failure).
#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    /// The configured timeout elapsed with no complete packet received.
    #[error("timed out waiting for broker packet")]
    Timeout,
    /// The broker closed the TCP connection (read returned 0 bytes).
    #[error("broker closed the connection")]
    Closed,
    /// Any other I/O or decode error.
    #[error("{0:#}")]
    Other(anyhow::Error),
}
pub use crate::ws::{WsFramer, WsUpgradeResult};

use crate::ws::WsStream;

// ── Transport ───────────────────────────────────────────────────────────────

/// Abstraction over TCP, TLS, and WebSocket transports.
#[allow(clippy::large_enum_variant)]
enum Transport {
    Tcp(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    WebSocket(WsStream),
}

impl Transport {
    /// Non-blocking write used in `AutoDisconnect::drop`. Returns the number
    /// of bytes written (best-effort; failures are silently ignored).
    fn try_write(&self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Tcp(s) => s.try_write(buf),
            Transport::Tls(s) => {
                let (tcp, _) = s.get_ref();
                tcp.try_write(buf)
            }
            Transport::WebSocket(ws) => {
                // Wrap in a WebSocket binary frame for the non-blocking best-effort write
                let frame = WsFramer::encode_binary_frame(buf);
                ws.tcp.try_write(&frame)
            }
        }
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Transport::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Transport::WebSocket(ws) => Pin::new(ws).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Transport::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Transport::WebSocket(ws) => Pin::new(ws).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_flush(cx),
            Transport::Tls(s) => Pin::new(s).poll_flush(cx),
            Transport::WebSocket(ws) => Pin::new(ws).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Transport::WebSocket(ws) => Pin::new(ws).poll_shutdown(cx),
        }
    }
}

// ── TLS configuration ───────────────────────────────────────────────────────

/// TLS configuration for connecting to a broker over TLS.
#[derive(Clone)]
pub struct TlsConfig {
    pub connector: tokio_rustls::TlsConnector,
    pub server_name: rustls_pki_types::ServerName<'static>,
}

impl TlsConfig {
    /// Build a TLS config from optional cert paths.
    ///
    /// - `ca_cert`: path to PEM CA certificate (None = use no custom CA)
    /// - `insecure`: skip server certificate verification
    /// - `server_name`: SNI hostname (extracted from broker address)
    pub fn build(
        ca_cert: Option<&std::path::Path>,
        insecure: bool,
        server_name: &str,
    ) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();

        if let Some(ca_path) = ca_cert {
            use rustls_pki_types::pem::PemObject;
            let certs = rustls_pki_types::CertificateDer::pem_file_iter(ca_path)
                .with_context(|| format!("cannot open CA cert: {}", ca_path.display()))?;
            for cert in certs {
                let cert = cert.context("failed to parse CA certificate")?;
                root_store
                    .add(cert)
                    .context("failed to add CA certificate")?;
            }
        }

        let config = if insecure {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let sni = rustls_pki_types::ServerName::try_from(server_name.to_string())
            .with_context(|| format!("invalid server name for TLS SNI: {server_name}"))?;

        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
            server_name: sni,
        })
    }
}

/// Certificate verifier that accepts any certificate (for `--insecure`).
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── RawClient ───────────────────────────────────────────────────────────────

pub struct RawClient {
    stream: Transport,
    read_buf: BytesMut,
    recv_timeout: Duration,
}

impl RawClient {
    /// Open a plain TCP connection. Does *not* send CONNECT.
    pub async fn connect_tcp(addr: &str, recv_timeout: Duration) -> Result<Self> {
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {addr} failed"))?;

        Ok(Self {
            stream: Transport::Tcp(tcp),
            read_buf: BytesMut::with_capacity(4096),
            recv_timeout,
        })
    }

    /// Open a TLS connection. Does *not* send CONNECT.
    pub async fn connect_tls(addr: &str, tls: &TlsConfig, recv_timeout: Duration) -> Result<Self> {
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {addr} failed"))?;
        let tls_stream = tls
            .connector
            .connect(tls.server_name.clone(), tcp)
            .await
            .context("TLS handshake failed")?;
        Ok(Self {
            stream: Transport::Tls(tls_stream),
            read_buf: BytesMut::with_capacity(4096),
            recv_timeout,
        })
    }

    /// Open a WebSocket connection. Performs the HTTP upgrade handshake.
    /// Does *not* send CONNECT. Returns the upgrade result alongside the client.
    pub async fn connect_ws(
        addr: &str,
        host: &str,
        path: &str,
        recv_timeout: Duration,
    ) -> Result<(Self, WsUpgradeResult)> {
        let mut tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {addr} failed"))?;

        let upgrade_result = crate::ws::ws_upgrade(&mut tcp, host, path)
            .await
            .context("WebSocket upgrade failed")?;

        let client = Self {
            stream: Transport::WebSocket(WsStream::new(tcp)),
            read_buf: BytesMut::with_capacity(4096),
            recv_timeout,
        };

        Ok((client, upgrade_result))
    }

    // ── Typed sends ──────────────────────────────────────────────────────────

    pub async fn send_connect(&mut self, params: &ConnectParams) -> Result<()> {
        self.send_raw(&codec::encode_connect(params)).await
    }

    pub async fn send_publish(&mut self, params: &PublishParams) -> Result<()> {
        self.send_raw(&codec::encode_publish(params)).await
    }

    /// Send PUBACK for a received QoS-1 PUBLISH.
    pub async fn send_puback(&mut self, packet_id: u16, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_pub_response(4, packet_id, reason_code))
            .await
    }

    /// Send PUBREC for a received QoS-2 PUBLISH.
    #[allow(dead_code)]
    pub async fn send_pubrec(&mut self, packet_id: u16, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_pub_response(5, packet_id, reason_code))
            .await
    }

    /// Send PUBREL in response to a PUBREC.
    pub async fn send_pubrel(&mut self, packet_id: u16, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_pub_response(6, packet_id, reason_code))
            .await
    }

    /// Send PUBCOMP in response to a PUBREL.
    #[allow(dead_code)]
    pub async fn send_pubcomp(&mut self, packet_id: u16, reason_code: u8) -> Result<()> {
        self.send_raw(&codec::encode_pub_response(7, packet_id, reason_code))
            .await
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

    pub async fn send_disconnect_with_properties(
        &mut self,
        reason_code: u8,
        properties: &Properties,
    ) -> Result<()> {
        self.send_raw(&codec::encode_disconnect_with_properties(
            reason_code,
            properties,
        ))
        .await
    }

    pub async fn send_auth(&mut self, reason_code: u8, properties: &Properties) -> Result<()> {
        self.send_raw(&codec::encode_auth(reason_code, properties))
            .await
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

    /// Wait up to the client's configured timeout for the next complete packet.
    pub async fn recv(&mut self) -> Result<Packet, RecvError> {
        self.recv_with_timeout(self.recv_timeout).await
    }

    /// Wait up to a custom timeout for the next complete packet.
    pub async fn recv_with_timeout(&mut self, wait: Duration) -> Result<Packet, RecvError> {
        trace!(timeout_ms = wait.as_millis() as u64, "waiting for packet");
        let packet = match timeout(wait, self.recv_inner()).await {
            Err(_) => return Err(RecvError::Timeout),
            Ok(result) => result?,
        };
        debug!(packet = %packet, "received");
        Ok(packet)
    }

    async fn recv_inner(&mut self) -> Result<Packet, RecvError> {
        loop {
            // Try to parse what we already have buffered.
            match codec::decode_packet(&self.read_buf) {
                Ok(Some((packet, consumed))) => {
                    let _ = self.read_buf.split_to(consumed);
                    return Ok(packet);
                }
                Ok(None) => {}
                Err(e) => return Err(RecvError::Other(anyhow::anyhow!("decode error: {e}"))),
            }

            // Need more bytes from the broker.
            let mut tmp = [0u8; 4096];
            let n =
                self.stream.read(&mut tmp).await.map_err(|e| {
                    RecvError::Other(anyhow::anyhow!("read from broker failed: {e}"))
                })?;
            trace!(bytes = n, "read from socket");
            if n == 0 {
                debug!("broker closed the connection");
                return Err(RecvError::Closed);
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
            // For TLS connections, try_write sends on the raw TCP socket
            // which is best-effort (the TLS layer won't encrypt it, but
            // the connection is being torn down anyway).
            let _ = inner.stream.try_write(&[0xE0, 0x00]);
        }
    }
}

/// Send CONNECT on an already-opened client and return (AutoDisconnect, CONNACK).
async fn handshake(
    mut client: RawClient,
    params: &ConnectParams,
) -> Result<(AutoDisconnect, crate::codec::ConnAck)> {
    client.send_connect(params).await?;
    match client.recv().await? {
        Packet::ConnAck(connack) => Ok((AutoDisconnect(Some(client)), connack)),
        other => bail!("expected CONNACK, got {other}"),
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
    let client = RawClient::connect_tcp(addr, recv_timeout).await?;
    handshake(client, params).await
}

/// Convenience: open TLS, send CONNECT, return the client and the CONNACK.
pub async fn connect_tls(
    addr: &str,
    params: &ConnectParams,
    tls: &TlsConfig,
    recv_timeout: Duration,
) -> Result<(AutoDisconnect, crate::codec::ConnAck)> {
    debug!(addr, client_id = %params.client_id, "CONNECT (TLS)");
    let client = RawClient::connect_tls(addr, tls, recv_timeout).await?;
    handshake(client, params).await
}

/// Convenience: open WebSocket, send CONNECT, return the client, CONNACK, and upgrade result.
pub async fn connect_ws(
    addr: &str,
    host: &str,
    path: &str,
    params: &ConnectParams,
    recv_timeout: Duration,
) -> Result<(AutoDisconnect, crate::codec::ConnAck, WsUpgradeResult)> {
    debug!(addr, client_id = %params.client_id, "CONNECT (WebSocket)");
    let (client, upgrade) = RawClient::connect_ws(addr, host, path, recv_timeout).await?;
    let (auto, connack) = handshake(client, params).await?;
    Ok((auto, connack, upgrade))
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
    client.recv().await?; // SUBACK

    Ok(client)
}

/// Convenience: create a subscriber + publisher pair for a given topic.
///
/// Builds client IDs by appending `-sub` and `-pub` to `id_prefix`.
/// The subscriber connects, subscribes at the given QoS, and consumes the
/// SUBACK. The publisher connects with a plain `ConnectParams`. Returns
/// `(subscriber, publisher)` — both wrapped in `AutoDisconnect`.
pub async fn sub_pub_pair(
    addr: &str,
    id_prefix: &str,
    topic: &str,
    sub_qos: codec::QoS,
    recv_timeout: Duration,
) -> Result<(AutoDisconnect, AutoDisconnect)> {
    let sub_id = format!("{id_prefix}-sub");
    let pub_id = format!("{id_prefix}-pub");
    let sub = connect_and_subscribe(addr, &sub_id, topic, sub_qos, recv_timeout).await?;
    let pub_params = ConnectParams::new(&pub_id);
    let (pub_client, _) = connect(addr, &pub_params, recv_timeout).await?;
    Ok((sub, pub_client))
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
