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
    self, ConnectParams, Packet, Properties, PublishParams, SubscribeParams, UnsubscribeParams,
};

// ── WebSocket support ──────────────────────────────────────────────────────

/// Result of the WebSocket HTTP upgrade handshake.
#[allow(dead_code)]
pub struct WsUpgradeResult {
    /// The subprotocol returned by the server in `Sec-WebSocket-Protocol`.
    pub subprotocol: Option<String>,
}

/// Perform a WebSocket upgrade handshake over an existing TCP stream.
/// Returns the upgrade result (including subprotocol) on success.
async fn ws_upgrade(stream: &mut TcpStream, host: &str, path: &str) -> Result<WsUpgradeResult> {
    use base64::Engine;

    // Generate random 16-byte key, base64-encode it.
    // Read from /dev/urandom for a proper nonce.
    let key_bytes: [u8; 16] = {
        use std::io::Read;
        let mut kb = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut kb).map(|_| kb))
            .unwrap_or_else(|_| {
                // Fallback: use address of a stack variable + time as entropy
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    ^ (&kb as *const _ as u128);
                for (i, b) in kb.iter_mut().enumerate() {
                    *b = (seed.wrapping_shr((i as u32 * 8) % 128)) as u8;
                }
                kb
            })
    };
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

    // Build HTTP upgrade request
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: mqtt\r\n\
         \r\n"
    );

    stream.write_all(request.as_bytes()).await?;

    // Read HTTP response (headers end with \r\n\r\n)
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut tmp = [0u8; 256];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("server closed connection during WebSocket upgrade");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            bail!("WebSocket upgrade response too large");
        }
    }

    let response = String::from_utf8_lossy(&buf);

    // Verify 101 Switching Protocols
    let status_line = response.lines().next().unwrap_or("");
    if !status_line.contains("101") {
        bail!("WebSocket upgrade failed: {status_line}");
    }

    // Verify Sec-WebSocket-Accept is present. We intentionally skip
    // cryptographic validation of the accept hash — it is a client-side
    // security measure (RFC 6455 §4.2.2) and not relevant to broker
    // compliance testing.
    if !response
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("sec-websocket-accept:"))
    {
        bail!("WebSocket upgrade response missing Sec-WebSocket-Accept header");
    }

    // Extract subprotocol
    let subprotocol = response
        .lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with("sec-websocket-protocol:")
        })
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string());

    Ok(WsUpgradeResult { subprotocol })
}

/// Minimal WebSocket framing state for a client connection.
/// Only supports binary frames (opcode 0x02) and close frames (0x08).
/// All client frames are masked as required by RFC 6455.
pub struct WsFramer {
    /// Buffered application data extracted from incoming WebSocket frames.
    pending_read: BytesMut,
    /// Partial frame data waiting for a complete frame.
    partial_frame: BytesMut,
}

impl WsFramer {
    fn new() -> Self {
        Self {
            pending_read: BytesMut::new(),
            partial_frame: BytesMut::new(),
        }
    }

    /// Encode application data as a masked binary WebSocket frame.
    pub fn encode_binary_frame(payload: &[u8]) -> Vec<u8> {
        Self::encode_frame(0x82, payload) // 0x80 (FIN) | 0x02 (binary)
    }

    /// Encode application data as a masked text WebSocket frame.
    pub fn encode_text_frame(payload: &[u8]) -> Vec<u8> {
        Self::encode_frame(0x81, payload) // 0x80 (FIN) | 0x01 (text)
    }

    fn encode_frame(first_byte: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.push(first_byte);

        // Length + mask bit (0x80)
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= 65535 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        // Masking key (use simple counter-based key)
        let mask_key: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        frame.extend_from_slice(&mask_key);

        // Masked payload
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask_key[i % 4]);
        }

        frame
    }

    /// Try to extract application bytes from buffered WebSocket frame data.
    /// Returns Ok(true) if a frame was decoded, Ok(false) if need more data.
    fn try_decode_frame(&mut self) -> Result<bool> {
        let buf = &self.partial_frame;
        if buf.len() < 2 {
            return Ok(false);
        }

        let _fin = buf[0] & 0x80 != 0;
        let opcode = buf[0] & 0x0F;
        let masked = buf[1] & 0x80 != 0;
        let len_byte = (buf[1] & 0x7F) as usize;

        let (payload_len, header_len) = if len_byte < 126 {
            (len_byte, 2)
        } else if len_byte == 126 {
            if buf.len() < 4 {
                return Ok(false);
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        } else {
            if buf.len() < 10 {
                return Ok(false);
            }
            let len = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]) as usize;
            (len, 10)
        };

        let mask_len = if masked { 4 } else { 0 };
        let total = header_len + mask_len + payload_len;
        if buf.len() < total {
            return Ok(false);
        }

        let payload_start = header_len + mask_len;
        let mut payload = buf[payload_start..payload_start + payload_len].to_vec();

        if masked {
            let mask = &buf[header_len..header_len + 4];
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }

        // Consume the frame from partial buffer
        let _ = self.partial_frame.split_to(total);

        match opcode {
            0x01 | 0x02 => {
                // Text or binary frame — deliver as application data
                self.pending_read.extend_from_slice(&payload);
            }
            0x08 => {
                // Close frame
                bail!("broker closed the WebSocket connection");
            }
            0x09 => {
                // Ping — we don't need to respond for testing purposes
            }
            _ => {
                // Ignore other opcodes
            }
        }

        Ok(true)
    }
}

/// A WebSocket-wrapped TCP stream that transparently frames/deframes
/// binary WebSocket data, so the MQTT codec layer works unchanged.
struct WsStream {
    tcp: TcpStream,
    framer: WsFramer,
}

impl WsStream {
    fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            framer: WsFramer::new(),
        }
    }
}

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
            Transport::WebSocket(ws) => {
                // First, deliver any already-decoded application data.
                if !ws.framer.pending_read.is_empty() {
                    let n = std::cmp::min(buf.remaining(), ws.framer.pending_read.len());
                    buf.put_slice(&ws.framer.pending_read.split_to(n));
                    return Poll::Ready(Ok(()));
                }

                // Read raw TCP data into a stack buffer, then append to partial_frame.
                let mut tmp = [0u8; 4096];
                let mut tmp_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut ws.tcp).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let filled = tmp_buf.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        ws.framer.partial_frame.extend_from_slice(filled);

                        // Try to decode frames
                        loop {
                            match ws.framer.try_decode_frame() {
                                Ok(true) => continue,
                                Ok(false) => break,
                                Err(e) => {
                                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                                }
                            }
                        }

                        if !ws.framer.pending_read.is_empty() {
                            let n = std::cmp::min(buf.remaining(), ws.framer.pending_read.len());
                            buf.put_slice(&ws.framer.pending_read.split_to(n));
                            Poll::Ready(Ok(()))
                        } else {
                            // Got TCP data but no complete WS frame yet — need more
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                    other => other,
                }
            }
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
            Transport::WebSocket(ws) => {
                // Wrap the application data in a WebSocket binary frame
                let frame = WsFramer::encode_binary_frame(buf);
                match Pin::new(&mut ws.tcp).poll_write(cx, &frame) {
                    Poll::Ready(Ok(_)) => {
                        // Report that we consumed all application bytes
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_flush(cx),
            Transport::Tls(s) => Pin::new(s).poll_flush(cx),
            Transport::WebSocket(ws) => Pin::new(&mut ws.tcp).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Transport::WebSocket(ws) => Pin::new(&mut ws.tcp).poll_shutdown(cx),
        }
    }
}

// ── TLS configuration ───────────────────────────────────────────────────────

/// TLS configuration for connecting to a broker over TLS.
#[derive(Clone)]
#[allow(dead_code)]
pub struct TlsConfig {
    pub connector: tokio_rustls::TlsConnector,
    pub server_name: rustls_pki_types::ServerName<'static>,
}

#[allow(dead_code)]
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
        use std::io::BufReader;

        let mut root_store = rustls::RootCertStore::empty();

        if let Some(ca_path) = ca_cert {
            let file = std::fs::File::open(ca_path)
                .with_context(|| format!("cannot open CA cert: {}", ca_path.display()))?;
            let mut reader = BufReader::new(file);
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to parse CA certificates")?;
            for cert in certs {
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
#[allow(dead_code)]
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
}

impl RawClient {
    /// Open a plain TCP connection. Does *not* send CONNECT.
    pub async fn connect_tcp(addr: &str) -> Result<Self> {
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {addr} failed"))?;

        Ok(Self {
            stream: Transport::Tcp(tcp),
            read_buf: BytesMut::with_capacity(4096),
        })
    }

    /// Open a TLS connection. Does *not* send CONNECT.
    pub async fn connect_tls(addr: &str, tls: &TlsConfig) -> Result<Self> {
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
        })
    }

    /// Open a WebSocket connection. Performs the HTTP upgrade handshake.
    /// Does *not* send CONNECT. Returns the upgrade result alongside the client.
    pub async fn connect_ws(addr: &str, host: &str) -> Result<(Self, WsUpgradeResult)> {
        let mut tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("TCP connect to {addr} failed"))?;

        let upgrade_result = ws_upgrade(&mut tcp, host, "/")
            .await
            .context("WebSocket upgrade failed")?;

        let client = Self {
            stream: Transport::WebSocket(WsStream::new(tcp)),
            read_buf: BytesMut::with_capacity(4096),
        };

        Ok((client, upgrade_result))
    }

    /// Send raw bytes directly to the underlying TCP stream, bypassing
    /// WebSocket framing. Used for testing invalid frame scenarios.
    #[allow(dead_code)]
    pub async fn send_raw_tcp(&mut self, bytes: &[u8]) -> Result<()> {
        match &mut self.stream {
            Transport::WebSocket(ws) => {
                ws.tcp
                    .write_all(bytes)
                    .await
                    .context("raw TCP write failed")?;
                Ok(())
            }
            _ => bail!("send_raw_tcp only supported on WebSocket transport"),
        }
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
            let n = self
                .stream
                .read(&mut tmp)
                .await
                .context("read from broker failed")?;
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
            // For TLS connections, try_write sends on the raw TCP socket
            // which is best-effort (the TLS layer won't encrypt it, but
            // the connection is being torn down anyway).
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

/// Convenience: open TLS, send CONNECT, return the client and the CONNACK.
pub async fn connect_tls(
    addr: &str,
    params: &ConnectParams,
    tls: &TlsConfig,
    recv_timeout: Duration,
) -> Result<(AutoDisconnect, crate::codec::ConnAck)> {
    debug!(addr, client_id = %params.client_id, "CONNECT (TLS)");
    let mut client = RawClient::connect_tls(addr, tls).await?;
    client.send_connect(params).await?;

    match client.recv(recv_timeout).await? {
        Packet::ConnAck(connack) => Ok((AutoDisconnect(Some(client)), connack)),
        other => bail!("expected CONNACK, got {other}"),
    }
}

/// Convenience: open WebSocket, send CONNECT, return the client, CONNACK, and upgrade result.
#[allow(dead_code)]
pub async fn connect_ws(
    addr: &str,
    host: &str,
    params: &ConnectParams,
    recv_timeout: Duration,
) -> Result<(AutoDisconnect, crate::codec::ConnAck, WsUpgradeResult)> {
    debug!(addr, client_id = %params.client_id, "CONNECT (WebSocket)");
    let (mut client, upgrade) = RawClient::connect_ws(addr, host).await?;
    client.send_connect(params).await?;

    match client.recv(recv_timeout).await? {
        Packet::ConnAck(connack) => Ok((AutoDisconnect(Some(client)), connack, upgrade)),
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
