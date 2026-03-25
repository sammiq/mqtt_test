//! Minimal WebSocket client for MQTT-over-WebSocket compliance testing.
//!
//! Provides the HTTP upgrade handshake, binary/text frame encoding, and
//! transparent frame decoding via `AsyncRead`/`AsyncWrite` on [`WsStream`].

use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Result, bail};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

// ── Upgrade handshake ────────────────────────────────────────────────────────

/// Result of the WebSocket HTTP upgrade handshake.
pub struct WsUpgradeResult {
    /// The subprotocol returned by the server in `Sec-WebSocket-Protocol`.
    pub subprotocol: Option<String>,
}

/// Perform a WebSocket upgrade handshake over an existing TCP stream.
/// Returns the upgrade result (including subprotocol) on success.
pub async fn ws_upgrade(stream: &mut TcpStream, host: &str, path: &str) -> Result<WsUpgradeResult> {
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

// ── Frame codec ──────────────────────────────────────────────────────────────

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

// ── WsStream ─────────────────────────────────────────────────────────────────

/// A WebSocket-wrapped TCP stream that transparently frames/deframes
/// binary WebSocket data, so the MQTT codec layer works unchanged.
pub(crate) struct WsStream {
    pub(crate) tcp: TcpStream,
    framer: WsFramer,
}

impl WsStream {
    pub(crate) fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            framer: WsFramer::new(),
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let ws = self.get_mut();

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

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Wrap the application data in a WebSocket binary frame
        let frame = WsFramer::encode_binary_frame(buf);
        match Pin::new(&mut self.get_mut().tcp).poll_write(cx, &frame) {
            Poll::Ready(Ok(_)) => {
                // Report that we consumed all application bytes
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}
