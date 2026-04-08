//! WebSocket transport compliance tests (MQTT §6).
//!
//! Tests that the broker correctly handles MQTT over WebSocket connections
//! as specified in Section 6 of the MQTT v5.0 specification.

use anyhow::{Context as _, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::client::{self, WsFramer};
use crate::codec::ConnectParams;
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("WEBSOCKET");

    suite.add(WS_SUBPROTOCOL, ws_subprotocol(config));
    suite.add(WS_PACKET_SPANNING, ws_packet_spanning(config));
    suite.add(WS_TEXT_FRAME_REJECTED, ws_text_frame_rejected(config));

    suite
}

// ── MQTT-6.0.0-4: Server MUST return "mqtt" subprotocol ─────────────────────

const WS_SUBPROTOCOL: TestContext = TestContext {
    refs: &["MQTT-6.0.0-4"],
    description: "WebSocket subprotocol returned by server MUST be \"mqtt\"",
    compliance: Compliance::Must,
};

async fn ws_subprotocol(config: TestConfig<'_>) -> Result<Outcome> {
    let Some((ws_addr, ws_host, ws_path)) = config.ws_info else {
        return Ok(Outcome::skip("WebSocket not configured"));
    };

    let params = ConnectParams::new("mqtt-test-ws-subprotocol");
    let (_client, connack, upgrade) =
        client::connect_ws(ws_addr, ws_host, ws_path, &params, config.recv_timeout).await?;

    if connack.reason_code != 0x00 {
        return Ok(Outcome::fail(format!(
            "CONNACK reason code {:#04x} (expected 0x00)",
            connack.reason_code
        )));
    }

    match upgrade.subprotocol.as_deref() {
        Some("mqtt") => Ok(Outcome::Pass),
        Some(other) => Ok(Outcome::fail(format!(
            "server returned subprotocol \"{other}\" instead of \"mqtt\""
        ))),
        None => Ok(Outcome::fail(
            "server did not return a Sec-WebSocket-Protocol header",
        )),
    }
}

// ── MQTT-6.0.0-2: MQTT packets may span WebSocket frames ───────────────────

const WS_PACKET_SPANNING: TestContext = TestContext {
    refs: &["MQTT-6.0.0-2"],
    description: "Server MUST NOT assume MQTT packets are aligned on WebSocket frame boundaries",
    compliance: Compliance::Must,
};

/// Send a CONNECT packet split across two WebSocket binary frames to verify
/// the broker correctly reassembles MQTT packets that span frame boundaries.
async fn ws_packet_spanning(config: TestConfig<'_>) -> Result<Outcome> {
    let Some((ws_addr, ws_host, ws_path)) = config.ws_info else {
        return Ok(Outcome::skip("WebSocket not configured"));
    };

    // Perform WebSocket upgrade manually so we can control framing
    let mut tcp = TcpStream::connect(ws_addr)
        .await
        .with_context(|| format!("TCP connect to {ws_addr} failed"))?;

    ws_upgrade_raw(&mut tcp, ws_host, ws_path).await?;

    // Build the CONNECT packet bytes
    let params = ConnectParams::new("mqtt-test-ws-spanning");
    let connect_bytes = crate::codec::encode_connect(&params);

    // Split the CONNECT packet roughly in half
    let mid = connect_bytes.len() / 2;
    let first_half = &connect_bytes[..mid];
    let second_half = &connect_bytes[mid..];

    // Send each half as a separate WebSocket binary frame
    let frame1 = WsFramer::encode_binary_frame(first_half);
    let frame2 = WsFramer::encode_binary_frame(second_half);

    tcp.write_all(&frame1).await?;
    tcp.write_all(&frame2).await?;

    // Read the response — the broker should reassemble and send CONNACK
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    let result = timeout(config.recv_timeout, async {
        loop {
            let n = tcp.read(&mut tmp).await?;
            if n == 0 {
                bail!("broker closed connection without sending CONNACK");
            }
            buf.extend_from_slice(&tmp[..n]);

            // Try to extract a WebSocket frame containing CONNACK
            if let Some(payload) = try_extract_ws_payload(&buf) {
                // CONNACK is packet type 0x20
                if !payload.is_empty() && (payload[0] & 0xF0) == 0x20 {
                    return Ok(());
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(Outcome::Pass),
        Ok(Err(e)) => Ok(Outcome::fail(format!("{e}"))),
        Err(_) => Ok(Outcome::fail(
            "timed out waiting for CONNACK after split-frame CONNECT",
        )),
    }
}

// ── MQTT-6.0.0-1: Non-binary frame must close connection ───────────────────

const WS_TEXT_FRAME_REJECTED: TestContext = TestContext {
    refs: &["MQTT-6.0.0-1"],
    description: "Server MUST close connection on non-binary WebSocket frame",
    compliance: Compliance::Must,
};

/// After a successful WebSocket upgrade, send a CONNECT packet wrapped in a
/// text frame (opcode 0x01) instead of binary (0x02). The broker MUST close
/// the connection.
async fn ws_text_frame_rejected(config: TestConfig<'_>) -> Result<Outcome> {
    let Some((ws_addr, ws_host, ws_path)) = config.ws_info else {
        return Ok(Outcome::skip("WebSocket not configured"));
    };

    let mut tcp = TcpStream::connect(ws_addr)
        .await
        .with_context(|| format!("TCP connect to {ws_addr} failed"))?;

    ws_upgrade_raw(&mut tcp, ws_host, ws_path).await?;

    // Build CONNECT and send it as a text frame (wrong opcode)
    let params = ConnectParams::new("mqtt-test-ws-text-frame");
    let connect_bytes = crate::codec::encode_connect(&params);
    let text_frame = WsFramer::encode_text_frame(&connect_bytes);
    tcp.write_all(&text_frame).await?;

    // The broker should close the connection. Try reading — we expect
    // either EOF, a WebSocket close frame, or a connection reset.
    let mut tmp = [0u8; 4096];
    let closed = timeout(config.recv_timeout, async {
        loop {
            match tcp.read(&mut tmp).await {
                Ok(0) => return true, // EOF — closed as expected
                Ok(n) => {
                    // Check for WebSocket close frame (opcode 0x08)
                    if (tmp[0] & 0x0F) == 0x08 {
                        return true;
                    }
                    // If we get a valid CONNACK, the broker accepted the text frame
                    if let Some(payload) = try_extract_ws_payload(&tmp[..n])
                        && !payload.is_empty()
                        && (payload[0] & 0xF0) == 0x20
                    {
                        return false;
                    }
                }
                Err(e) => {
                    // Treat connection reset/broken pipe as expected closure.
                    use std::io::ErrorKind;
                    return matches!(
                        e.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::NotConnected
                    );
                }
            }
        }
    })
    .await;

    match closed {
        Ok(true) => Ok(Outcome::Pass),
        Ok(false) => Ok(Outcome::fail(
            "broker accepted CONNECT in a text WebSocket frame instead of closing",
        )),
        Err(_) => Ok(Outcome::fail(
            "broker did not close connection after receiving text WebSocket frame",
        )),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Perform the WebSocket HTTP upgrade handshake directly on a TcpStream.
/// Used by tests that need to control WebSocket framing manually.
async fn ws_upgrade_raw(stream: &mut TcpStream, host: &str, path: &str) -> Result<()> {
    use base64::Engine;

    let key_bytes: [u8; 16] = {
        use std::io::Read;
        let mut kb = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut kb).map(|_| kb))
            .unwrap_or_else(|_| {
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
    let status_line = response.lines().next().unwrap_or("");
    if !status_line.contains("101") {
        bail!("WebSocket upgrade failed: {status_line}");
    }

    // Verify Sec-WebSocket-Accept is present (skip cryptographic validation —
    // it is a client-side security measure, not broker compliance).
    if !response
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("sec-websocket-accept:"))
    {
        bail!("WebSocket upgrade response missing Sec-WebSocket-Accept header");
    }

    Ok(())
}

/// Try to extract the payload from the first WebSocket frame in a buffer.
/// Returns None if the frame is incomplete.
fn try_extract_ws_payload(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }

    let masked = buf[1] & 0x80 != 0;
    let len_byte = (buf[1] & 0x7F) as usize;

    let (payload_len, header_len) = if len_byte < 126 {
        (len_byte, 2)
    } else if len_byte == 126 {
        if buf.len() < 4 {
            return None;
        }
        (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
    } else {
        if buf.len() < 10 {
            return None;
        }
        let len = u64::from_be_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]) as usize;
        (len, 10)
    };

    let mask_len = if masked { 4 } else { 0 };
    let total = header_len + mask_len + payload_len;
    if buf.len() < total {
        return None;
    }

    let payload_start = header_len + mask_len;
    let mut payload = buf[payload_start..payload_start + payload_len].to_vec();

    if masked {
        let mask = &buf[header_len..header_len + 4];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }

    Some(payload)
}
