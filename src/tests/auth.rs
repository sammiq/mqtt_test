//! Enhanced Authentication compliance tests [MQTT-4.12].
//!
//! MQTT v5 defines an optional challenge-response authentication mechanism
//! using AUTH packets exchanged between client and server during connection.
//!
//! Most brokers (including Mosquitto) do **not** implement enhanced authentication.
//! Tests that require a multi-step AUTH exchange will skip gracefully when the
//! broker rejects the authentication method. To fully exercise this suite, use a
//! broker configured with a challenge-response auth plugin (e.g. SCRAM-SHA-256).

use std::time::Duration;

use anyhow::Result;

use crate::client::{RawClient, RecvError};
use crate::codec::{ConnectParams, Packet, Properties};
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("ENHANCED AUTH");

    suite.add(BAD_AUTH_METHOD, bad_auth_method(config));
    suite.add(NO_AUTH_NO_AUTH_PACKET, no_auth_no_auth_packet(config));
    suite.add(AUTH_CONTINUE, auth_continue(config));
    suite.add(AUTH_METHOD_CONSISTENT, auth_method_consistent(config));
    suite.add(FULL_EXCHANGE, full_exchange(config));
    suite.add(REAUTH, reauth(config));
    suite.add(REAUTH_FAIL, reauth_fail(config));

    suite
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const AUTH_METHOD: &str = "SCRAM-SHA-256";
const SKIP_MSG: &str = "Broker does not support enhanced authentication";

/// Build an AUTH response Properties with the standard test method and data.
fn auth_response(data: &[u8]) -> Properties {
    Properties {
        authentication_method: Some(AUTH_METHOD.into()),
        authentication_data: Some(data.to_vec()),
        ..Default::default()
    }
}

/// Build a ConnectParams requesting enhanced auth with the test method.
fn auth_connect_params(client_id: &str) -> ConnectParams {
    let mut params = ConnectParams::new(client_id);
    params.properties.authentication_method = Some(AUTH_METHOD.into());
    params.properties.authentication_data = Some(b"client-first-data".to_vec());
    params
}

/// Drive the initial auth exchange to completion, returning the connected client.
///
/// Returns `Ok(client)` on successful authentication.
/// Returns `Err(Outcome::Skip)` if the broker rejects the auth method.
/// Returns `Err(Outcome::Fail)` if the handshake fails unexpectedly or I/O fails.
async fn complete_auth_exchange(
    config: TestConfig<'_>,
    client_id: &str,
) -> std::result::Result<RawClient, Outcome> {
    let params = auth_connect_params(client_id);
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout)
        .await
        .map_err(|e| Outcome::fail(format!("failed to connect: {e:#}")))?;
    client
        .send_connect(&params)
        .await
        .map_err(|e| Outcome::fail(format!("failed to send CONNECT: {e:#}")))?;

    loop {
        match client.recv().await {
            Err(RecvError::Closed) => return Err(Outcome::skip(SKIP_MSG)),
            Err(RecvError::Timeout) => {
                return Err(Outcome::fail(
                    "broker did not respond during auth exchange (timed out)",
                ));
            }
            Err(RecvError::Other(e)) => {
                return Err(Outcome::fail(format!("auth exchange error: {e:#}")));
            }
            Ok(packet) => match packet {
                Packet::Auth {
                    reason_code: 0x18, ..
                } => {
                    client
                        .send_auth(0x18, &auth_response(b"client-response"))
                        .await
                        .map_err(|e| Outcome::fail(format!("failed to send AUTH: {e:#}")))?;
                }
                Packet::ConnAck(connack) if connack.reason_code == 0x00 => {
                    return Ok(client);
                }
                Packet::ConnAck(connack)
                    if connack.reason_code == 0x8C || connack.reason_code == 0x87 =>
                {
                    return Err(Outcome::skip(SKIP_MSG));
                }
                other => {
                    return Err(Outcome::fail_packet(
                        "AUTH(0x18) or CONNACK(0x00/0x8C/0x87)",
                        &other,
                    ));
                }
            },
        }
    }
}

// ── Tests that work without an auth plugin ──────────────────────────────────

const BAD_AUTH_METHOD: TestContext = TestContext {
    refs: &["MQTT-4.12.0-1", "MQTT-4.12.0-4"],
    description: "If server does not support the Authentication Method supplied by client, it MAY send a CONNACK with a Reason Code of 0x8C (Bad authentication method) or 0x87 (Not Authorized) as described in section 4.13 and MUST close the Network Connection",
    compliance: Compliance::Must,
};

/// Send CONNECT with an unsupported Authentication Method. The server MAY send
/// CONNACK with 0x8C (Bad authentication method) or 0x87 (Not Authorized) and
/// If the Server does not support the Authentication Method supplied by the Client, it MAY send a CONNACK with a Reason Code of 0x8C (Bad authentication method) or 0x87 (Not Authorized) as described in section 4.13 and MUST close the Network Connection. [MQTT-4.12.0-1].
async fn bad_auth_method(config: TestConfig<'_>) -> Result<Outcome> {
    // Probe: verify the broker is accepting MQTT connections before testing.
    // Without this, a connection reset from an unready broker would be
    // indistinguishable from a legitimate rejection of the bad auth method.
    let probe = ConnectParams::new("mqtt-test-auth-probe");
    let (probe_client, _) = crate::client::connect(config.addr, &probe, config.recv_timeout)
        .await
        .map_err(|e| anyhow::anyhow!("broker not reachable (probe failed): {e:#}"))?;
    drop(probe_client);

    let mut params = ConnectParams::new("mqtt-test-auth-bad-method");
    params.properties.authentication_method = Some("BOGUS-AUTH-METHOD-12345".into());

    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack))
            if connack.reason_code == 0x8C || connack.reason_code == 0x87 =>
        {
            Ok(Outcome::Pass)
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => Ok(Outcome::fail(
            "Broker accepted CONNECT with unsupported Authentication Method",
        )),
        Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => {
            // Connection closed (possibly without CONNACK) — the MUST to close is satisfied,
            // though a CONNACK before close is preferred. Pass since the spec says "MAY send CONNACK".
            Ok(Outcome::Pass)
        }
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not close connection (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Auth { .. }) => Ok(Outcome::fail(
            "Broker sent AUTH for unsupported method instead of rejecting",
        )),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK (reject)", &other)),
    }
}

const NO_AUTH_NO_AUTH_PACKET: TestContext = TestContext {
    refs: &["MQTT-4.12.0-6"],
    description: "If client does not include an Authentication Method in the CONNECT, server MUST NOT send an AUTH packet",
    compliance: Compliance::Must,
};

/// A plain CONNECT (no Authentication Method) must never trigger an AUTH packet
/// If the Client does not include an Authentication Method in the CONNECT, the Server MUST NOT send an AUTH packet, and it MUST NOT send an Authentication Method in the CONNACK packet. [MQTT-4.12.0-6].
/// first response is CONNACK, not AUTH.
async fn no_auth_no_auth_packet(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-auth-no-method");
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    match client.recv().await? {
        Packet::ConnAck(connack) if connack.reason_code == 0x00 => {
            if connack.properties.authentication_method.is_some() {
                return Ok(Outcome::fail(
                    "CONNACK included Authentication Method despite client not requesting it",
                ));
            }
            let _ = client.send_disconnect(0x00).await;
            Ok(Outcome::Pass)
        }
        Packet::ConnAck(_) => {
            // Connection rejected for other reasons — still no AUTH, so pass
            Ok(Outcome::Pass)
        }
        Packet::Auth { .. } => Ok(Outcome::fail(
            "Server sent AUTH packet despite no Authentication Method in CONNECT",
        )),
        other => Ok(Outcome::fail_packet("CONNACK", &other)),
    }
}

// ── Tests that require a broker with enhanced auth support ──────────────────
//
// These tests skip when the broker rejects the auth method, which is the
// common case for brokers like Mosquitto that don't implement enhanced auth.

const AUTH_CONTINUE: TestContext = TestContext {
    refs: &["MQTT-4.12.0-2"],
    description: "If server requires additional information to complete the authorization, it can send an AUTH packet to client",
    compliance: Compliance::Must,
};

/// Server sends AUTH rc=0x18 to request additional authentication data
/// If the Server requires additional information to complete the authorization, it can send an AUTH packet to the Client. This packet MUST contain a Reason Code of 0x18 (Continue authentication). [MQTT-4.12.0-2].
async fn auth_continue(config: TestConfig<'_>) -> Result<Outcome> {
    let params = auth_connect_params("mqtt-test-auth-continue");
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    match client.recv().await {
        Ok(Packet::Auth {
            reason_code: 0x18, ..
        }) => {
            let _ = client.send_disconnect(0x00).await;
            Ok(Outcome::Pass)
        }
        Ok(Packet::ConnAck(connack))
            if connack.reason_code == 0x8C || connack.reason_code == 0x87 =>
        {
            Ok(Outcome::skip(SKIP_MSG))
        }
        Err(RecvError::Closed) => Ok(Outcome::skip(SKIP_MSG)),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "broker did not respond to CONNECT (timed out)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("AUTH(rc=0x18)", &other)),
    }
}

const AUTH_METHOD_CONSISTENT: TestContext = TestContext {
    refs: &["MQTT-4.12.0-5"],
    description: "If the initial CONNECT packet included an Authentication Method property then all AUTH packets",
    compliance: Compliance::Must,
};

/// Every AUTH packet and the final CONNACK must carry the same Authentication
/// If the initial CONNECT packet included an Authentication Method property then all AUTH packets, and any successful CONNACK packet MUST include an Authentication Method Property with the same value as in the CONNECT packet. [MQTT-4.12.0-5].
async fn auth_method_consistent(config: TestConfig<'_>) -> Result<Outcome> {
    let params = auth_connect_params("mqtt-test-auth-consistent");
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    loop {
        match client.recv().await? {
            Packet::Auth {
                reason_code: 0x18,
                ref properties,
            } => match &properties.authentication_method {
                Some(m) if m == AUTH_METHOD => {
                    client
                        .send_auth(0x18, &auth_response(b"client-response"))
                        .await?;
                }
                Some(m) => {
                    return Ok(Outcome::fail(format!(
                        "AUTH contained Authentication Method \"{m}\", expected \"{AUTH_METHOD}\""
                    )));
                }
                None => {
                    return Ok(Outcome::fail(
                        "AUTH packet missing Authentication Method property",
                    ));
                }
            },
            Packet::ConnAck(ref connack) if connack.reason_code == 0x00 => {
                match &connack.properties.authentication_method {
                    Some(m) if m == AUTH_METHOD => {
                        let _ = client.send_disconnect(0x00).await;
                        return Ok(Outcome::Pass);
                    }
                    Some(m) => {
                        return Ok(Outcome::fail(format!(
                            "CONNACK contained Authentication Method \"{m}\", expected \"{AUTH_METHOD}\""
                        )));
                    }
                    None => {
                        return Ok(Outcome::fail(
                            "Successful CONNACK missing Authentication Method property",
                        ));
                    }
                }
            }
            Packet::ConnAck(connack)
                if connack.reason_code == 0x8C || connack.reason_code == 0x87 =>
            {
                return Ok(Outcome::skip(SKIP_MSG));
            }
            other => return Ok(Outcome::fail_packet("AUTH or CONNACK", &other)),
        }
    }
}

const FULL_EXCHANGE: TestContext = TestContext {
    refs: &["MQTT-4.12.0-2", "MQTT-4.12.0-3"],
    description: "If server requires additional information to complete the authorization, it can send an AUTH packet to client",
    compliance: Compliance::Must,
};

/// If the Server requires additional information to complete the authorization, it can send an AUTH packet to the Client. This packet MUST contain a Reason Code of 0x18 (Continue authentication). [MQTT-4.12.0-2].
/// The exact data values are auth-method-specific; we send placeholder responses.
async fn full_exchange(config: TestConfig<'_>) -> Result<Outcome> {
    let params = auth_connect_params("mqtt-test-auth-exchange");
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    let mut rounds = 0u8;
    loop {
        if rounds > 10 {
            return Ok(Outcome::fail(
                "Auth exchange exceeded 10 rounds without completing",
            ));
        }

        match client.recv().await? {
            Packet::Auth {
                reason_code: 0x18, ..
            } => {
                rounds += 1;
                client
                    .send_auth(0x18, &auth_response(b"client-response"))
                    .await?;
            }
            Packet::ConnAck(connack) if connack.reason_code == 0x00 => {
                let _ = client.send_disconnect(0x00).await;
                return Ok(Outcome::Pass);
            }
            Packet::ConnAck(connack)
                if connack.reason_code == 0x8C || connack.reason_code == 0x87 =>
            {
                return Ok(Outcome::skip(SKIP_MSG));
            }
            Packet::ConnAck(connack) => {
                return Ok(Outcome::fail(format!(
                    "Auth exchange ended with CONNACK reason {:#04x} (expected 0x00)",
                    connack.reason_code
                )));
            }
            other => return Ok(Outcome::fail_packet("AUTH or CONNACK", &other)),
        }
    }
}

const REAUTH: TestContext = TestContext {
    refs: &["MQTT-4.12.1-1"],
    description: "If client supplied an Authentication Method in the CONNECT packet it can initiate a re-authentication at any time after receiving a CONNACK",
    compliance: Compliance::Must,
};

/// After a successful enhanced-auth connection, initiate re-authentication
/// If the Client supplied an Authentication Method in the CONNECT packet it can initiate a re-authentication at any time after receiving a CONNACK. It does this by sending an AUTH packet with a Reason Code of 0x19 (Re-authentication). The Client MUST set the Authentication Method to the same value as the Authentication Method originally used to authenticate the Network Connection. [MQTT-4.12.1-1].
/// AUTH rc=0x00 (success) or rc=0x18 (continue).
async fn reauth(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = match complete_auth_exchange(config, "mqtt-test-auth-reauth").await {
        Ok(c) => c,
        Err(outcome) => return Ok(outcome),
    };

    // Initiate re-authentication
    client
        .send_auth(0x19, &auth_response(b"reauth-data"))
        .await?;

    let mut rounds = 0u8;
    loop {
        if rounds > 10 {
            return Ok(Outcome::fail("Re-auth exchange exceeded 10 rounds"));
        }

        match client.recv_with_timeout(Duration::from_secs(5)).await {
            Ok(Packet::Auth {
                reason_code: 0x00, ..
            }) => {
                let _ = client.send_disconnect(0x00).await;
                return Ok(Outcome::Pass);
            }
            Ok(Packet::Auth {
                reason_code: 0x18, ..
            }) => {
                rounds += 1;
                client
                    .send_auth(0x18, &auth_response(b"reauth-response"))
                    .await?;
            }
            Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => {
                return Ok(Outcome::fail(
                    "Server disconnected instead of handling re-authentication",
                ));
            }
            Err(RecvError::Timeout) => {
                return Ok(Outcome::fail(
                    "Server did not respond to re-authentication (timed out)",
                ));
            }
            Err(RecvError::Other(e)) => {
                return Ok(Outcome::fail(format!("unexpected error: {e:#}")));
            }
            Ok(other) => {
                return Ok(Outcome::fail_packet("AUTH(0x00 or 0x18)", &other));
            }
        }
    }
}

const REAUTH_FAIL: TestContext = TestContext {
    refs: &["MQTT-4.12.1-2"],
    description: "If the re-authentication fails, client or Server SHOULD send DISCONNECT with an appropriate Reason Code and MUST close the Network Connection",
    compliance: Compliance::Should,
};

/// If re-authentication fails, the server SHOULD send DISCONNECT with a reason
/// If the re-authentication fails, the Client or Server SHOULD send DISCONNECT with an appropriate Reason Code and MUST close the Network Connection. [MQTT-4.12.1-2].
/// with a different (unsupported) method.
async fn reauth_fail(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = match complete_auth_exchange(config, "mqtt-test-auth-reauth-fail").await {
        Ok(c) => c,
        Err(outcome) => return Ok(outcome),
    };

    // Send re-auth with a *different* method — this violates MQTT-4.12.1-1
    // and should cause the server to reject.
    let bad_props = Properties {
        authentication_method: Some("BOGUS-REAUTH-METHOD".into()),
        ..Default::default()
    };
    client.send_auth(0x19, &bad_props).await?;

    match client.recv_with_timeout(Duration::from_secs(5)).await {
        Ok(Packet::Disconnect(disc)) if disc.reason_code >= 0x80 => Ok(Outcome::Pass),
        Ok(Packet::Disconnect(_)) => {
            // DISCONNECT with non-error code — unusual but still a disconnect
            Ok(Outcome::Pass)
        }
        Err(RecvError::Closed) => Ok(Outcome::fail(
            "Server closed connection without sending DISCONNECT on re-auth failure",
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "Server did not respond to failed re-auth (timed out)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("DISCONNECT", &other)),
    }
}
