//! CONNECT / CONNACK compliance tests [MQTT-3.1 / MQTT-3.2].

use std::time::Duration;

use anyhow::Result;

use crate::client::{self, RawClient, RecvError};
use crate::codec::{
    ConnectParams, Packet, Properties, PublishParams, QoS, SubscribeParams, WillParams,
};
use crate::helpers::{expect_connack_success, expect_disconnect, expect_suback};
use crate::types::{Compliance, IntoOutcome, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("CONNECT / CONNACK");

    suite.add(BASIC_CONNECT, basic_connect(config));
    suite.add(CLEAN_START_TRUE, clean_start_true(config));
    suite.add(CLEAN_START_FALSE, clean_start_false_no_session(config));
    suite.add(ZERO_LEN_CLIENT_ID, zero_length_client_id(config));
    suite.add(
        ZERO_LEN_NO_CLEAN,
        zero_length_client_id_no_clean_start(config),
    );
    suite.add(ASSIGNED_CLIENT_ID, assigned_client_id(config));
    suite.add(FIRST_CONNECT, first_packet_must_be_connect(config));
    suite.add(SESSION_EXPIRY, session_expiry_interval_accepted(config));
    suite.add(RECEIVE_MAX, receive_maximum_accepted(config));
    suite.add(MAX_PACKET_SIZE, maximum_packet_size_accepted(config));
    suite.add(SERVER_KEEP_ALIVE, server_keep_alive(config));
    suite.add(TOPIC_ALIAS_MAX, topic_alias_maximum(config));
    suite.add(WILDCARD_SUB_AVAIL, wildcard_subscription_available(config));
    suite.add(DUP_CONNECT, duplicate_connect(config));
    suite.add(INVALID_PROTO_NAME, invalid_protocol_name(config));
    suite.add(INVALID_PROTO_VER, invalid_protocol_version(config));
    suite.add(KEEP_ALIVE, keep_alive_timeout(config));
    suite.add(WILL_ON_CLOSE, will_message_on_unexpected_close(config));
    suite.add(
        WILL_REMOVED_ON_DISCONNECT,
        will_message_removed_on_disconnect(config),
    );
    suite.add(WILL_RETAIN, will_retain_flag(config));
    suite.add(WILL_DELAY, will_delay_interval(config));
    suite.add(REQ_RESP_INFO, request_response_information(config));
    suite.add(SERVER_MAX_QOS, server_maximum_qos(config));
    suite.add(SERVER_RECV_MAX, server_receive_maximum(config));
    suite.add(ENHANCED_AUTH, enhanced_auth_method(config));
    suite.add(REASON_STRING, reason_string_in_connack(config));
    suite.add(
        SESSION_PRESENT_ZERO_ON_REJECT,
        session_present_zero_on_reject(config),
    );
    suite.add(ACCEPTABLE_CLIENT_ID, acceptable_client_id_chars(config));
    suite.add(FLOW_CONTROL, flow_control_receive_maximum(config));
    suite.add(CONNACK_MAX_QOS, connack_maximum_qos(config));
    suite.add(CONNACK_RETAIN_AVAIL, connack_retain_available(config));
    suite.add(CONNACK_SUB_IDS, connack_subscription_ids_available(config));
    suite.add(
        CONNACK_SHARED_SUB,
        connack_shared_subscription_available(config),
    );
    suite.add(CONNACK_SERVER_REF, connack_server_reference(config));
    suite.add(SERVER_REDIRECT, server_redirection(config));
    suite.add(USERNAME_PASSWORD, username_password_accepted(config));
    suite.add(PASSWORD_NO_USERNAME, password_without_username(config));
    suite.add(EMPTY_USERNAME, empty_username(config));
    suite.add(USERNAME_ONLY, username_only(config));
    suite.add(WILL_NON_RETAINED, will_non_retained(config));
    suite.add(TOPIC_ALIAS_MAX_ZERO, topic_alias_maximum_zero(config));
    suite.add(CONNACK_BEFORE_CLOSE, connack_before_close_on_error(config));

    suite
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const BASIC_CONNECT: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1", "MQTT-3.1.4-4"],
    description: "Server MUST send CONNACK in response to CONNECT",
    compliance: Compliance::Must,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1]. The Server MUST perform the processing of Clean Start [MQTT-3.1.4-4].
///
/// This test sends a valid CONNECT and verifies the server responds with a successful CONNACK.
async fn basic_connect(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-basic-connect");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const CLEAN_START_TRUE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-4", "MQTT-3.2.2-2"],
    description: "Clean Start=1: server MUST start a new session (session_present=0)",
    compliance: Compliance::Must,
};

/// If a CONNECT packet is received with Clean Start set to 1, the Client and Server MUST discard any existing Session
/// and start a new Session [MQTT-3.1.2-4]. If the Server accepts a connection with Clean Start set to 1, the Server
/// MUST set Session Present to 0 in the CONNACK packet [MQTT-3.2.2-2].
///
/// This test connects with Clean Start=1 and verifies session_present=0 in CONNACK.
async fn clean_start_true(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-clean-start");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.session_present {
        Ok(Outcome::fail(
            "CONNACK session_present=1 despite Clean Start=1",
        ))
    } else {
        Ok(Outcome::Pass)
    }
}

const CLEAN_START_FALSE: TestContext = TestContext {
    refs: &["MQTT-3.2.2-3"],
    description: "Clean Start=0 with no prior session: session_present MUST be 0",
    compliance: Compliance::Must,
};

/// If the Server accepts a connection with Clean Start set to 0 and the Server has Session State for the ClientID,
/// it MUST set Session Present to 1 in the CONNACK packet, otherwise it MUST set Session Present to 0 in the CONNACK
/// packet [MQTT-3.2.2-3].
///
/// This test connects with Clean Start=0 using a unique client ID (no prior session) and verifies session_present=0.
async fn clean_start_false_no_session(config: TestConfig<'_>) -> Result<Outcome> {
    // Use a unique client ID unlikely to have an existing session.
    let id = format!(
        "mqtt-test-no-session-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let mut params = ConnectParams::new(id);
    params.clean_start = false;

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.session_present {
        Ok(Outcome::fail(
            "CONNACK session_present=1 but no prior session should exist",
        ))
    } else {
        Ok(Outcome::Pass)
    }
}

const ZERO_LEN_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.1.3-7"],
    description: "Zero-length client ID with Clean Start=1 MUST be accepted",
    compliance: Compliance::Must,
};

/// If a Server receives a zero length ClientID it MUST process the CONNECT packet as if the Client had provided a
/// unique ClientID, and MUST return the Assigned Client Identifier in the CONNACK packet [MQTT-3.1.3-7].
///
/// This test connects with a zero-length client ID and Clean Start=1 and verifies the server accepts it.
async fn zero_length_client_id(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const ZERO_LEN_NO_CLEAN: TestContext = TestContext {
    refs: &["MQTT-3.1.3-8"],
    description: "Zero-length client ID with Clean Start=0 MAY be rejected with 0x85",
    compliance: Compliance::May,
};

/// If the Server rejects the ClientID it MAY respond to the CONNECT packet with a CONNACK using Reason Code 0x85
/// (Client Identifier not valid) and then it MUST close the Network Connection [MQTT-3.1.3-8].
///
/// This test connects with a zero-length client ID and Clean Start=0 and checks for a 0x85 rejection.
async fn zero_length_client_id_no_clean_start(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("");
    params.clean_start = false;

    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x85 => Ok(Outcome::Pass),
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => {
            // Connection closed — also acceptable rejection
            Ok(Outcome::Pass)
        }
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => {
            let _ = client.send_disconnect(0x00).await;
            Ok(Outcome::unsupported(
                "Broker accepted empty client ID with Clean Start=0 (no 0x85 rejection)",
            ))
        }
        Ok(Packet::ConnAck(connack)) => Ok(Outcome::unsupported(format!(
            "Expected reason 0x85, got {:#04x}",
            connack.reason_code
        ))),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK with 0x85", &other)),
    }
}

const ASSIGNED_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.2.2-16"],
    description: "Server SHOULD return Assigned Client Identifier when accepting empty client ID",
    compliance: Compliance::Should,
};

/// If the Server accepts a connection with a zero length Client Identifier, the Server MUST respond with a CONNACK
/// containing an Assigned Client Identifier. The Assigned Client Identifier MUST be a new Client Identifier not used
/// by any other Session currently in the Server [MQTT-3.2.2-16].
///
/// This test connects with a zero-length client ID and checks for an Assigned Client Identifier in CONNACK.
async fn assigned_client_id(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code != 0x00 {
        return Ok(Outcome::skip(format!(
            "Broker rejected empty client ID (reason {:#04x})",
            connack.reason_code
        )));
    }

    if connack.properties.assigned_client_id.is_some() {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(
            "Broker accepted empty client ID but did not return Assigned Client Identifier",
        ))
    }
}

const FIRST_CONNECT: TestContext = TestContext {
    refs: &["MQTT-3.1.0-1"],
    description: "Server MUST close connection if first packet is not CONNECT",
    compliance: Compliance::Must,
};

/// After a Network Connection is established by a Client to a Server, the first packet sent from the Client to the
/// Server MUST be a CONNECT packet [MQTT-3.1.0-1].
///
/// This test sends a PINGREQ as the first packet (instead of CONNECT) and verifies the server closes the connection.
async fn first_packet_must_be_connect(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Send a PINGREQ as the first packet instead of CONNECT
    client.send_pingreq().await?;

    match client.recv().await {
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::PingResp) => Ok(Outcome::fail(
            "Broker responded to PINGREQ without prior CONNECT",
        )),
        Ok(other) => Ok(Outcome::fail_packet("connection close", &other)),
    }
}

// ── MAY ──────────────────────────────────────────────────────────────────────

const SESSION_EXPIRY: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Session Expiry Interval property is accepted",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test connects with a Session Expiry Interval property and verifies the server accepts it.
async fn session_expiry_interval_accepted(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-sei");
    params.properties.session_expiry_interval = Some(60);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const RECEIVE_MAX: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Receive Maximum property in CONNECT is accepted",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test connects with a Receive Maximum property and verifies the server accepts it.
async fn receive_maximum_accepted(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-recv-max");
    params.properties.receive_maximum = Some(10);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const MAX_PACKET_SIZE: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Maximum Packet Size property in CONNECT is accepted",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test connects with a Maximum Packet Size property and verifies the server accepts it.
async fn maximum_packet_size_accepted(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-max-pkt");
    params.properties.maximum_packet_size = Some(65536);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const SERVER_KEEP_ALIVE: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Server Keep Alive: server MAY override client's keep-alive value",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server includes the Server Keep Alive property in CONNACK to override the client's
/// requested keep-alive interval.
async fn server_keep_alive(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-server-ka");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.server_keep_alive.is_some() {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::unsupported(
            "Server did not include Server Keep Alive property in CONNACK",
        ))
    }
}

const TOPIC_ALIAS_MAX: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Topic Alias Maximum: server reports maximum supported topic aliases",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server includes the Topic Alias Maximum property in CONNACK.
async fn topic_alias_maximum(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-ta-max");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if let Some(max) = connack.properties.topic_alias_maximum {
        if max > 0 {
            Ok(Outcome::Pass)
        } else {
            Ok(Outcome::unsupported(
                "Topic Alias Maximum is 0 (topic aliases not supported)",
            ))
        }
    } else {
        Ok(Outcome::unsupported(
            "Server did not include Topic Alias Maximum in CONNACK",
        ))
    }
}

const WILDCARD_SUB_AVAIL: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Wildcard Subscription Available: server reports wildcard subscription support",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server includes the Wildcard Subscription Available property in CONNACK.
async fn wildcard_subscription_available(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-wildcard-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.wildcard_subscription_available {
        Some(true) | None => {
            // None means default (true per spec)
            Ok(Outcome::Pass)
        }
        Some(false) => Ok(Outcome::fail(
            "Server reported Wildcard Subscription Available = false",
        )),
    }
}

// ── Protocol violations ─────────────────────────────────────────────────────

const DUP_CONNECT: TestContext = TestContext {
    refs: &["MQTT-3.1.0-2"],
    description: "Server MUST disconnect a client that sends a second CONNECT",
    compliance: Compliance::Must,
};

/// The Server MUST process a second CONNECT packet sent from a Client as a Protocol Error and close the Network
/// Connection [MQTT-3.1.0-2].
///
/// This test sends two CONNECT packets on the same connection and verifies the server disconnects.
async fn duplicate_connect(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-dup-connect");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Send a second CONNECT on the same connection.
    client.send_connect(&params).await?;

    // Broker must either send DISCONNECT or close the connection.
    Ok(expect_disconnect(&mut client).await)
}

const INVALID_PROTO_NAME: TestContext = TestContext {
    refs: &["MQTT-3.1.2-1"],
    description: "Server MUST close connection if protocol name is not 'MQTT'",
    compliance: Compliance::Must,
};

/// If the protocol name is incorrect the Server MAY send a CONNACK with Reason Code of 0x84 (Unsupported Protocol
/// Version), and then it MUST close the Network Connection [MQTT-3.1.2-1].
///
/// This test sends a CONNECT with protocol name "XQTT" and verifies the server closes the connection.
async fn invalid_protocol_name(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with protocol name "XQTT" instead of "MQTT"
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                               // CONNECT fixed header
        0x0D,                               // remaining length = 13
        0x00, 0x04, b'X', b'Q', b'T', b'T', // protocol name "XQTT"
        0x05,                               // protocol version 5
        0x02,                               // connect flags: clean start
        0x00, 0x3C,                         // keep alive = 60
        0x00,                               // properties length = 0
        0x00, 0x00,                         // client ID length = 0
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_disconnect(&mut client).await)
}

const INVALID_PROTO_VER: TestContext = TestContext {
    refs: &["MQTT-3.1.2-2"],
    description: "Server MAY respond with reason 0x84 for unsupported protocol version",
    compliance: Compliance::May,
};

/// If the Server does not support the protocol version requested by the Client, the Server MAY send a CONNACK packet
/// with Reason Code 0x84 (Unsupported Protocol Version) and then MUST close the Network
/// Connection [MQTT-3.1.2-2].
///
/// This test sends a CONNECT with protocol version 4 (MQTT 3.1.1) and checks for a 0x84 rejection.
async fn invalid_protocol_version(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with protocol version 4 (MQTT 3.1.1) — no properties field
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
    client.send_raw(bad_connect).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x84 => Ok(Outcome::Pass),
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => Ok(Outcome::unsupported(
            "Broker accepted MQTT v4 CONNECT (no 0x84 rejection)",
        )),
        Ok(Packet::ConnAck(connack)) => Ok(Outcome::unsupported(format!(
            "Expected CONNACK reason 0x84, got {:#04x}",
            connack.reason_code
        ))),
        Err(RecvError::Closed) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK or close", &other)),
    }
}

const SESSION_PRESENT_ZERO_ON_REJECT: TestContext = TestContext {
    refs: &["MQTT-3.2.2-6"],
    description: "Session Present MUST be 0 when CONNACK reason code is non-zero",
    compliance: Compliance::Must,
};

/// If a Server sends a CONNACK packet containing a non-zero Reason Code it MUST set Session Present to
/// 0 [MQTT-3.2.2-6].
///
/// This test provokes a CONNACK rejection (via invalid protocol version) and verifies session_present=0.
async fn session_present_zero_on_reject(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Send a CONNECT with invalid protocol version to provoke a rejection.
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
    client.send_raw(bad_connect).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code != 0x00 => {
            if connack.session_present {
                Ok(Outcome::fail(format!(
                    "CONNACK with reason {:#04x} has session_present=1 (MUST be 0)",
                    connack.reason_code
                )))
            } else {
                Ok(Outcome::Pass)
            }
        }
        Ok(Packet::ConnAck(_)) => {
            // Broker accepted the v4 CONNECT — can't test this requirement.
            Ok(Outcome::skip(
                "Broker accepted MQTT v4 CONNECT; cannot provoke rejection",
            ))
        }
        Err(_) => {
            // Broker closed connection — acceptable but can't verify session_present.
            Ok(Outcome::skip(
                "Broker closed connection without CONNACK; cannot verify session_present",
            ))
        }
        Ok(other) => Ok(Outcome::fail_packet("CONNACK", &other)),
    }
}

const KEEP_ALIVE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-22"],
    description: "Server MUST disconnect client exceeding 1.5x keep-alive without activity",
    compliance: Compliance::Must,
};

/// If the Keep Alive value is non-zero and the Server does not receive an MQTT Control Packet from the Client within
/// one and a half times the Keep Alive time period, it MUST close the Network Connection to the Client as if the
/// network had failed [MQTT-3.1.2-22].
///
/// This test connects with a 2-second keep-alive, sends no further packets, and verifies the server disconnects
/// within 5 seconds.
async fn keep_alive_timeout(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-keepalive");
    params.keep_alive = 2; // 2 seconds → broker should disconnect after ~3s

    let (mut client, _) = client::connect(config.addr, &params, Duration::from_secs(5)).await?;

    // Do NOT send PINGREQ. Wait for the broker to disconnect us.
    match client.recv_with_timeout(Duration::from_secs(5)).await {
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet(
            "disconnect after keep-alive timeout",
            &other,
        )),
    }
}

// ── Will message tests ──────────────────────────────────────────────────────

const WILL_ON_CLOSE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-8"],
    description: "Will message MUST be published when connection closes unexpectedly",
    compliance: Compliance::Must,
};

/// The Will Message MUST be published after the Network Connection is subsequently closed and either the Will Delay
/// Interval has elapsed or the Session ends, unless the Will Message has been deleted by the Server on receipt of a
/// DISCONNECT packet with Reason Code 0x00 (Normal disconnection) [MQTT-3.1.2-8].
///
/// This test connects with a will message, drops the connection without DISCONNECT, and verifies the will is
/// published.
async fn will_message_on_unexpected_close(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/will/unexpected";

    // Set up a subscriber to receive the will message
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Connect a client with a will message
    let mut will_params = ConnectParams::new("mqtt-test-will-pub");
    will_params.will = Some(WillParams::new(will_topic, b"will-triggered".as_slice()));
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Drop the client without sending DISCONNECT — simulates unexpected close
    drop(will_client.into_raw());

    // The subscriber should receive the will message
    match sub_client.recv_with_timeout(Duration::from_secs(5)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => {
            if p.payload == b"will-triggered" {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Will payload mismatch: got {:?}",
                    String::from_utf8_lossy(&p.payload)
                )))
            }
        }
        Ok(other) => Ok(Outcome::fail_packet("PUBLISH (will message)", &other)),
        Err(_) => Ok(Outcome::fail(
            "Will message not received after unexpected disconnect",
        )),
    }
}

const WILL_REMOVED_ON_DISCONNECT: TestContext = TestContext {
    refs: &["MQTT-3.1.2-10"],
    description: "Will message MUST be removed on normal DISCONNECT",
    compliance: Compliance::Must,
};

/// The Will Message MUST be removed from the stored Session State in the Server once it has been published or the
/// Server has received a DISCONNECT packet with a Reason Code of 0x00 (Normal disconnection) from the
/// Client [MQTT-3.1.2-10].
///
/// This test connects with a will message, disconnects normally (0x00), and verifies the will is not published.
async fn will_message_removed_on_disconnect(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/will/normal";

    // Set up a subscriber
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-norm-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Connect with a will message, then disconnect normally
    let mut will_params = ConnectParams::new("mqtt-test-will-norm-pub");
    will_params.will = Some(WillParams::new(will_topic, b"should-not-arrive".as_slice()));
    let (mut will_client, _) =
        client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Normal disconnect — will message should NOT be published
    will_client.send_disconnect(0x00).await?;

    // Short timeout — we expect NO message
    match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::Pass),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(Outcome::fail(
            "Will message was published despite normal DISCONNECT",
        )),
        Ok(_) => Ok(Outcome::Pass),
    }
}

const WILL_RETAIN: TestContext = TestContext {
    refs: &["MQTT-3.1.2-15"],
    description: "Will Retain flag MUST be respected when will message is published",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 1 and Will Retain is set to 1, the Server MUST publish the Will Message as a retained
/// message [MQTT-3.1.2-15].
///
/// This test connects with a retained will message, drops the connection, and verifies a new subscriber receives the
/// will as a retained message.
async fn will_retain_flag(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/will/retain";

    // Check if broker supports retain
    let check_params = ConnectParams::new("mqtt-test-will-retain-check");
    let (_check_client, connack) =
        client::connect(config.addr, &check_params, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(Outcome::skip("Broker reported Retain Available = false"));
    }

    // Clear any existing retained message on this topic
    let clear_params = ConnectParams::new("mqtt-test-will-retain-clear");
    let (mut clear_client, _) =
        client::connect(config.addr, &clear_params, config.recv_timeout).await?;
    clear_client
        .send_publish(&PublishParams::retained(will_topic, vec![]))
        .await?;

    // Connect with a retained will message
    let mut will_params = ConnectParams::new("mqtt-test-will-retain-pub");
    will_params.will = Some(WillParams {
        topic: will_topic.to_string(),
        payload: b"retained-will".to_vec(),
        qos: QoS::AtMostOnce,
        retain: true,
        properties: Properties::default(),
    });
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Drop without DISCONNECT to trigger will
    drop(will_client.into_raw());

    // Give broker time to process the will
    tokio::time::sleep(Duration::from_secs(1)).await;

    // New subscriber should receive the retained will message
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-retain-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == will_topic && p.retain => Ok(Outcome::Pass),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(Outcome::fail(
            "Will message received but retain flag was not set",
        )),
        Ok(other) => Ok(Outcome::fail_packet("retained PUBLISH (will)", &other)),
        Err(_) => Ok(Outcome::fail(
            "Retained will message not delivered to new subscriber",
        )),
    }
}

// ── CONNACK server property enforcement ─────────────────────────────────────

const SERVER_MAX_QOS: TestContext = TestContext {
    refs: &["MQTT-3.2.2-11"],
    description: "Client MUST NOT send QoS exceeding server's Maximum QoS",
    compliance: Compliance::Must,
};

/// If a Client receives a Maximum QoS from a Server, it MUST NOT send PUBLISH packets at a QoS level exceeding the
/// Maximum QoS level specified [MQTT-3.2.2-11]. It is a Protocol Error if the Server receives a PUBLISH packet with
/// a QoS greater than the Maximum QoS it specified.
///
/// This test sends a PUBLISH above the server's advertised Maximum QoS and verifies the server rejects it.
async fn server_maximum_qos(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-max-qos");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let max_qos = connack.properties.maximum_qos;

    match max_qos {
        Some(0) => {
            // Server only supports QoS 0 — sending QoS 1 should be rejected
            let pub_params =
                PublishParams::qos1("mqtt/test/connack/maxqos", b"qos1-over-max".as_slice(), 1);
            client.send_publish(&pub_params).await?;

            match client.recv().await {
                Ok(Packet::Disconnect(d)) if d.reason_code == 0x9B => {
                    // 0x9B = QoS not supported
                    Ok(Outcome::Pass)
                }
                Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => {
                    // Disconnected — acceptable
                    Ok(Outcome::Pass)
                }
                Err(RecvError::Timeout) => {
                    Ok(Outcome::fail("broker did not disconnect (timed out)"))
                }
                Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
                Ok(Packet::PubAck(ack)) if ack.reason_code >= 0x80 => Ok(Outcome::Pass),
                Ok(Packet::PubAck(_)) => Ok(Outcome::fail(
                    "Server accepted QoS 1 PUBLISH despite Maximum QoS = 0",
                )),
                Ok(other) => Ok(Outcome::fail_packet("DISCONNECT or error PUBACK", &other)),
            }
        }
        Some(1) => {
            // Server supports up to QoS 1 — sending QoS 2 should be rejected
            let pub_params =
                PublishParams::qos2("mqtt/test/connack/maxqos", b"qos2-over-max".as_slice(), 1);
            client.send_publish(&pub_params).await?;

            match client.recv().await {
                Ok(Packet::Disconnect(d)) if d.reason_code == 0x9B => Ok(Outcome::Pass),
                Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
                Err(RecvError::Timeout) => {
                    Ok(Outcome::fail("broker did not disconnect (timed out)"))
                }
                Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
                Ok(Packet::PubRec(rec)) if rec.reason_code >= 0x80 => Ok(Outcome::Pass),
                Ok(Packet::PubRec(_)) => Ok(Outcome::fail(
                    "Server accepted QoS 2 PUBLISH despite Maximum QoS = 1",
                )),
                Ok(other) => Ok(Outcome::fail_packet("DISCONNECT or error PUBREC", &other)),
            }
        }
        _ => {
            // Server supports QoS 2 (default) or didn't advertise — skip
            Ok(Outcome::skip(
                "Server supports QoS 2 (no Maximum QoS restriction to test)",
            ))
        }
    }
}

const SERVER_RECV_MAX: TestContext = TestContext {
    refs: &["MQTT-3.3.4-9"],
    description: "Server MUST NOT send more concurrent QoS>0 messages than Receive Maximum",
    compliance: Compliance::Must,
};

/// The Server MUST NOT send more than Receive Maximum QoS 1 and QoS 2 PUBLISH packets for which it has not received
/// PUBACK, PUBCOMP, or PUBREC with a Reason Code of 128 or greater from the Client [MQTT-3.3.4-9].
///
/// This test connects with a low Receive Maximum, publishes more messages than the limit, and verifies the server
/// does not send more than Receive Maximum messages without receiving PUBACK.
async fn server_receive_maximum(config: TestConfig<'_>) -> Result<Outcome> {
    // Connect with a very low Receive Maximum
    let recv_max: u16 = 2;
    let mut sub_params = ConnectParams::new("mqtt-test-recv-max-sub");
    sub_params.properties.receive_maximum = Some(recv_max);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let topic = "mqtt/test/connack/recvmax";
    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Publish more messages than Receive Maximum using a separate client
    let pub_params = ConnectParams::new("mqtt-test-recv-max-pub");
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params, config.recv_timeout).await?;

    let msg_count = (recv_max + 2) as usize;
    for i in 0..msg_count {
        let p = PublishParams::qos1(topic, format!("msg-{i}"), (i + 1) as u16);
        pub_client.send_publish(&p).await?;
    }
    // Drain PUBACKs from publisher
    for _ in 0..msg_count {
        let _ = pub_client.recv().await;
    }

    // Receive messages on the subscriber WITHOUT sending PUBACK.
    // The broker should stop sending after Receive Maximum inflight messages.
    let mut received = 0u16;
    for _ in 0..msg_count {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(_)) => received += 1,
            Err(_) => break,
            Ok(_) => {}
        }
    }

    if received <= recv_max {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Received {received} QoS 1 messages without PUBACK (Receive Maximum = {recv_max})",
        )))
    }
}

// ── Will Delay Interval ─────────────────────────────────────────────────────

const WILL_DELAY: TestContext = TestContext {
    refs: &["MQTT-3.1.3-9"],
    description: "Will Delay Interval: will message publication MAY be delayed",
    compliance: Compliance::May,
};

/// If a new Network Connection to this Session is made before the Will Delay Interval has passed, the Server MUST NOT
/// send the Will Message [MQTT-3.1.3-9].
///
/// This test connects with a will message and Will Delay Interval=2s, abruptly disconnects, verifies the will does
/// not arrive within 1s, then waits for it to arrive after the delay.
async fn will_delay_interval(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/will/delay";

    // Subscriber
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-delay-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Connect with will delay = 2 seconds
    let mut will_params = ConnectParams::new("mqtt-test-will-delay-pub");
    will_params.will = Some(WillParams {
        topic: will_topic.to_string(),
        payload: b"delayed-will".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        properties: Properties {
            will_delay_interval: Some(2),
            ..Properties::default()
        },
    });
    will_params.properties.session_expiry_interval = Some(60);
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Abrupt disconnect
    drop(will_client.into_raw());

    // Should NOT arrive immediately (within 1 second)
    match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => {
            return Ok(Outcome::unsupported(
                "Will message arrived immediately despite Will Delay Interval = 2s",
            ));
        }
        _ => {} // expected — no message yet
    }

    // Should arrive after the delay (wait up to 4 more seconds)
    match sub_client.recv_with_timeout(Duration::from_secs(4)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(Outcome::Pass),
        Ok(other) => Ok(Outcome::fail_packet("PUBLISH (delayed will)", &other)),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "Will message not received after delay interval expired (timed out)",
        )),
        Err(RecvError::Closed) => Ok(Outcome::fail(
            "Connection closed before delayed will message arrived",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

// ── Request/Response Information ────────────────────────────────────────────

const REQ_RESP_INFO: TestContext = TestContext {
    refs: &["MQTT-3.1.2-28"],
    description: "Request Response Information: server MAY return Response Information",
    compliance: Compliance::May,
};

/// A value of 0 indicates that the Server MUST NOT return Response Information [MQTT-3.1.2-28]. If the value is 1 the
/// Server MAY return Response Information in the CONNACK packet.
///
/// This test connects with Request Response Information=1 and checks whether the server includes Response Information
/// in CONNACK.
async fn request_response_information(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-resp-info");
    params.properties.request_response_information = Some(true);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.response_information.is_some() {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::unsupported(
            "Server did not include Response Information despite request",
        ))
    }
}

// ── Enhanced authentication ─────────────────────────────────────────────────

const ENHANCED_AUTH: TestContext = TestContext {
    refs: &["MQTT-3.1.4-2"],
    description: "Enhanced authentication via AUTH packets is supported",
    compliance: Compliance::May,
};

/// The Server MAY check that the contents of the CONNECT packet meet any further restrictions and SHOULD perform
/// authentication and authorization checks. If any of these checks fail, it MUST close the Network
/// Connection [MQTT-3.1.4-2].
///
/// This test sends a CONNECT with an Authentication Method (SCRAM-SHA-256) and verifies the server handles it
/// correctly — either continuing with AUTH, rejecting with an appropriate CONNACK reason code, or accepting.
async fn enhanced_auth_method(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-enhanced-auth");
    params.properties.authentication_method = Some("SCRAM-SHA-256".to_string());
    params.properties.authentication_data = Some(b"client-first-message".to_vec());

    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    match client.recv().await {
        Ok(Packet::Auth {
            reason_code: 0x18, ..
        }) => {
            // 0x18 = Continue authentication — broker supports enhanced auth
            let _ = client.send_disconnect(0x00).await;
            Ok(Outcome::Pass)
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x8C => {
            // Bad authentication method — broker rejects but handles correctly
            Ok(Outcome::Pass)
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x87 => {
            // Not Authorized — broker rejects but handles correctly
            Ok(Outcome::Pass)
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => {
            // Broker accepted without challenge — unusual but not invalid
            let _ = client.send_disconnect(0x00).await;
            Ok(Outcome::Pass)
        }
        Ok(Packet::ConnAck(connack)) => Ok(Outcome::unsupported(format!(
            "CONNACK reason {:#04x} for enhanced auth CONNECT",
            connack.reason_code
        ))),
        Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => Ok(Outcome::unsupported(
            "Broker closed connection instead of sending CONNACK with auth error code",
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "broker did not respond to enhanced auth CONNECT (timed out)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK or AUTH", &other)),
    }
}

// ── Reason String ───────────────────────────────────────────────────────────

const REASON_STRING: TestContext = TestContext {
    refs: &["MQTT-3.2.2-19"],
    description: "Reason String: server MAY include a human-readable diagnostic in CONNACK",
    compliance: Compliance::May,
};

/// The Server MUST NOT send this property [Reason String] if it would increase the size of the CONNACK packet beyond
/// the Maximum Packet Size specified by the Client [MQTT-3.2.2-19].
///
/// This test triggers a CONNACK rejection (via invalid protocol version) and checks whether the server includes a
/// Reason String property.
async fn reason_string_in_connack(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with protocol version 4 to trigger a CONNACK rejection
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
    client.send_raw(bad_connect).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code >= 0x80 => {
            if connack.properties.reason_string.is_some() {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::unsupported(
                    "CONNACK rejection did not include Reason String",
                ))
            }
        }
        Ok(Packet::ConnAck(_)) => Ok(Outcome::skip(
            "Broker accepted MQTT v4 CONNECT — cannot test error Reason String",
        )),
        Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => Ok(Outcome::unsupported(
            "Broker closed connection instead of sending CONNACK with Reason String",
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "broker did not respond to CONNECT (timed out)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK", &other)),
    }
}

// ── SHOULD ──────────────────────────────────────────────────────────────────

const ACCEPTABLE_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.1.3-5"],
    description: "Server SHOULD accept client IDs of [0-9a-zA-Z] with 1-23 bytes",
    compliance: Compliance::Should,
};

/// The Server SHOULD accept ClientIDs which contain only the characters
/// "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" [MQTT-3.1.3-5].
///
/// This test connects with a 23-character client ID using only the recommended character set.
async fn acceptable_client_id_chars(config: TestConfig<'_>) -> Result<Outcome> {
    // A 23-char ID using the recommended character set.
    let client_id = "abcABC0123456789xyzXYZw";
    let params = ConnectParams::new(client_id);
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const FLOW_CONTROL: TestContext = TestContext {
    refs: &["MQTT-4.9.0-1"],
    description: "Server SHOULD use Receive Maximum to limit concurrent inflight messages",
    compliance: Compliance::Should,
};

/// The Client or Server MUST set its initial send quota to a non-zero value not exceeding the Receive
/// Maximum [MQTT-4.9.0-1].
///
/// This test reads the server's Receive Maximum from CONNACK and verifies the server does not exceed it when
/// delivering QoS 1 messages without receiving PUBACK from the client.
async fn flow_control_receive_maximum(config: TestConfig<'_>) -> Result<Outcome> {
    // Connect subscriber — inspect server's Receive Maximum from CONNACK.
    let sub_params = ConnectParams::new("mqtt-test-flow-ctrl-sub");
    let (mut sub_client, connack) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let server_recv_max = connack.properties.receive_maximum.unwrap_or(65535);
    if server_recv_max > 20 {
        return Ok(Outcome::skip(format!(
            "Server Receive Maximum is {server_recv_max} — too high to practically test flow control"
        )));
    }

    let topic = "mqtt/test/flow/ctrl";
    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Publish more messages than Receive Maximum.
    let pub_params = ConnectParams::new("mqtt-test-flow-ctrl-pub");
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params, config.recv_timeout).await?;

    let msg_count = (server_recv_max + 5) as usize;
    for i in 0..msg_count {
        let p = PublishParams::qos1(topic, format!("flow-{i}"), (i + 1) as u16);
        pub_client.send_publish(&p).await?;
    }
    for _ in 0..msg_count {
        let _ = pub_client.recv().await;
    }

    // Receive without sending PUBACK — server should pause at Receive Maximum.
    let mut received = 0u16;
    for _ in 0..msg_count {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(_)) => received += 1,
            Err(_) => break,
            Ok(_) => {}
        }
    }
    if received <= server_recv_max {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Server sent {received} QoS 1 messages without PUBACK (Receive Maximum = {server_recv_max})",
        )))
    }
}

// ── MAY (CONNACK properties) ────────────────────────────────────────────────

const CONNACK_MAX_QOS: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Maximum QoS property in CONNACK reports server's QoS capability",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server includes the Maximum QoS property in CONNACK and validates its value.
async fn connack_maximum_qos(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-max-qos-prop");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.maximum_qos {
        Some(qos) if qos <= 2 => Ok(Outcome::Pass),
        Some(qos) => Ok(Outcome::fail(format!(
            "Maximum QoS property has invalid value {qos} (expected 0, 1, or 2)"
        ))),
        None => Ok(Outcome::unsupported(
            "CONNACK does not include Maximum QoS property (defaults to 2)",
        )),
    }
}

const CONNACK_RETAIN_AVAIL: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Retain Available property in CONNACK reports retain support",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server includes the Retain Available property in CONNACK.
async fn connack_retain_available(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-retain-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.retain_available {
        Some(_) => Ok(Outcome::Pass),
        None => Ok(Outcome::unsupported(
            "CONNACK does not include Retain Available property (defaults to true)",
        )),
    }
}

const CONNACK_SUB_IDS: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Subscription Identifiers Available property in CONNACK",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server includes the Subscription Identifiers Available property in CONNACK.
async fn connack_subscription_ids_available(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-subid-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.subscription_ids_available {
        Some(_) => Ok(Outcome::Pass),
        None => Ok(Outcome::unsupported(
            "CONNACK does not include Subscription Identifiers Available property (defaults to true)",
        )),
    }
}

const CONNACK_SHARED_SUB: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Shared Subscription Available property in CONNACK",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server includes the Shared Subscription Available property in CONNACK.
async fn connack_shared_subscription_available(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-shared-sub-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.shared_subscription_available {
        Some(_) => Ok(Outcome::Pass),
        None => Ok(Outcome::unsupported(
            "CONNACK does not include Shared Subscription Available property (defaults to true)",
        )),
    }
}

const CONNACK_SERVER_REF: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Server Reference in rejected CONNACK for server redirection",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test provokes a rejected CONNACK and checks whether the server includes a Server Reference property.
async fn connack_server_reference(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Send MQTT v4 CONNECT to trigger a rejection
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
    client.send_raw(bad_connect).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code >= 0x80 => {
            if connack.properties.server_reference.is_some() {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::unsupported(
                    "Rejected CONNACK does not include Server Reference property",
                ))
            }
        }
        Ok(Packet::ConnAck(_)) => Ok(Outcome::skip(
            "Broker accepted MQTT v4 CONNECT — cannot test rejected CONNACK properties",
        )),
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(Outcome::skip(
            "Broker closed connection without CONNACK — cannot inspect Server Reference",
        )),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK", &other)),
    }
}

const SERVER_REDIRECT: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Server redirection: CONNACK with reason 0x9C or 0x9D indicates redirect",
    compliance: Compliance::May,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test checks whether the server uses reason codes 0x9C (Use Another Server) or 0x9D (Server Moved) to
/// redirect clients, as described in section 4.11 (non-normative).
async fn server_redirection(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-redirect");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // A successful CONNACK won't have redirection reason codes, but the
    // server may still advertise a Server Reference for informational purposes.
    if connack.reason_code == 0x9C || connack.reason_code == 0x9D {
        // Actively redirecting — check for Server Reference.
        if connack.properties.server_reference.is_some() {
            Ok(Outcome::Pass)
        } else {
            Ok(Outcome::fail(format!(
                "Redirect reason {:#04x} without Server Reference property",
                connack.reason_code
            )))
        }
    } else {
        // Normal connection — server is not redirecting.
        Ok(Outcome::unsupported(
            "Broker did not redirect (no 0x9C/0x9D reason code in CONNACK)",
        ))
    }
}

// ── Username / Password ─────────────────────────────────────────────────────

const USERNAME_PASSWORD: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1"],
    description: "Server MUST accept CONNECT with Username and Password flags set",
    compliance: Compliance::Must,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other than
/// AUTH [MQTT-3.2.0-1].
///
/// This test sends a CONNECT with both Username and Password flags set and verifies the server accepts it.
async fn username_password_accepted(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-user-pass");
    params.username = Some("testuser".into());
    params.password = Some(b"testpass".to_vec());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const PASSWORD_NO_USERNAME: TestContext = TestContext {
    refs: &["MQTT-3.1.2-19"],
    description: "MQTT v5 allows Password without Username (v5 change from v3.1.1)",
    compliance: Compliance::May,
};

/// If the Password Flag is set to 1, a Password MUST be present in the Payload [MQTT-3.1.2-19].
///
/// This test sends a CONNECT with Password flag set but no Username flag (valid in MQTT v5) and verifies the server
/// accepts it.
async fn password_without_username(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-pass-no-user");
    params.password = Some(b"testpass".to_vec());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const EMPTY_USERNAME: TestContext = TestContext {
    refs: &["MQTT-3.1.2-17"],
    description: "Server MUST accept zero-length username when Username flag is set",
    compliance: Compliance::Must,
};

/// If the User Name Flag is set to 1, a User Name MUST be present in the Payload [MQTT-3.1.2-17].
///
/// This test sends a CONNECT with the Username flag set and a zero-length UTF-8 string, verifying the server accepts
/// the valid (though empty) username.
async fn empty_username(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-empty-user");
    params.username = Some(String::new());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const USERNAME_ONLY: TestContext = TestContext {
    refs: &["MQTT-3.1.2-17"],
    description: "Server MUST accept CONNECT with Username flag set and no Password",
    compliance: Compliance::Must,
};

/// If the User Name Flag is set to 1, a User Name MUST be present in the Payload [MQTT-3.1.2-17].
///
/// This test sends a CONNECT with only the Username flag set (no Password flag) and verifies the server accepts it.
async fn username_only(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-user-only");
    params.username = Some("testuser".into());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

// ── Will Retain=0 → non-retained ────────────────────────────────────────

const WILL_NON_RETAINED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-14"],
    description: "Will Retain=0: will message MUST be published as non-retained",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 1 and Will Retain is set to 0, the Server MUST publish the Will Message as a
/// non-retained message [MQTT-3.1.2-14].
///
/// This test connects with a non-retained will message, drops the connection, and verifies a new subscriber does not
/// receive it as retained.
async fn will_non_retained(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/will/nonretain";

    // Clear any existing retained message on this topic
    let clear_params = ConnectParams::new("mqtt-test-will-nr-clear");
    let (mut clear_client, _) =
        client::connect(config.addr, &clear_params, config.recv_timeout).await?;
    clear_client
        .send_publish(&PublishParams::retained(will_topic, vec![]))
        .await?;
    drop(clear_client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Subscribe first so we receive the will message when it's published
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-nr-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Connect with a non-retained will message (retain=false)
    let mut will_params = ConnectParams::new("mqtt-test-will-nr-pub");
    will_params.will = Some(WillParams {
        topic: will_topic.to_string(),
        payload: b"non-retained-will".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        properties: Properties::default(),
    });
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Drop without DISCONNECT to trigger will
    drop(will_client.into_raw());

    // Wait for will message on subscriber
    tokio::time::sleep(Duration::from_millis(500)).await;

    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => {
            drop(sub_client);

            // Verify it was NOT stored as retained: new subscriber should NOT receive it
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut sub2 = client::connect_and_subscribe(
                config.addr,
                "mqtt-test-will-nr-sub2",
                will_topic,
                QoS::AtMostOnce,
                config.recv_timeout,
            )
            .await?;

            match sub2.recv_with_timeout(Duration::from_secs(1)).await {
                Ok(Packet::Publish(p2)) if p2.topic == will_topic && !p2.payload.is_empty() => {
                    Ok(Outcome::fail(
                        "Will message with Retain=0 was stored as retained (new subscriber received it)",
                    ))
                }
                _ => Ok(Outcome::Pass),
            }
        }
        Ok(other) => Ok(Outcome::fail_packet("PUBLISH (will message)", &other)),
        Err(_) => Ok(Outcome::fail(
            "Will message not published after ungraceful disconnect",
        )),
    }
}

// ── Topic Alias Maximum=0 ───────────────────────────────────────────────

const TOPIC_ALIAS_MAX_ZERO: TestContext = TestContext {
    refs: &["MQTT-3.1.2-26"],
    description: "Topic Alias Maximum=0: server MUST NOT send Topic Aliases to client",
    compliance: Compliance::Must,
};

/// The Server MUST NOT send a Topic Alias in a PUBLISH packet to the Client greater than Topic Alias
/// Maximum [MQTT-3.1.2-26].
///
/// This test connects with Topic Alias Maximum=0, subscribes to a topic, publishes several messages, and verifies
/// none of the received messages contain a Topic Alias.
async fn topic_alias_maximum_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/connect/ta_zero";

    // Connect subscriber with topic_alias_maximum=0
    let mut sub_params = ConnectParams::new("mqtt-test-ta0-sub");
    sub_params.properties.topic_alias_maximum = Some(0);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtMostOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Publish several messages from another client to increase chance of alias use
    let pub_conn = ConnectParams::new("mqtt-test-ta0-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    for i in 0..5 {
        pub_client
            .send_publish(&PublishParams::qos0(
                topic,
                format!("ta0-msg-{i}").into_bytes(),
            ))
            .await?;
    }

    // Receive messages and verify none have a topic alias
    let mut received = 0;
    for _ in 0..5 {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                if let Some(alias) = p.properties.topic_alias {
                    return Ok(Outcome::fail(format!(
                        "Server sent Topic Alias {alias} to client with Topic Alias Maximum=0",
                    )));
                }
                received += 1;
            }
            _ => break,
        }
    }

    if received > 0 {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(
            "No messages received to verify topic alias behavior",
        ))
    }
}

// ── CONNACK before close on error ───────────────────────────────────────

const CONNACK_BEFORE_CLOSE: TestContext = TestContext {
    refs: &["MQTT-3.1.4-2"],
    description: "Server MAY send CONNACK with reason >= 0x80 before closing on error",
    compliance: Compliance::May,
};

/// The Server MAY check that the contents of the CONNECT packet meet any further restrictions and SHOULD perform
/// authentication and authorization checks. If any of these checks fail, it MUST close the Network
/// Connection [MQTT-3.1.4-2]. Before closing the Network Connection, it MAY send an appropriate CONNACK response
/// with a Reason Code of 0x80 or greater.
///
/// This test sends a CONNECT with reserved flags set (malformed) and checks whether the server sends a CONNACK with
/// an error reason code before closing.
async fn connack_before_close_on_error(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with reserved flag set (bit 0 = 1) — this is a malformed packet
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                       // CONNECT fixed header
        0x0F,                                       // remaining length = 15
        0x00, 0x04, b'M', b'Q', b'T', b'T',        // protocol name "MQTT"
        0x05,                                       // protocol version 5
        0x03,                                       // connect flags: clean start + reserved bit set
        0x00, 0x3C,                                 // keep alive = 60
        0x00,                                       // properties length = 0
        0x00, 0x00,                                 // client ID length = 0
    ];
    client.send_raw(bad_connect).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code >= 0x80 => Ok(Outcome::Pass),
        Ok(Packet::ConnAck(connack)) => Ok(Outcome::fail(format!(
            "CONNACK reason {:#04x} (expected >= 0x80 for malformed CONNECT)",
            connack.reason_code
        ))),
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => {
            // Server closed without sending CONNACK — allowed (it's a MAY)
            Ok(Outcome::unsupported(
                "Server closed connection without sending CONNACK before closing",
            ))
        }
        Err(RecvError::Timeout) => Ok(Outcome::unsupported(
            "broker did not respond to malformed CONNECT (timed out)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK", &other)),
    }
}
