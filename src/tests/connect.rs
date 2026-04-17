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

    // MQTT-3.1.0-1 — first packet MUST be CONNECT
    suite.add(FIRST_PACKET_PINGREQ, first_packet_pingreq_rejected(config));
    suite.add(FIRST_PACKET_AUTH, first_packet_auth_rejected(config));

    // MQTT-3.1.0-2 — second CONNECT is a Protocol Error
    suite.add(DUP_CONNECT, duplicate_connect(config));

    // MQTT-3.1.2-1 — protocol name MUST be "MQTT"
    suite.add(INVALID_PROTO_NAME, invalid_protocol_name(config));

    // MQTT-3.1.2-2 — Protocol Version MUST be 5
    suite.add(INVALID_PROTO_VER, invalid_protocol_version(config));

    // MQTT-3.2.2-3 — Clean Start=0, no prior session: CONNACK Session Present MUST be 0
    suite.add(CLEAN_START_FALSE, clean_start_false_no_session(config));

    // MQTT-3.1.2-8 — Will Message publication on abrupt close
    suite.add(WILL_ON_CLOSE, will_message_on_unexpected_close(config));

    // MQTT-3.1.2-10 — Will Message removal from Session State
    suite.add(
        WILL_REMOVED_ON_DISCONNECT,
        will_message_removed_on_disconnect(config),
    );
    suite.add(
        WILL_REMOVED_PERSISTS,
        will_removed_persists_across_resume(config),
    );
    suite.add(
        WILL_NOT_REPUBLISHED,
        will_not_republished_after_publish(config),
    );

    // MQTT-3.1.2-14 — Will Retain=0 → Will Message published as non-retained
    suite.add(WILL_NON_RETAINED, will_non_retained(config));

    // MQTT-3.1.2-15 — Will Retain=1 → Will Message published as retained
    suite.add(WILL_RETAIN, will_retain_flag(config));

    // MQTT-3.1.2-17 — User Name Flag=1 requires a User Name (positive cases)
    suite.add(EMPTY_USERNAME, empty_username(config));
    suite.add(USERNAME_ONLY, username_only(config));

    // MQTT-3.1.2-19 — Password Flag=1 requires a Password (positive case)
    suite.add(PASSWORD_NO_USERNAME, password_without_username(config));

    // MQTT-3.1.2-17 / MQTT-3.1.2-19 — Username + Password flags both set (positive case)
    suite.add(USERNAME_PASSWORD, username_password_accepted(config));

    // MQTT-3.1.2-22 — Server MUST close idle connection after 1.5× Keep Alive
    suite.add(KEEP_ALIVE, keep_alive_timeout(config));

    // MQTT-3.1.2-26 — Server MUST NOT send Topic Alias greater than Topic Alias Maximum
    suite.add(
        TOPIC_ALIAS_WITHIN_MAX,
        server_topic_alias_within_max(config),
    );

    // MQTT-3.1.2-27 — Topic Alias Maximum absent or zero: server MUST NOT send any Topic Aliases
    suite.add(TOPIC_ALIAS_MAX_ZERO, topic_alias_maximum_zero(config));
    suite.add(TOPIC_ALIAS_MAX_ABSENT, topic_alias_maximum_absent(config));

    // MQTT-3.1.2-28 — Request Response Information=0/absent: server MUST NOT return Response Info
    suite.add(
        RESP_INFO_ABSENT_DEFAULT,
        response_info_absent_when_not_requested(config),
    );
    suite.add(
        RESP_INFO_ABSENT_ZERO,
        response_info_absent_when_zero(config),
    );

    // MQTT-3.1.3-5 — Server MUST allow 1–23 byte alphanumeric ClientIDs (boundaries)
    suite.add(
        ACCEPTABLE_CLIENT_ID_MIN,
        acceptable_client_id_1_byte(config),
    );
    suite.add(
        ACCEPTABLE_CLIENT_ID_MAX,
        acceptable_client_id_23_bytes(config),
    );

    // MQTT-3.1.3-6 — Server MAY allow zero-length ClientID; MUST assign a unique Client Identifier
    suite.add(EMPTY_CLIENT_ID_ALLOWED, empty_client_id_allowed(config));
    suite.add(ASSIGNED_CLIENT_ID_UNIQUE, assigned_client_id_unique(config));

    // MQTT-3.1.3-7 — Server MUST return Assigned Client Identifier for zero-length ClientID
    suite.add(ASSIGNED_CLIENT_ID, assigned_client_id(config));

    // MQTT-3.1.3-8 — Server MAY reject ClientID with CONNACK 0x85, then MUST close
    suite.add(ZERO_LEN_CLIENT_ID, zero_length_client_id(config));

    // MQTT-3.1.3-9 — Reconnect within Will Delay MUST suppress the Will Message
    suite.add(
        WILL_DELAY_SUPPRESSED,
        will_delay_suppressed_on_reconnect(config),
    );

    // MQTT-3.1.3-10 — Server MUST maintain Will User Properties order when forwarding
    suite.add(WILL_USER_PROPS_ORDER, will_user_properties_order(config));

    // MQTT-3.1.4-2 — Server MAY further validate CONNECT, SHOULD auth/authz, MUST close on failure
    suite.add(ENHANCED_AUTH, enhanced_auth_method(config));
    suite.add(CONNACK_BEFORE_CLOSE, connack_before_close_on_error(config));

    // MQTT-3.1.4-4 / MQTT-3.1.4-5 — Clean Start processing; CONNACK 0x00 acknowledgement
    suite.add(BASIC_CONNECT, basic_connect(config));

    // ── reviewed up to here ─────────────────────────────────────────────────

    suite.add(CLEAN_START_TRUE, clean_start_true(config));
    suite.add(SERVER_MAX_QOS, server_maximum_qos(config));
    suite.add(SERVER_RECV_MAX, server_receive_maximum(config));
    suite.add(
        SESSION_PRESENT_ZERO_ON_REJECT,
        session_present_zero_on_reject(config),
    );
    suite.add(FLOW_CONTROL, flow_control_receive_maximum(config));

    suite
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const BASIC_CONNECT: TestContext = TestContext {
    refs: &["MQTT-3.2.0-1", "MQTT-3.1.4-4", "MQTT-3.1.4-5"],
    description: "Server MUST acknowledge CONNECT with CONNACK 0x00 (Success)",
    compliance: Compliance::Must,
};

/// The Server MUST send a CONNACK with a 0x00 (Success) Reason Code before sending any Packet other
/// than AUTH. [MQTT-3.2.0-1]
///
/// The Server MUST perform the processing of Clean Start. [MQTT-3.1.4-4]
///
/// The Server MUST acknowledge the CONNECT packet with a CONNACK packet containing a 0x00 (Success)
/// Reason Code. [MQTT-3.1.4-5]
///
/// This test sends a valid CONNECT with Clean Start=1 and verifies the server responds with a
/// successful CONNACK (reason code 0x00). `expect_connack_success` asserts reason_code == 0x00,
/// covering the -3.1.4-5 MUST. The Clean Start=1 path implicitly exercises the -3.1.4-4 processing
/// obligation; dedicated Clean Start behaviour is tested in [session.rs] and `clean_start_true`.
async fn basic_connect(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-basic-connect");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const CLEAN_START_TRUE: TestContext = TestContext {
    refs: &["MQTT-3.2.2-2"],
    description: "Clean Start=1 accepted: CONNACK Session Present MUST be 0",
    compliance: Compliance::Must,
};

/// If the Server accepts a connection with Clean Start set to 1, the Server MUST set Session Present
/// to 0 in the CONNACK packet in addition to setting a 0x00 (Success) Reason Code in the CONNACK
/// packet. [MQTT-3.2.2-2]
///
/// This test connects with Clean Start=1 and verifies session_present=0 in CONNACK. Note: the
/// observable behaviour of MQTT-3.1.2-4 (discarding any existing Session) is tested separately in
/// [session.rs] `clean_start_discards_existing_session`.
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
    description: "Clean Start=0 with no prior Session: CONNACK Session Present MUST be 0",
    compliance: Compliance::Must,
};

/// If the Server accepts a connection with Clean Start set to 0 and the Server has Session State
/// for the ClientID, it MUST set Session Present to 1 in the CONNACK packet, otherwise it MUST set
/// Session Present to 0 in the CONNACK packet. In both cases it MUST set a 0x00 (Success) Reason
/// Code in the CONNACK packet. [MQTT-3.2.2-3]
///
/// This test exercises the "no Session State" branch: it connects with Clean Start=0 using a fresh
/// (timestamp-derived) Client ID unlikely to have a prior session, and verifies CONNACK
/// session_present=0. The complementary "Session State exists" branch is covered by
/// [session.rs] `session_present_on_resume`.
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
    refs: &["MQTT-3.1.3-8"],
    description: "Server MAY reject zero-length ClientID with CONNACK 0x85",
    compliance: Compliance::May,
};

/// If the Server rejects the ClientID it MAY respond to the CONNECT packet with a CONNACK using
/// Reason Code 0x85 (Client Identifier not valid) as described in section 4.13 Handling errors,
/// and then it MUST close the Network Connection. [MQTT-3.1.3-8]
///
/// This test connects with a zero-length client ID and Clean Start=0. YES if the broker rejects
/// (either with 0x85 or a clean connection close); NO if the broker accepts the CONNECT or
/// rejects with a different reason code — neither is a protocol violation under the MAY clause.
async fn zero_length_client_id(config: TestConfig<'_>) -> Result<Outcome> {
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
    refs: &["MQTT-3.1.3-7"],
    description: "Server MUST return Assigned Client Identifier in CONNACK for zero-length ClientID",
    compliance: Compliance::Must,
};

/// If a Server receives a zero length ClientID, it MUST process the CONNECT packet as if the
/// Client had provided that unique ClientID, and MUST return the Assigned Client Identifier in
/// the CONNACK packet. [MQTT-3.1.3-7]
///
/// This test connects with a zero-length client ID and verifies the CONNACK contains an
/// Assigned Client Identifier property. Skips cleanly if the broker exercises its MAY right
/// under MQTT-3.1.3-6 to reject empty ClientIDs.
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

const EMPTY_CLIENT_ID_ALLOWED: TestContext = TestContext {
    refs: &["MQTT-3.1.3-6"],
    description: "Server MAY allow a Client to supply a ClientID of zero bytes",
    compliance: Compliance::May,
};

/// A Server MAY allow a Client to supply a ClientID that has a length of zero bytes. [MQTT-3.1.3-6]
///
/// This test connects with Clean Start=1 and an empty ClientID. The MAY clause of MQTT-3.1.3-6
/// means a broker is free to accept or reject: YES if the broker accepts, NO if the broker
/// rejects — neither is a protocol violation. The companion MUST clause (unique assigned
/// identifier) is covered by `assigned_client_id_unique`.
async fn empty_client_id_allowed(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("");
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => {
            let _ = client.send_disconnect(0x00).await;
            Ok(Outcome::Pass)
        }
        Ok(Packet::ConnAck(connack)) => Ok(Outcome::unsupported(format!(
            "Broker rejected empty ClientID (reason {:#04x})",
            connack.reason_code
        ))),
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::unsupported(
            "Broker closed connection rather than accepting empty ClientID",
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "broker did not respond to CONNECT (timed out)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("CONNACK", &other)),
    }
}

const ASSIGNED_CLIENT_ID_UNIQUE: TestContext = TestContext {
    refs: &["MQTT-3.1.3-6", "MQTT-3.2.2-16"],
    description: "Concurrent empty ClientIDs MUST receive distinct Assigned Client Identifiers",
    compliance: Compliance::Must,
};

/// A Server MAY allow a Client to supply a ClientID that has a length of zero bytes, however if it
/// does so the Server MUST treat this as a special case and assign a unique ClientID to that
/// Client. [MQTT-3.1.3-6]
///
/// This test opens two overlapping sessions each supplying an empty ClientID, collects both
/// Assigned Client Identifiers from their CONNACKs, and verifies they differ. Both sessions
/// remain open at the point of the second assignment to exercise the "unique" requirement
/// (MQTT-3.2.2-16: "not used by any other Session currently in the Server").
async fn assigned_client_id_unique(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("");

    let (_client_a, connack_a) = client::connect(config.addr, &params, config.recv_timeout).await?;
    if connack_a.reason_code != 0x00 {
        return Ok(Outcome::skip(format!(
            "Broker rejected first empty client ID (reason {:#04x})",
            connack_a.reason_code
        )));
    }
    let Some(id_a) = connack_a.properties.assigned_client_id.clone() else {
        return Ok(Outcome::skip(
            "Broker accepted empty client ID but did not return Assigned Client Identifier",
        ));
    };

    // Open a second session while the first is still active.
    let (_client_b, connack_b) = client::connect(config.addr, &params, config.recv_timeout).await?;
    if connack_b.reason_code != 0x00 {
        return Ok(Outcome::skip(format!(
            "Broker rejected second empty client ID (reason {:#04x})",
            connack_b.reason_code
        )));
    }
    let Some(id_b) = connack_b.properties.assigned_client_id.clone() else {
        return Ok(Outcome::skip(
            "Broker did not return Assigned Client Identifier for second session",
        ));
    };

    if id_a == id_b {
        return Ok(Outcome::fail(format!(
            "Broker returned identical Assigned Client Identifier {id_a:?} for two concurrent empty-ClientID sessions"
        )));
    }

    Ok(Outcome::Pass)
}

const FIRST_PACKET_PINGREQ: TestContext = TestContext {
    refs: &["MQTT-3.1.0-1"],
    description: "Server MUST close connection if first packet is PINGREQ instead of CONNECT",
    compliance: Compliance::Must,
};

/// After a Network Connection is established by a Client to a Server, the first packet sent from
/// the Client to the Server MUST be a CONNECT packet. [MQTT-3.1.0-1]
///
/// This test sends a PINGREQ as the first packet (instead of CONNECT) and verifies the server
/// closes the connection.
async fn first_packet_pingreq_rejected(config: TestConfig<'_>) -> Result<Outcome> {
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

const FIRST_PACKET_AUTH: TestContext = TestContext {
    refs: &["MQTT-3.1.0-1"],
    description: "Server MUST close connection if first packet is AUTH instead of CONNECT",
    compliance: Compliance::Must,
};

/// After a Network Connection is established by a Client to a Server, the first packet sent from
/// the Client to the Server MUST be a CONNECT packet. [MQTT-3.1.0-1]
///
/// This test sends an AUTH packet as the first packet (instead of CONNECT) and verifies the
/// server closes the connection. AUTH is a plausible violation candidate because §3.15 allows
/// AUTH exchanges during an enhanced authentication flow — but only after a CONNECT with an
/// Authentication Method property.
async fn first_packet_auth_rejected(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Minimal AUTH packet: 0xF0 fixed header, remaining length 0 (reason code and properties
    // omitted — per §3.15.2.1 this is valid when reason code = 0x00 and no properties).
    client.send_raw(&[0xF0, 0x00]).await?;

    match client.recv().await {
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Auth { .. }) => Ok(Outcome::fail(
            "Broker responded to AUTH without prior CONNECT",
        )),
        Ok(other) => Ok(Outcome::fail_packet("connection close", &other)),
    }
}

// ── Protocol violations ─────────────────────────────────────────────────────

const DUP_CONNECT: TestContext = TestContext {
    refs: &["MQTT-3.1.0-2"],
    description: "Server MUST treat a second CONNECT as a Protocol Error and close the connection",
    compliance: Compliance::Must,
};

/// The Server MUST process a second CONNECT Packet sent from a Client as a Protocol Error and
/// close the Network Connection. [MQTT-3.1.0-2]
///
/// This test completes a normal CONNECT/CONNACK handshake, then sends a second CONNECT on the
/// same connection and verifies the broker closes the connection (with or without a DISCONNECT).
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
    description: "Server MUST close the Network Connection if the protocol name is not \"MQTT\"",
    compliance: Compliance::Must,
};

/// The protocol name MUST be the UTF-8 String "MQTT". If the Server does not want to accept the
/// CONNECT, and wishes to reveal that it is an MQTT Server it MAY send a CONNACK packet with
/// Reason Code of 0x84 (Unsupported Protocol Version), and then it MUST close the Network
/// Connection. [MQTT-3.1.2-1]
///
/// This test sends a CONNECT with protocol name "XQTT" instead of "MQTT" and verifies the broker
/// closes the connection (the optional CONNACK 0x84 is accepted but not required).
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
    description: "Server MUST close the Network Connection if the Protocol Version is not 5",
    compliance: Compliance::Must,
};

/// If the Protocol Version is not 5 and the Server does not want to accept the CONNECT packet, the
/// Server MAY send a CONNACK packet with Reason Code 0x84 (Unsupported Protocol Version) and then
/// MUST close the Network Connection [MQTT-3.1.2-2].
///
/// This test sends a CONNECT with protocol version 4 (MQTT 3.1.1) and verifies the broker closes
/// the connection (the optional CONNACK 0x84 is accepted; brokers that accept v3.1.1 in dual-mode
/// are reported as unsupported for this v5-only assertion).
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

/// If the Keep Alive value is non-zero and the Server does not receive an MQTT Control Packet from
/// the Client within one and a half times the Keep Alive time period, it MUST close the Network
/// Connection to the Client as if the network had failed. [MQTT-3.1.2-22]
///
/// This test connects with Keep Alive=2s, sends no further packets, and waits up to 5s for the
/// broker to close the connection (the spec requires closure within 1.5 × 2s = 3s; 5s is a generous
/// upper bound to absorb scheduling jitter). A clean TCP close or a DISCONNECT from the broker both
/// satisfy "close the Network Connection". A timeout (broker never closed) is a fail.
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
    description: "Will Message MUST be published after abrupt Network Connection close",
    compliance: Compliance::Must,
};

/// The Will Message MUST be published after the Network Connection is subsequently closed and
/// either the Will Delay Interval has elapsed or the Session ends, unless the Will Message has been
/// deleted by the Server on receipt of a DISCONNECT packet with Reason Code 0x00 (Normal
/// disconnection) or a new Network Connection for the ClientID is opened before the Will Delay
/// Interval has elapsed. [MQTT-3.1.2-8]
///
/// This test exercises the base case under default settings: connects with a Will Message and no
/// Will Delay Interval (defaults to 0 — "no delay before the Will Message is published" per
/// §3.1.3.2.2) and no Session Expiry Interval (defaults to 0 — Session ends immediately on close).
/// Both branches of the "either … or …" therefore trigger at t=0, so the Will should be published
/// promptly. The 5-second timeout is a generous bound for broker processing latency. Drops the
/// connection without sending DISCONNECT and verifies the Will is delivered to a subscriber.
///
/// Complementary clauses are covered by [disconnect.rs] `disconnect_with_will` (non-0x00 DISCONNECT
/// still publishes), [disconnect.rs] `will_delay_interval` (Will Delay Interval delays publication
/// when SEI is large enough that the Session does not end first), and
/// [disconnect.rs] `will_publishes_on_session_end` (Session ends before Will Delay elapses).
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
    description: "Will Message MUST NOT be published after a DISCONNECT with Reason Code 0x00",
    compliance: Compliance::Must,
};

/// The Will Message MUST be removed from the stored Session State in the Server once it has been
/// published or the Server has received a DISCONNECT packet with a Reason Code of 0x00 (Normal
/// disconnection) from the Client. [MQTT-3.1.2-10]
///
/// This test exercises the in-connection effect of the rule: connects with a Will Message,
/// disconnects with Reason Code 0x00, and verifies a subscriber receives no Will publication.
/// Companion tests `will_removed_persists_across_resume` and `will_not_republished_after_publish`
/// verify removal across session resume.
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

const WILL_REMOVED_PERSISTS: TestContext = TestContext {
    refs: &["MQTT-3.1.2-10"],
    description: "Will removed by 0x00 DISCONNECT MUST stay removed across Session resume",
    compliance: Compliance::Must,
};

/// The Will Message MUST be removed from the stored Session State in the Server once it has been
/// published or the Server has received a DISCONNECT packet with a Reason Code of 0x00 (Normal
/// disconnection) from the Client. [MQTT-3.1.2-10]
///
/// This test verifies the Will is removed from *Session State* (not just from the closed
/// connection): connects with Session Expiry Interval=60 and a Will Message, sends DISCONNECT with
/// Reason Code 0x00 (which MUST remove the Will from the persisted Session), reconnects with the
/// same Client ID and Clean Start=0 (resuming the Session) but without supplying a new Will, then
/// drops the second connection abruptly. A subscriber MUST NOT receive any Will publication — if
/// the broker had retained the original Will in Session State despite the 0x00 DISCONNECT, the
/// abrupt close of the resumed connection would fire it.
async fn will_removed_persists_across_resume(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-will-rem-persist";
    let will_topic = "mqtt/test/will/removed_persists";

    // Subscriber for the will topic.
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-rem-persist-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // 1. Connect with persistent session + Will, then send DISCONNECT 0x00.
    let mut will_params = ConnectParams::new(client_id);
    will_params.will = Some(WillParams::new(will_topic, b"should-not-arrive"));
    will_params.properties.session_expiry_interval = Some(60);
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;
    let mut raw1 = will_client.into_raw();
    raw1.send_disconnect(0x00).await?;
    drop(raw1);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 2. Reconnect resuming the session, no new Will. Then abruptly close.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (c2, _) = client::connect(config.addr, &params2, config.recv_timeout).await?;
    drop(c2.into_raw()); // abrupt close — no DISCONNECT

    // 3. Subscriber MUST NOT receive any Will publication.
    let result = match sub_client.recv_with_timeout(Duration::from_secs(3)).await {
        Err(RecvError::Timeout) | Err(RecvError::Closed) => Outcome::Pass,
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Outcome::fail(
            "Will fired on the resumed connection's abrupt close — broker did not remove the Will from Session State after DISCONNECT 0x00",
        ),
        Ok(_) => Outcome::Pass,
    };

    // Cleanup: clear the persistent session.
    let mut cleanup = ConnectParams::new(client_id);
    cleanup.clean_start = true;
    let _ = client::connect(config.addr, &cleanup, config.recv_timeout).await;

    Ok(result)
}

const WILL_NOT_REPUBLISHED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-10"],
    description: "Will MUST NOT be published a second time after it has already fired",
    compliance: Compliance::Must,
};

/// The Will Message MUST be removed from the stored Session State in the Server once it has been
/// published or the Server has received a DISCONNECT packet with a Reason Code of 0x00 (Normal
/// disconnection) from the Client. [MQTT-3.1.2-10]
///
/// This test verifies the "once it has been published" clause: connects with Session Expiry
/// Interval=60 and a Will Message, abruptly closes the network connection so the Will fires (per
/// MQTT-3.1.2-8) and consumes that publication, reconnects with the same Client ID and
/// Clean Start=0 (resuming the Session) without supplying a new Will, then abruptly closes again.
/// A subscriber MUST NOT receive a second Will publication — if the broker failed to remove the
/// Will from Session State after publishing it, the second abrupt close would fire it again.
async fn will_not_republished_after_publish(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-will-norepub";
    let will_topic = "mqtt/test/will/norepublish";

    // Subscriber for the will topic.
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-norepub-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // 1. Connect with persistent session + Will, then drop abruptly so the Will fires.
    let mut will_params = ConnectParams::new(client_id);
    will_params.will = Some(WillParams::new(will_topic, b"first-fire"));
    will_params.properties.session_expiry_interval = Some(60);
    let (c1, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;
    drop(c1.into_raw()); // abrupt — Will fires.

    // 2. Wait for and consume the first Will publication.
    match sub_client.recv_with_timeout(Duration::from_secs(5)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => {} // expected first fire
        Ok(other) => {
            // Cleanup before bailing.
            let mut cleanup = ConnectParams::new(client_id);
            cleanup.clean_start = true;
            let _ = client::connect(config.addr, &cleanup, config.recv_timeout).await;
            return Ok(Outcome::fail_packet("first Will PUBLISH", &other));
        }
        Err(_) => {
            let mut cleanup = ConnectParams::new(client_id);
            cleanup.clean_start = true;
            let _ = client::connect(config.addr, &cleanup, config.recv_timeout).await;
            return Ok(Outcome::fail(
                "First Will did not fire — cannot test republish suppression",
            ));
        }
    }

    // 3. Reconnect resuming the session, no new Will. Then abruptly close.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (c2, _) = client::connect(config.addr, &params2, config.recv_timeout).await?;
    drop(c2.into_raw()); // abrupt — should NOT fire a second Will.

    // 4. Verify subscriber receives no second Will publication.
    let result = match sub_client.recv_with_timeout(Duration::from_secs(3)).await {
        Err(RecvError::Timeout) | Err(RecvError::Closed) => Outcome::Pass,
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Outcome::fail(
            "Will fired a second time on the resumed connection's abrupt close — broker did not remove the Will from Session State after publishing it",
        ),
        Ok(_) => Outcome::Pass,
    };

    // Cleanup: clear the persistent session.
    let mut cleanup = ConnectParams::new(client_id);
    cleanup.clean_start = true;
    let _ = client::connect(config.addr, &cleanup, config.recv_timeout).await;

    Ok(result)
}

const WILL_RETAIN: TestContext = TestContext {
    refs: &["MQTT-3.1.2-15"],
    description: "Will Retain flag MUST be respected when will message is published",
    compliance: Compliance::Must,
};

/// If the Will Flag is set to 1 and Will Retain is set to 1, the Server MUST publish the Will
/// Message as a retained message. [MQTT-3.1.2-15]
///
/// This test connects with Will Retain=1, drops the connection to trigger the Will, then has a
/// fresh subscriber connect and verifies the Will is delivered with the Retain flag set (i.e. was
/// stored as a retained message on the Will Topic).
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

const WILL_DELAY_SUPPRESSED: TestContext = TestContext {
    refs: &["MQTT-3.1.3-9"],
    description: "Reconnect within Will Delay Interval MUST suppress the Will Message",
    compliance: Compliance::Must,
};

/// If a new Network Connection to this Session is made before the Will Delay Interval has passed,
/// the Server MUST NOT send the Will Message. [MQTT-3.1.3-9]
///
/// This test connects a publisher with Will Delay Interval=2s and Session Expiry Interval=60s,
/// abruptly drops the connection, then reconnects the same ClientID with Clean Start=0 well
/// within the Will Delay window. It verifies that the subscriber receives no Will message even
/// after the original Will Delay deadline has passed — the new connection must suppress it.
async fn will_delay_suppressed_on_reconnect(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/will/suppressed";
    let publisher_id = "mqtt-test-will-suppressed-pub";

    // Subscriber — observes that no Will arrives.
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-suppressed-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publisher with Will Delay=2s, SEI=60s so the Session survives the abrupt close.
    let mut will_params = ConnectParams::new(publisher_id);
    will_params.will = Some(WillParams {
        topic: will_topic.to_string(),
        payload: b"should-not-arrive".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        properties: Properties {
            will_delay_interval: Some(2),
            ..Properties::default()
        },
    });
    will_params.properties.session_expiry_interval = Some(60);
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Abrupt disconnect — starts the Will Delay countdown.
    drop(will_client.into_raw());

    // Reconnect well within the 2s Will Delay window using the same ClientID and Clean Start=0.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut resume_params = ConnectParams::new(publisher_id);
    resume_params.clean_start = false;
    resume_params.properties.session_expiry_interval = Some(60);
    let (_resume_client, _) =
        client::connect(config.addr, &resume_params, config.recv_timeout).await?;

    // Wait past the original Will Delay deadline and confirm nothing arrives.
    match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(Outcome::fail(format!(
            "Will published after reconnect within Will Delay — spec requires suppression (payload: {:?})",
            String::from_utf8_lossy(&p.payload)
        ))),
        Ok(other) => Ok(Outcome::fail_packet("no packet (expected silence)", &other)),
        Err(RecvError::Closed) => Ok(Outcome::fail("subscriber connection closed unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

const WILL_USER_PROPS_ORDER: TestContext = TestContext {
    refs: &["MQTT-3.1.3-10"],
    description: "Will User Properties order MUST be maintained when forwarding",
    compliance: Compliance::Must,
};

/// The Server MUST maintain the order of User Properties when forwarding the Application Message.
/// [MQTT-3.1.3-10]
///
/// This test applies MQTT-3.1.3-10 specifically to the Will Message (a distinct code path from
/// ordinary PUBLISH forwarding, which is covered by MQTT-3.3.2-18 in [publish.rs]). Connects a
/// publisher with a Will containing three User Properties in a known order, drops the connection
/// abruptly, and verifies the subscriber receives the Will with User Properties in the same order.
async fn will_user_properties_order(config: TestConfig<'_>) -> Result<Outcome> {
    let will_topic = "mqtt/test/will/up_order";

    // Subscriber
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-will-uporder-sub",
        will_topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let ordered_props = vec![
        ("k1".to_string(), "v1".to_string()),
        ("k2".to_string(), "v2".to_string()),
        ("k3".to_string(), "v3".to_string()),
    ];

    // Publisher with a Will carrying ordered User Properties.
    let mut will_params = ConnectParams::new("mqtt-test-will-uporder-pub");
    will_params.will = Some(WillParams {
        topic: will_topic.to_string(),
        payload: b"will-ordered".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        properties: Properties {
            user_properties: ordered_props.clone(),
            ..Properties::default()
        },
    });
    let (will_client, _) = client::connect(config.addr, &will_params, config.recv_timeout).await?;

    // Abrupt disconnect — triggers Will publication (no Will Delay, default SEI=0).
    drop(will_client.into_raw());

    match sub_client.recv_with_timeout(Duration::from_secs(5)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => {
            if p.properties.user_properties == ordered_props {
                Ok(Outcome::Pass)
            } else if p.properties.user_properties.is_empty() {
                Ok(Outcome::fail(
                    "No user properties in forwarded Will message",
                ))
            } else {
                Ok(Outcome::fail(format!(
                    "Will user properties order not maintained: expected {:?}, got {:?}",
                    ordered_props, p.properties.user_properties
                )))
            }
        }
        Ok(other) => Ok(Outcome::fail_packet("PUBLISH (Will message)", &other)),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "Will message not received after unexpected disconnect",
        )),
        Err(RecvError::Closed) => Ok(Outcome::fail("subscriber connection closed unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

// ── Request/Response Information ────────────────────────────────────────────

const RESP_INFO_ABSENT_DEFAULT: TestContext = TestContext {
    refs: &["MQTT-3.1.2-28"],
    description: "Request Response Information absent (default 0): CONNACK MUST NOT carry Response Information",
    compliance: Compliance::Must,
};

/// A value of 0 indicates that the Server MUST NOT return Response Information. [MQTT-3.1.2-28]
///
/// Covers the default (absent) half of the rule: §3.1.2.11.6 says Request Response Information is
/// a 0/1 flag defaulting to 0 when absent. This test connects WITHOUT the property in CONNECT and
/// verifies the CONNACK does not include a Response Information property. Companion to
/// `response_info_absent_when_zero`, which covers the explicit-zero case.
async fn response_info_absent_when_not_requested(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-resp-info-absent");
    assert!(
        params.properties.request_response_information.is_none(),
        "property must be absent for this test"
    );

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if let Some(info) = connack.properties.response_information {
        Ok(Outcome::fail(format!(
            "Server returned Response Information ({info:?}) despite Request Response Information being absent (default 0)",
        )))
    } else {
        Ok(Outcome::Pass)
    }
}

const RESP_INFO_ABSENT_ZERO: TestContext = TestContext {
    refs: &["MQTT-3.1.2-28"],
    description: "Request Response Information=0: CONNACK MUST NOT carry Response Information",
    compliance: Compliance::Must,
};

/// A value of 0 indicates that the Server MUST NOT return Response Information. [MQTT-3.1.2-28]
///
/// Covers the explicit-zero half of the rule. A broker may conceivably treat the absent property
/// as a request (incorrectly defaulting to 1), so this test pins down the explicit-0 case as
/// well: connect with Request Response Information=0 and verify the CONNACK does not carry a
/// Response Information property. Companion to `response_info_absent_when_not_requested`.
async fn response_info_absent_when_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let mut params = ConnectParams::new("mqtt-test-resp-info-zero");
    params.properties.request_response_information = Some(false);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if let Some(info) = connack.properties.response_information {
        Ok(Outcome::fail(format!(
            "Server returned Response Information ({info:?}) despite Request Response Information=0",
        )))
    } else {
        Ok(Outcome::Pass)
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

// ── SHOULD ──────────────────────────────────────────────────────────────────

const ACCEPTABLE_CLIENT_ID_MIN: TestContext = TestContext {
    refs: &["MQTT-3.1.3-5"],
    description: "Server MUST accept a 1-byte client ID from [0-9a-zA-Z]",
    compliance: Compliance::Must,
};

/// The Server MUST allow ClientID's which are between 1 and 23 UTF-8 encoded bytes in length, and
/// that contain only the characters
/// "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ". [MQTT-3.1.3-5]
///
/// This test connects with a single-character client ID ("a") drawn from the recommended alphabet
/// — the lower boundary of the mandated length range.
async fn acceptable_client_id_1_byte(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("a");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    Ok(expect_connack_success(connack).into_outcome())
}

const ACCEPTABLE_CLIENT_ID_MAX: TestContext = TestContext {
    refs: &["MQTT-3.1.3-5"],
    description: "Server MUST accept a 23-byte client ID from [0-9a-zA-Z]",
    compliance: Compliance::Must,
};

/// The Server MUST allow ClientID's which are between 1 and 23 UTF-8 encoded bytes in length, and
/// that contain only the characters
/// "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ". [MQTT-3.1.3-5]
///
/// This test connects with a 23-character client ID drawn from the recommended alphabet — the
/// upper boundary of the mandated length range.
async fn acceptable_client_id_23_bytes(config: TestConfig<'_>) -> Result<Outcome> {
    // Exactly 23 bytes from the mandated character set.
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

// ── Username / Password ─────────────────────────────────────────────────────

const USERNAME_PASSWORD: TestContext = TestContext {
    refs: &["MQTT-3.1.2-17", "MQTT-3.1.2-19"],
    description: "Server MUST accept CONNECT with Username and Password flags both set",
    compliance: Compliance::Must,
};

/// If the User Name Flag is set to 1, a User Name MUST be present in the Payload. [MQTT-3.1.2-17]
///
/// If the Password Flag is set to 1, a Password MUST be present in the Payload. [MQTT-3.1.2-19]
///
/// Positive case: this test sends a CONNECT with BOTH the Username and Password flags set, with a
/// non-empty User Name and Password in the Payload, and verifies the server accepts it. The
/// individual-flag variants are covered by `empty_username`, `username_only`, and
/// `password_without_username`; this test is the combined case.
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

/// If the Password Flag is set to 1, a Password MUST be present in the Payload. [MQTT-3.1.2-19]
///
/// Positive case: this test sends a CONNECT with the Password flag set (and a Password in the
/// Payload) but no Username flag — valid in MQTT v5, which removed the v3.1.1 restriction requiring
/// a Username whenever a Password is present — and verifies the server accepts it.
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

/// If the User Name Flag is set to 1, a User Name MUST be present in the Payload. [MQTT-3.1.2-17]
///
/// Positive case: this test sends a CONNECT with the Username flag set and a zero-length UTF-8
/// string as the User Name. A zero-length string is a valid User Name, so the User Name IS present
/// in the Payload — the server must accept it.
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

/// If the User Name Flag is set to 1, a User Name MUST be present in the Payload. [MQTT-3.1.2-17]
///
/// Positive case: this test sends a CONNECT with the Username flag set and a non-empty User Name
/// (no Password flag), and verifies the server accepts it.
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

/// If the Will Flag is set to 1 and Will Retain is set to 0, the Server MUST publish the Will
/// Message as a non-retained message. [MQTT-3.1.2-14]
///
/// This test connects with Will Retain=0, drops the connection to trigger the Will, and then has a
/// fresh subscriber connect after the fact — verifying the Will was NOT stored as a retained
/// message on the Will Topic (a subsequent subscriber receives nothing).
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
    refs: &["MQTT-3.1.2-26", "MQTT-3.1.2-27"],
    description: "Topic Alias Maximum=0: server MUST NOT send any Topic Aliases to client",
    compliance: Compliance::Must,
};

/// If Topic Alias Maximum is absent or zero, the Server MUST NOT send any Topic Aliases to the
/// Client. [MQTT-3.1.2-27]
///
/// This test covers the explicit Topic Alias Maximum=0 case: subscriber connects with
/// topic_alias_maximum=0, publisher sends 5 messages on one topic, and none of the forwarded
/// PUBLISH packets may carry a `topic_alias` property. The "absent" half of the rule is covered
/// by `topic_alias_maximum_absent`. Any non-zero alias would be both >0 and >Maximum, so this is
/// also the strongest possible check for MQTT-3.1.2-26 in the Max=0 regime.
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

const TOPIC_ALIAS_MAX_ABSENT: TestContext = TestContext {
    refs: &["MQTT-3.1.2-26", "MQTT-3.1.2-27"],
    description: "Topic Alias Maximum absent: server MUST NOT send any Topic Aliases to client",
    compliance: Compliance::Must,
};

/// If Topic Alias Maximum is absent or zero, the Server MUST NOT send any Topic Aliases to the
/// Client. [MQTT-3.1.2-27]
///
/// This test covers the "absent" half of the rule. A broker may conceivably default a missing
/// Topic Alias Maximum to something other than zero (e.g. a broker-configured maximum), which
/// would be non-compliant. Subscriber connects WITHOUT a `topic_alias_maximum` property in
/// CONNECT, subscribes, publisher sends 5 messages, and none of the forwarded PUBLISH packets may
/// carry a `topic_alias` property. Companion to `topic_alias_maximum_zero`, which covers the
/// explicit-zero half.
async fn topic_alias_maximum_absent(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/connect/ta_absent";

    // Connect subscriber WITHOUT topic_alias_maximum (property absent).
    let sub_params = ConnectParams::new("mqtt-test-ta-absent-sub");
    assert!(
        sub_params.properties.topic_alias_maximum.is_none(),
        "property must be absent for this test"
    );
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtMostOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    let pub_conn = ConnectParams::new("mqtt-test-ta-absent-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    for i in 0..5 {
        pub_client
            .send_publish(&PublishParams::qos0(
                topic,
                format!("ta-absent-msg-{i}").into_bytes(),
            ))
            .await?;
    }

    let mut received = 0;
    for _ in 0..5 {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                if let Some(alias) = p.properties.topic_alias {
                    return Ok(Outcome::fail(format!(
                        "Server sent Topic Alias {alias} to client that did not advertise Topic Alias Maximum",
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

// ── Topic Alias Maximum>0 boundary ──────────────────────────────────────

const TOPIC_ALIAS_WITHIN_MAX: TestContext = TestContext {
    refs: &["MQTT-3.1.2-26"],
    description: "Server MUST NOT send Topic Alias greater than client's Topic Alias Maximum",
    compliance: Compliance::Must,
};

/// The Server MUST NOT send a Topic Alias in a PUBLISH packet to the Client greater than Topic
/// Alias Maximum. [MQTT-3.1.2-26]
///
/// This test exercises the general Max>0 boundary that the Max=0 test cannot reach. Subscriber
/// connects with Topic Alias Maximum=2 and subscribes to a wildcard `mqtt/test/ta_cap/+`. A
/// separate publisher sends 10 QoS 0 messages to distinct topics beneath that prefix — enough
/// distinct topics that a broker using aliases would exhaust the permitted range (1..=2) and be
/// tempted to either allocate alias=3 or evict/reuse existing aliases. The test scans every
/// forwarded PUBLISH: any `topic_alias` value outside 1..=2 is a fail. If no PUBLISH ever carries
/// a `topic_alias` property (broker opts not to use aliases at all, which is permitted), the
/// outcome is SKIP rather than PASS — a vacuous pass would hide genuine violations on brokers
/// that do emit aliases.
async fn server_topic_alias_within_max(config: TestConfig<'_>) -> Result<Outcome> {
    let prefix = "mqtt/test/ta_cap";
    let filter = format!("{prefix}/+");
    const MAX: u16 = 2;
    const N_TOPICS: usize = 10;

    let mut sub_params = ConnectParams::new("mqtt-test-ta-cap-sub");
    sub_params.properties.topic_alias_maximum = Some(MAX);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, &filter, QoS::AtMostOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    let pub_conn = ConnectParams::new("mqtt-test-ta-cap-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    for i in 0..N_TOPICS {
        let topic = format!("{prefix}/t{i}");
        pub_client
            .send_publish(&PublishParams::qos0(topic, format!("msg-{i}").into_bytes()))
            .await?;
    }

    let mut any_alias_seen = false;
    for _ in 0..N_TOPICS {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(p)) if p.topic.starts_with(prefix) => {
                if let Some(alias) = p.properties.topic_alias {
                    any_alias_seen = true;
                    if alias == 0 || alias > MAX {
                        return Ok(Outcome::fail(format!(
                            "Server sent Topic Alias {alias} to client with Topic Alias Maximum={MAX}",
                        )));
                    }
                }
            }
            _ => break,
        }
    }

    if any_alias_seen {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::skip(
            "Broker did not use Topic Aliases on server-to-client PUBLISH — vacuous pass avoided",
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
