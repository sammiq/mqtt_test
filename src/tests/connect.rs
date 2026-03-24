//! CONNECT / CONNACK compliance tests [MQTT-3.1 / MQTT-3.2].

use std::time::Duration;

use crate::client::{self, RawClient};
use crate::codec::{
    ConnectParams, Packet, Properties, PublishParams, QoS, SubscribeParams, WillParams,
};
use crate::types::{Compliance, SuiteRunner, TestConfig, TestContext, TestResult};

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

/// A valid CONNECT MUST receive a CONNACK in return [MQTT-3.2.0-1].
async fn basic_connect(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = BASIC_CONNECT;

    let params = ConnectParams::new("mqtt-test-basic-connect");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "CONNACK reason code {:#04x} (expected 0x00)",
                connack.reason_code
            ),
        ))
    }
}

const CLEAN_START_TRUE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-4", "MQTT-3.2.2-2"],
    description: "Clean Start=1: server MUST start a new session (session_present=0)",
    compliance: Compliance::Must,
};

/// Clean Start = 1 MUST create a new session [MQTT-3.1.2-4].
async fn clean_start_true(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CLEAN_START_TRUE;

    let params = ConnectParams::new("mqtt-test-clean-start");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.session_present {
        Ok(TestResult::fail(
            &ctx,
            "CONNACK session_present=1 despite Clean Start=1",
        ))
    } else {
        Ok(TestResult::pass(&ctx))
    }
}

const CLEAN_START_FALSE: TestContext = TestContext {
    refs: &["MQTT-3.2.2-4"],
    description: "Clean Start=0 with no prior session: session_present MUST be 0",
    compliance: Compliance::Must,
};

/// Clean Start = 0 with no existing session MUST set session_present=0 [MQTT-3.2.2-4].
async fn clean_start_false_no_session(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CLEAN_START_FALSE;

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
        Ok(TestResult::fail(
            &ctx,
            "CONNACK session_present=1 but no prior session should exist",
        ))
    } else {
        Ok(TestResult::pass(&ctx))
    }
}

const ZERO_LEN_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.1.3-7"],
    description: "Zero-length client ID with Clean Start=1 MUST be accepted",
    compliance: Compliance::Must,
};

/// Zero-length client ID with Clean Start=1 MUST be accepted [MQTT-3.1.3-7].
async fn zero_length_client_id(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = ZERO_LEN_CLIENT_ID;

    let params = ConnectParams::new("");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.reason_code {
        0x00 => Ok(TestResult::pass(&ctx)),
        code => Ok(TestResult::fail(
            &ctx,
            format!("CONNACK reason code {code:#04x}; broker rejected empty client ID"),
        )),
    }
}

const ZERO_LEN_NO_CLEAN: TestContext = TestContext {
    refs: &["MQTT-3.1.3-8"],
    description: "Zero-length client ID with Clean Start=0 MAY be rejected with 0x85",
    compliance: Compliance::May,
};

/// Zero-length client ID with Clean Start=0 MAY be rejected [MQTT-3.1.3-8].
async fn zero_length_client_id_no_clean_start(
    config: TestConfig<'_>,
) -> anyhow::Result<TestResult> {
    let ctx = ZERO_LEN_NO_CLEAN;

    let mut params = ConnectParams::new("");
    params.clean_start = false;

    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;
    client.send_connect(&params).await?;

    match client.recv().await {
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x85 => Ok(TestResult::pass(&ctx)),
        Err(_) | Ok(Packet::Disconnect(_)) => {
            // Connection closed — also acceptable rejection
            Ok(TestResult::pass(&ctx))
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => {
            let _ = client.send_disconnect(0x00).await;
            Ok(TestResult::fail(
                &ctx,
                "Broker accepted empty client ID with Clean Start=0 (expected 0x85 rejection)",
            ))
        }
        Ok(Packet::ConnAck(connack)) => Ok(TestResult::fail(
            &ctx,
            format!("Expected reason 0x85, got {:#04x}", connack.reason_code),
        )),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "CONNACK with 0x85", &other)),
    }
}

const ASSIGNED_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.2.2-16"],
    description: "Server SHOULD return Assigned Client Identifier when accepting empty client ID",
    compliance: Compliance::Should,
};

/// When the server accepts a zero-length Client ID, it SHOULD return an
/// Assigned Client Identifier property in CONNACK [MQTT-3.2.2-16].
async fn assigned_client_id(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = ASSIGNED_CLIENT_ID;

    let params = ConnectParams::new("");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code != 0x00 {
        return Ok(TestResult::skip(
            &ctx,
            format!(
                "Broker rejected empty client ID (reason {:#04x})",
                connack.reason_code
            ),
        ));
    }

    if connack.properties.assigned_client_id.is_some() {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            "Broker accepted empty client ID but did not return Assigned Client Identifier",
        ))
    }
}

const FIRST_CONNECT: TestContext = TestContext {
    refs: &["MQTT-3.1.0-1"],
    description: "Server MUST close connection if first packet is not CONNECT",
    compliance: Compliance::Must,
};

/// First packet on a connection MUST be CONNECT [MQTT-3.1.0-1].
async fn first_packet_must_be_connect(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = FIRST_CONNECT;

    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Send a PINGREQ as the first packet instead of CONNECT
    client.send_pingreq().await?;

    match client.recv().await {
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::PingResp) => Ok(TestResult::fail(
            &ctx,
            "Broker responded to PINGREQ without prior CONNECT",
        )),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "connection close", &other)),
    }
}

// ── MAY ──────────────────────────────────────────────────────────────────────

const SESSION_EXPIRY: TestContext = TestContext {
    refs: &["MQTT-3.1.2-11"],
    description: "Session Expiry Interval property is accepted",
    compliance: Compliance::May,
};

/// Session Expiry Interval property is accepted [MQTT-3.1.2-11].
async fn session_expiry_interval_accepted(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SESSION_EXPIRY;

    let mut params = ConnectParams::new("mqtt-test-sei");
    params.properties.session_expiry_interval = Some(60);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!("CONNACK reason code {:#04x}", connack.reason_code),
        ))
    }
}

const RECEIVE_MAX: TestContext = TestContext {
    refs: &["MQTT-3.2.2-14"],
    description: "Receive Maximum property in CONNECT is accepted",
    compliance: Compliance::May,
};

/// Receive Maximum property is accepted [MQTT-3.1.2-11].
async fn receive_maximum_accepted(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = RECEIVE_MAX;

    let mut params = ConnectParams::new("mqtt-test-recv-max");
    params.properties.receive_maximum = Some(10);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!("CONNACK reason code {:#04x}", connack.reason_code),
        ))
    }
}

const MAX_PACKET_SIZE: TestContext = TestContext {
    refs: &["MQTT-3.2.2-17"],
    description: "Maximum Packet Size property in CONNECT is accepted",
    compliance: Compliance::May,
};

/// Maximum Packet Size property is accepted [MQTT-3.2.2-17].
async fn maximum_packet_size_accepted(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = MAX_PACKET_SIZE;

    let mut params = ConnectParams::new("mqtt-test-max-pkt");
    params.properties.maximum_packet_size = Some(65536);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!("CONNACK reason code {:#04x}", connack.reason_code),
        ))
    }
}

const SERVER_KEEP_ALIVE: TestContext = TestContext {
    refs: &["MQTT-3.2.2-21"],
    description: "Server Keep Alive: server MAY override client's keep-alive value",
    compliance: Compliance::May,
};

/// Server MAY send Server Keep Alive in CONNACK to override the client's
/// requested keep-alive interval [MQTT-3.2.2-21].
async fn server_keep_alive(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SERVER_KEEP_ALIVE;

    let params = ConnectParams::new("mqtt-test-server-ka");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.server_keep_alive.is_some() {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            "Server did not include Server Keep Alive property in CONNACK",
        ))
    }
}

const TOPIC_ALIAS_MAX: TestContext = TestContext {
    refs: &["MQTT-3.2.2-9"],
    description: "Topic Alias Maximum: server reports maximum supported topic aliases",
    compliance: Compliance::May,
};

/// Server MAY include Topic Alias Maximum in CONNACK [MQTT-3.2.2-9].
async fn topic_alias_maximum(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = TOPIC_ALIAS_MAX;

    let params = ConnectParams::new("mqtt-test-ta-max");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if let Some(max) = connack.properties.topic_alias_maximum {
        if max > 0 {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                "Topic Alias Maximum is 0 (topic aliases not supported)",
            ))
        }
    } else {
        Ok(TestResult::fail(
            &ctx,
            "Server did not include Topic Alias Maximum in CONNACK",
        ))
    }
}

const WILDCARD_SUB_AVAIL: TestContext = TestContext {
    refs: &["MQTT-3.2.2-12"],
    description: "Wildcard Subscription Available: server reports wildcard subscription support",
    compliance: Compliance::May,
};

/// Server MAY include Wildcard Subscription Available in CONNACK [MQTT-3.2.2-12].
/// Most brokers support wildcards so this checks if the property is present and true.
async fn wildcard_subscription_available(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILDCARD_SUB_AVAIL;

    let params = ConnectParams::new("mqtt-test-wildcard-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.wildcard_subscription_available {
        Some(true) | None => {
            // None means default (true per spec)
            Ok(TestResult::pass(&ctx))
        }
        Some(false) => Ok(TestResult::fail(
            &ctx,
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

/// Server MUST disconnect a client that sends a second CONNECT [MQTT-3.1.0-2].
async fn duplicate_connect(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = DUP_CONNECT;

    let params = ConnectParams::new("mqtt-test-dup-connect");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Send a second CONNECT on the same connection.
    client.send_connect(&params).await?;

    // Broker must either send DISCONNECT or close the connection.
    match client.recv().await {
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "disconnect", &other)),
    }
}

const INVALID_PROTO_NAME: TestContext = TestContext {
    refs: &["MQTT-3.1.2-1"],
    description: "Server MUST close connection if protocol name is not 'MQTT'",
    compliance: Compliance::Must,
};

/// Server MUST close connection if protocol name is not 'MQTT' [MQTT-3.1.2-1].
async fn invalid_protocol_name(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = INVALID_PROTO_NAME;

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

    match client.recv().await {
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "connection close", &other)),
    }
}

const INVALID_PROTO_VER: TestContext = TestContext {
    refs: &["MQTT-3.1.2-2"],
    description: "Server MAY respond with reason 0x84 for unsupported protocol version",
    compliance: Compliance::May,
};

/// Server MAY respond with 0x84 for unsupported protocol version [MQTT-3.1.2-2].
async fn invalid_protocol_version(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = INVALID_PROTO_VER;

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
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x84 => Ok(TestResult::pass(&ctx)),
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => Ok(TestResult::fail(
            &ctx,
            "Broker accepted MQTT v4 CONNECT with success (expected rejection)",
        )),
        Ok(Packet::ConnAck(connack)) => Ok(TestResult::fail(
            &ctx,
            format!(
                "Expected CONNACK reason 0x84, got {:#04x}",
                connack.reason_code
            ),
        )),
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "CONNACK or close", &other)),
    }
}

const SESSION_PRESENT_ZERO_ON_REJECT: TestContext = TestContext {
    refs: &["MQTT-3.2.2-3"],
    description: "Session Present MUST be 0 when CONNACK reason code is non-zero",
    compliance: Compliance::Must,
};

/// If the server rejects the CONNECT, session_present MUST be 0 in the
/// CONNACK regardless of any prior session state [MQTT-3.2.2-3].
async fn session_present_zero_on_reject(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SESSION_PRESENT_ZERO_ON_REJECT;

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
                Ok(TestResult::fail(
                    &ctx,
                    format!(
                        "CONNACK with reason {:#04x} has session_present=1 (MUST be 0)",
                        connack.reason_code
                    ),
                ))
            } else {
                Ok(TestResult::pass(&ctx))
            }
        }
        Ok(Packet::ConnAck(_)) => {
            // Broker accepted the v4 CONNECT — can't test this requirement.
            Ok(TestResult::skip(
                &ctx,
                "Broker accepted MQTT v4 CONNECT; cannot provoke rejection",
            ))
        }
        Err(_) => {
            // Broker closed connection — acceptable but can't verify session_present.
            Ok(TestResult::skip(
                &ctx,
                "Broker closed connection without CONNACK; cannot verify session_present",
            ))
        }
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "CONNACK", &other)),
    }
}

const KEEP_ALIVE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-22"],
    description: "Server MUST disconnect client exceeding 1.5x keep-alive without activity",
    compliance: Compliance::Must,
};

/// Server MUST disconnect client that exceeds 1.5× keep-alive without activity [MQTT-3.1.2-22].
async fn keep_alive_timeout(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = KEEP_ALIVE;

    let mut params = ConnectParams::new("mqtt-test-keepalive");
    params.keep_alive = 2; // 2 seconds → broker should disconnect after ~3s

    let (mut client, _) = client::connect(config.addr, &params, Duration::from_secs(5)).await?;

    // Do NOT send PINGREQ. Wait for the broker to disconnect us.
    match client.recv_with_timeout(Duration::from_secs(5)).await {
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
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

/// Will message MUST be published on unexpected connection close [MQTT-3.1.2-8].
async fn will_message_on_unexpected_close(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILL_ON_CLOSE;

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
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!(
                        "Will payload mismatch: got {:?}",
                        String::from_utf8_lossy(&p.payload)
                    ),
                ))
            }
        }
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH (will message)",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "Will message not received after unexpected disconnect",
        )),
    }
}

const WILL_REMOVED_ON_DISCONNECT: TestContext = TestContext {
    refs: &["MQTT-3.1.2-10"],
    description: "Will message MUST be removed on normal DISCONNECT",
    compliance: Compliance::Must,
};

/// Will message MUST be removed from session on normal DISCONNECT [MQTT-3.1.2-10].
async fn will_message_removed_on_disconnect(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILL_REMOVED_ON_DISCONNECT;

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
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(TestResult::fail(
            &ctx,
            "Will message was published despite normal DISCONNECT",
        )),
        Ok(_) => Ok(TestResult::pass(&ctx)),
    }
}

const WILL_RETAIN: TestContext = TestContext {
    refs: &["MQTT-3.1.2-13"],
    description: "Will Retain flag MUST be respected when will message is published",
    compliance: Compliance::Must,
};

/// Will Retain flag MUST be respected [MQTT-3.1.2-13].
async fn will_retain_flag(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILL_RETAIN;

    let will_topic = "mqtt/test/will/retain";

    // Check if broker supports retain
    let check_params = ConnectParams::new("mqtt-test-will-retain-check");
    let (_check_client, connack) =
        client::connect(config.addr, &check_params, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Retain Available = false",
        ));
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
        Ok(Packet::Publish(p)) if p.topic == will_topic && p.retain => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(TestResult::fail(
            &ctx,
            "Will message received but retain flag was not set",
        )),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "retained PUBLISH (will)",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "Retained will message not delivered to new subscriber",
        )),
    }
}

// ── CONNACK server property enforcement ─────────────────────────────────────

const SERVER_MAX_QOS: TestContext = TestContext {
    refs: &["MQTT-3.2.2-19"],
    description: "Client MUST NOT send QoS exceeding server's Maximum QoS",
    compliance: Compliance::Must,
};

/// If server advertises Maximum QoS, publishing above it MUST result in DISCONNECT [MQTT-3.2.2-19].
async fn server_maximum_qos(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SERVER_MAX_QOS;

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
                    Ok(TestResult::pass(&ctx))
                }
                Err(_) | Ok(Packet::Disconnect(_)) => {
                    // Disconnected — acceptable
                    Ok(TestResult::pass(&ctx))
                }
                Ok(Packet::PubAck(ack)) if ack.reason_code >= 0x80 => Ok(TestResult::pass(&ctx)),
                Ok(Packet::PubAck(_)) => Ok(TestResult::fail(
                    &ctx,
                    "Server accepted QoS 1 PUBLISH despite Maximum QoS = 0",
                )),
                Ok(other) => Ok(TestResult::fail_packet(
                    &ctx,
                    "DISCONNECT or error PUBACK",
                    &other,
                )),
            }
        }
        Some(1) => {
            // Server supports up to QoS 1 — sending QoS 2 should be rejected
            let pub_params =
                PublishParams::qos2("mqtt/test/connack/maxqos", b"qos2-over-max".as_slice(), 1);
            client.send_publish(&pub_params).await?;

            match client.recv().await {
                Ok(Packet::Disconnect(d)) if d.reason_code == 0x9B => Ok(TestResult::pass(&ctx)),
                Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
                Ok(Packet::PubRec(rec)) if rec.reason_code >= 0x80 => Ok(TestResult::pass(&ctx)),
                Ok(Packet::PubRec(_)) => Ok(TestResult::fail(
                    &ctx,
                    "Server accepted QoS 2 PUBLISH despite Maximum QoS = 1",
                )),
                Ok(other) => Ok(TestResult::fail_packet(
                    &ctx,
                    "DISCONNECT or error PUBREC",
                    &other,
                )),
            }
        }
        _ => {
            // Server supports QoS 2 (default) or didn't advertise — skip
            Ok(TestResult::skip(
                &ctx,
                "Server supports QoS 2 (no Maximum QoS restriction to test)",
            ))
        }
    }
}

const SERVER_RECV_MAX: TestContext = TestContext {
    refs: &["MQTT-3.2.2-14"],
    description: "Server MUST NOT send more concurrent QoS>0 messages than Receive Maximum",
    compliance: Compliance::Must,
};

/// Server MUST respect client's Receive Maximum [MQTT-3.2.2-14].
async fn server_receive_maximum(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SERVER_RECV_MAX;

    // Connect with a very low Receive Maximum
    let recv_max: u16 = 2;
    let mut sub_params = ConnectParams::new("mqtt-test-recv-max-sub");
    sub_params.properties.receive_maximum = Some(recv_max);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let topic = "mqtt/test/connack/recvmax";
    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

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
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "Received {received} QoS 1 messages without PUBACK (Receive Maximum = {recv_max})",
            ),
        ))
    }
}

// ── Will Delay Interval ─────────────────────────────────────────────────────

const WILL_DELAY: TestContext = TestContext {
    refs: &["MQTT-3.1.3-9"],
    description: "Will Delay Interval: will message publication MAY be delayed",
    compliance: Compliance::May,
};

/// Will Delay Interval: if set, the server MAY delay publishing the will
/// message for up to the specified number of seconds [MQTT-3.1.3-9].
/// We test with a short delay and verify the message is NOT published
/// immediately but IS published after the delay expires.
async fn will_delay_interval(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILL_DELAY;

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
            return Ok(TestResult::fail(
                &ctx,
                "Will message arrived immediately despite Will Delay Interval = 2s",
            ));
        }
        _ => {} // expected — no message yet
    }

    // Should arrive after the delay (wait up to 4 more seconds)
    match sub_client.recv_with_timeout(Duration::from_secs(4)).await {
        Ok(Packet::Publish(p)) if p.topic == will_topic => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH (delayed will)",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "Will message not received after delay interval expired",
        )),
    }
}

// ── Request/Response Information ────────────────────────────────────────────

const REQ_RESP_INFO: TestContext = TestContext {
    refs: &["MQTT-3.1.2-28"],
    description: "Request Response Information: server MAY return Response Information",
    compliance: Compliance::May,
};

/// When the client sets Request Response Information = 1, the server MAY
/// include Response Information in the CONNACK [MQTT-3.1.2-28].
async fn request_response_information(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = REQ_RESP_INFO;

    let mut params = ConnectParams::new("mqtt-test-resp-info");
    params.properties.request_response_information = Some(true);

    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.response_information.is_some() {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            "Server did not include Response Information despite request",
        ))
    }
}

// ── Enhanced authentication ─────────────────────────────────────────────────

const ENHANCED_AUTH: TestContext = TestContext {
    refs: &["MQTT-3.15"],
    description: "Enhanced authentication via AUTH packets is supported",
    compliance: Compliance::May,
};

/// Enhanced authentication: CONNECT with Authentication Method [MQTT-3.15].
///
/// If the broker does not support the method, it should respond with a CONNACK
/// containing reason code 0x8C (Bad authentication method) or 0x87 (Not Authorized).
/// If it does support it, it may respond with an AUTH packet to continue the exchange.
async fn enhanced_auth_method(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = ENHANCED_AUTH;

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
            Ok(TestResult::pass(&ctx))
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x8C => {
            // Bad authentication method — broker rejects but handles correctly
            Ok(TestResult::pass(&ctx))
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x87 => {
            // Not Authorized — broker rejects but handles correctly
            Ok(TestResult::pass(&ctx))
        }
        Ok(Packet::ConnAck(connack)) if connack.reason_code == 0x00 => {
            // Broker accepted without challenge — unusual but not invalid
            let _ = client.send_disconnect(0x00).await;
            Ok(TestResult::pass(&ctx))
        }
        Ok(Packet::ConnAck(connack)) => Ok(TestResult::fail(
            &ctx,
            format!(
                "CONNACK reason {:#04x} for enhanced auth CONNECT",
                connack.reason_code
            ),
        )),
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::fail(
            &ctx,
            "Broker closed connection instead of sending CONNACK with auth error code",
        )),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "CONNACK or AUTH", &other)),
    }
}

// ── Reason String ───────────────────────────────────────────────────────────

const REASON_STRING: TestContext = TestContext {
    refs: &["MQTT-3.2.2-20"],
    description: "Reason String: server MAY include a human-readable diagnostic in CONNACK",
    compliance: Compliance::May,
};

/// Server MAY include a Reason String in CONNACK when rejecting a connection [MQTT-3.2.2-20].
/// We trigger a rejection with an invalid protocol name and check for a Reason String.
async fn reason_string_in_connack(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = REASON_STRING;

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
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    "CONNACK rejection did not include Reason String",
                ))
            }
        }
        Ok(Packet::ConnAck(_)) => Ok(TestResult::skip(
            &ctx,
            "Broker accepted MQTT v4 CONNECT — cannot test error Reason String",
        )),
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::fail(
            &ctx,
            "Broker closed connection instead of sending CONNACK with Reason String",
        )),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "CONNACK", &other)),
    }
}

// ── SHOULD ──────────────────────────────────────────────────────────────────

const ACCEPTABLE_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-3.1.3-5"],
    description: "Server SHOULD accept client IDs of [0-9a-zA-Z] with 1-23 bytes",
    compliance: Compliance::Should,
};

/// Server SHOULD allow Client Identifiers which contain only characters
/// [0-9a-zA-Z] and are between 1 and 23 bytes long [MQTT-3.1.3-5].
async fn acceptable_client_id_chars(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = ACCEPTABLE_CLIENT_ID;

    // A 23-char ID using the recommended character set.
    let client_id = "abcABC0123456789xyzXYZw";
    let params = ConnectParams::new(client_id);
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "Broker rejected 23-char alphanumeric client ID (reason {:#04x})",
                connack.reason_code
            ),
        ))
    }
}

const FLOW_CONTROL: TestContext = TestContext {
    refs: &["MQTT-4.9.0-1"],
    description: "Server SHOULD use Receive Maximum to limit concurrent inflight messages",
    compliance: Compliance::Should,
};

/// The server SHOULD use its Receive Maximum (from CONNACK) to limit the
/// number of concurrent QoS>0 messages it sends before receiving acknowledgements
/// [MQTT-4.9.0-1]. We read the server's Receive Maximum and verify the server
/// does not exceed it when delivering QoS 1 messages without client PUBACK.
async fn flow_control_receive_maximum(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = FLOW_CONTROL;

    // Connect subscriber — inspect server's Receive Maximum from CONNACK.
    let sub_params = ConnectParams::new("mqtt-test-flow-ctrl-sub");
    let (mut sub_client, connack) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let server_recv_max = connack.properties.receive_maximum.unwrap_or(65535);
    if server_recv_max > 20 {
        return Ok(TestResult::skip(
            &ctx,
            format!(
                "Server Receive Maximum is {server_recv_max} — too high to practically test flow control"
            ),
        ));
    }

    let topic = "mqtt/test/flow/ctrl";
    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

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
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "Server sent {received} QoS 1 messages without PUBACK (Receive Maximum = {server_recv_max})",
            ),
        ))
    }
}

// ── MAY (CONNACK properties) ────────────────────────────────────────────────

const CONNACK_MAX_QOS: TestContext = TestContext {
    refs: &["MQTT-3.2.2-7"],
    description: "Maximum QoS property in CONNACK reports server's QoS capability",
    compliance: Compliance::May,
};

/// Server MAY include Maximum QoS in CONNACK to advertise its highest
/// supported QoS level [MQTT-3.2.2-7].
async fn connack_maximum_qos(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CONNACK_MAX_QOS;

    let params = ConnectParams::new("mqtt-test-max-qos-prop");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.maximum_qos {
        Some(qos) if qos <= 2 => Ok(TestResult::pass(&ctx)),
        Some(qos) => Ok(TestResult::fail(
            &ctx,
            format!("Maximum QoS property has invalid value {qos} (expected 0, 1, or 2)"),
        )),
        None => Ok(TestResult::fail(
            &ctx,
            "CONNACK does not include Maximum QoS property (defaults to 2)",
        )),
    }
}

const CONNACK_RETAIN_AVAIL: TestContext = TestContext {
    refs: &["MQTT-3.2.2-10"],
    description: "Retain Available property in CONNACK reports retain support",
    compliance: Compliance::May,
};

/// Server MAY include Retain Available in CONNACK [MQTT-3.2.2-10].
async fn connack_retain_available(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CONNACK_RETAIN_AVAIL;

    let params = ConnectParams::new("mqtt-test-retain-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.retain_available {
        Some(_) => Ok(TestResult::pass(&ctx)),
        None => Ok(TestResult::fail(
            &ctx,
            "CONNACK does not include Retain Available property (defaults to true)",
        )),
    }
}

const CONNACK_SUB_IDS: TestContext = TestContext {
    refs: &["MQTT-3.2.2-13"],
    description: "Subscription Identifiers Available property in CONNACK",
    compliance: Compliance::May,
};

/// Server MAY include Subscription Identifiers Available in CONNACK [MQTT-3.2.2-13].
async fn connack_subscription_ids_available(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CONNACK_SUB_IDS;

    let params = ConnectParams::new("mqtt-test-subid-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.subscription_ids_available {
        Some(_) => Ok(TestResult::pass(&ctx)),
        None => Ok(TestResult::fail(
            &ctx,
            "CONNACK does not include Subscription Identifiers Available property (defaults to true)",
        )),
    }
}

const CONNACK_SHARED_SUB: TestContext = TestContext {
    refs: &["MQTT-3.2.2-15"],
    description: "Shared Subscription Available property in CONNACK",
    compliance: Compliance::May,
};

/// Server MAY include Shared Subscription Available in CONNACK [MQTT-3.2.2-15].
async fn connack_shared_subscription_available(
    config: TestConfig<'_>,
) -> anyhow::Result<TestResult> {
    let ctx = CONNACK_SHARED_SUB;

    let params = ConnectParams::new("mqtt-test-shared-sub-avail");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    match connack.properties.shared_subscription_available {
        Some(_) => Ok(TestResult::pass(&ctx)),
        None => Ok(TestResult::fail(
            &ctx,
            "CONNACK does not include Shared Subscription Available property (defaults to true)",
        )),
    }
}

const CONNACK_SERVER_REF: TestContext = TestContext {
    refs: &["MQTT-3.2.2-18"],
    description: "Server Reference in rejected CONNACK for server redirection",
    compliance: Compliance::May,
};

/// Server MAY include a Server Reference property in a rejected CONNACK
/// to redirect the client [MQTT-3.2.2-18].
async fn connack_server_reference(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CONNACK_SERVER_REF;

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
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    "Rejected CONNACK does not include Server Reference property",
                ))
            }
        }
        Ok(Packet::ConnAck(_)) => Ok(TestResult::skip(
            &ctx,
            "Broker accepted MQTT v4 CONNECT — cannot test rejected CONNACK properties",
        )),
        Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::skip(
            &ctx,
            "Broker closed connection without CONNACK — cannot inspect Server Reference",
        )),
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "CONNACK", &other)),
    }
}

const SERVER_REDIRECT: TestContext = TestContext {
    refs: &["MQTT-4.11.0-1"],
    description: "Server redirection: CONNACK with reason 0x9C or 0x9D indicates redirect",
    compliance: Compliance::May,
};

/// Server MAY use reason codes 0x9C (Use Another Server) or 0x9D
/// (Server Moved) to redirect clients [MQTT-4.11]. We check if a normal
/// CONNACK includes a Server Reference, indicating redirection support.
async fn server_redirection(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SERVER_REDIRECT;

    let params = ConnectParams::new("mqtt-test-redirect");
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // A successful CONNACK won't have redirection reason codes, but the
    // server may still advertise a Server Reference for informational purposes.
    if connack.reason_code == 0x9C || connack.reason_code == 0x9D {
        // Actively redirecting — check for Server Reference.
        if connack.properties.server_reference.is_some() {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                format!(
                    "Redirect reason {:#04x} without Server Reference property",
                    connack.reason_code
                ),
            ))
        }
    } else {
        // Normal connection — server is not redirecting. Not a failure for MAY.
        Ok(TestResult::fail(
            &ctx,
            "Server did not redirect (no 0x9C/0x9D reason code in CONNACK)",
        ))
    }
}

// ── Username / Password ─────────────────────────────────────────────────────

const USERNAME_PASSWORD: TestContext = TestContext {
    refs: &["MQTT-3.1.3-4"],
    description: "Server MUST accept CONNECT with Username and Password flags set",
    compliance: Compliance::Must,
};

/// A CONNECT carrying both username and password MUST be accepted (assuming the
/// broker allows anonymous or the credentials are valid) [MQTT-3.1.3-4/5].
async fn username_password_accepted(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = USERNAME_PASSWORD;

    let mut params = ConnectParams::new("mqtt-test-user-pass");
    params.username = Some("testuser".into());
    params.password = Some(b"testpass".to_vec());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "CONNACK reason code {:#04x} (expected 0x00)",
                connack.reason_code
            ),
        ))
    }
}

const PASSWORD_NO_USERNAME: TestContext = TestContext {
    refs: &["MQTT-3.1.2-19"],
    description: "MQTT v5 allows Password without Username (v5 change from v3.1.1)",
    compliance: Compliance::May,
};

/// In MQTT v5, a CONNECT MAY include a password without a username — the
/// username-flag=0, password-flag=1 combination is valid [MQTT-3.1.2-19].
async fn password_without_username(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = PASSWORD_NO_USERNAME;

    let mut params = ConnectParams::new("mqtt-test-pass-no-user");
    params.password = Some(b"testpass".to_vec());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "CONNACK reason code {:#04x} — broker rejected password without username",
                connack.reason_code
            ),
        ))
    }
}

const EMPTY_USERNAME: TestContext = TestContext {
    refs: &["MQTT-3.1.3-10"],
    description: "Server MUST accept zero-length username when Username flag is set",
    compliance: Compliance::Must,
};

/// A CONNECT with the Username flag set and a zero-length UTF-8 string is valid
/// per the spec — the username is simply empty [MQTT-3.1.3-4].
async fn empty_username(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = EMPTY_USERNAME;

    let mut params = ConnectParams::new("mqtt-test-empty-user");
    params.username = Some(String::new());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "CONNACK reason code {:#04x} (expected 0x00)",
                connack.reason_code
            ),
        ))
    }
}

const USERNAME_ONLY: TestContext = TestContext {
    refs: &["MQTT-3.1.2-15"],
    description: "Server MUST accept CONNECT with Username flag set and no Password",
    compliance: Compliance::Must,
};

/// A CONNECT with only the Username flag set (no Password flag) is valid.
async fn username_only(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = USERNAME_ONLY;

    let mut params = ConnectParams::new("mqtt-test-user-only");
    params.username = Some("testuser".into());
    let (_client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.reason_code == 0x00 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "CONNACK reason code {:#04x} (expected 0x00)",
                connack.reason_code
            ),
        ))
    }
}

// ── Will Retain=0 → non-retained ────────────────────────────────────────

const WILL_NON_RETAINED: TestContext = TestContext {
    refs: &["MQTT-3.1.2-14"],
    description: "Will Retain=0: will message MUST be published as non-retained",
    compliance: Compliance::Must,
};

/// When Will Flag=1 and Will Retain=0, the server MUST publish the will
/// message as a non-retained message [MQTT-3.1.2-14].
async fn will_non_retained(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILL_NON_RETAINED;

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
                    Ok(TestResult::fail(
                        &ctx,
                        "Will message with Retain=0 was stored as retained (new subscriber received it)",
                    ))
                }
                _ => Ok(TestResult::pass(&ctx)),
            }
        }
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH (will message)",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
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

/// If the client sets Topic Alias Maximum=0 in CONNECT, the server MUST NOT
/// send any Topic Aliases in PUBLISH packets to that client [MQTT-3.1.2-26].
async fn topic_alias_maximum_zero(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = TOPIC_ALIAS_MAX_ZERO;

    let topic = "mqtt/test/connect/ta_zero";

    // Connect subscriber with topic_alias_maximum=0
    let mut sub_params = ConnectParams::new("mqtt-test-ta0-sub");
    sub_params.properties.topic_alias_maximum = Some(0);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtMostOnce);
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

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
                    return Ok(TestResult::fail(
                        &ctx,
                        format!(
                            "Server sent Topic Alias {alias} to client with Topic Alias Maximum=0",
                        ),
                    ));
                }
                received += 1;
            }
            _ => break,
        }
    }

    if received > 0 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
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

/// When the server rejects a CONNECT (e.g. due to a malformed packet), it MAY
/// send a CONNACK with a Reason Code of 0x80 or greater before closing the
/// network connection [MQTT-3.1.4-2].
async fn connack_before_close_on_error(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CONNACK_BEFORE_CLOSE;

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
        Ok(Packet::ConnAck(connack)) if connack.reason_code >= 0x80 => Ok(TestResult::pass(&ctx)),
        Ok(Packet::ConnAck(connack)) => Ok(TestResult::fail(
            &ctx,
            format!(
                "CONNACK reason {:#04x} (expected >= 0x80 for malformed CONNECT)",
                connack.reason_code
            ),
        )),
        Err(_) | Ok(Packet::Disconnect(_)) => {
            // Server closed without sending CONNACK — allowed (it's a MAY)
            Ok(TestResult::fail(
                &ctx,
                "Server closed connection without sending CONNACK (MAY behavior)",
            ))
        }
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "CONNACK", &other)),
    }
}
