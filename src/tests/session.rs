//! Session state and message redelivery compliance tests [MQTT-4.4 / MQTT-3.1.2].

use std::time::Duration;

use anyhow::Result;

use crate::client::{self, RecvError};
use crate::codec::{ConnectParams, Packet, PublishParams, QoS, SubscribeParams};
use crate::helpers::expect_suback;
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

/// Clean up a persistent session by reconnecting with clean_start=true.
async fn cleanup_session(addr: &str, client_id: &str, recv_timeout: Duration) {
    let params = ConnectParams::new(client_id);
    if let Ok((_c, _)) = client::connect(addr, &params, recv_timeout).await {
        // AutoDisconnect handles the clean disconnect on drop.
    }
}

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("SESSION");

    suite.add(SESSION_PRESENT, session_present_on_resume(config));
    suite.add(QOS1_REDELIVER, qos1_redelivery_on_resume(config));
    suite.add(QOS2_REDELIVER, qos2_redelivery_on_resume(config));
    suite.add(SUB_PERSISTS, subscription_persists_across_sessions(config));
    suite.add(SESSION_EXPIRY_ZERO, session_expiry_zero(config));
    suite.add(SESSION_EXPIRY_MAX, session_expiry_max(config));
    suite.add(SESSION_TAKEOVER, session_takeover(config));
    suite.add(SESSION_EXPIRY_DISCARD, session_expiry_discard(config));
    suite.add(
        SESSION_PRESENT_PERSISTENCE,
        session_present_verify_persistence(config),
    );
    suite.add(QOS1_DUP_FLAG, qos1_dup_on_redelivery(config));

    suite
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const SESSION_PRESENT: TestContext = TestContext {
    refs: &["MQTT-3.1.2-5"],
    description: "Clean Start=0 with prior session: session_present MUST be 1",
    compliance: Compliance::Must,
};

/// If a session exists and the client reconnects with Clean Start=0,
/// session_present MUST be 1 in the CONNACK [MQTT-3.1.2-5].
async fn session_present_on_resume(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-session-present";

    // First connection: Clean Start=1, set Session Expiry so the session survives.
    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(60);
    let (c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;
    drop(c1); // AutoDisconnect sends DISCONNECT on drop.

    // Small delay so the broker has processed the disconnect.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connection: Clean Start=0 — broker should find the session.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (_c2, connack) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    // Clean up the session.
    cleanup_session(config.addr, client_id, config.recv_timeout).await;

    if connack.session_present {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(
            "session_present=0 on reconnect with Clean Start=0 (expected 1)",
        ))
    }
}

const QOS1_REDELIVER: TestContext = TestContext {
    refs: &["MQTT-4.4.0-1", "MQTT-4.5.0-1"],
    description: "Unacknowledged QoS 1 messages MUST be redelivered on session resume",
    compliance: Compliance::Must,
};

/// When a client reconnects with Clean Start=0, any QoS 1 messages that were
/// not acknowledged MUST be redelivered [MQTT-4.4.0-1].
///
/// Note: this test publishes while the subscriber is offline, so the redelivered
/// message is a *first* delivery — DUP=0 is correct. See `qos1_dup_on_redelivery`
/// for the DUP=1 check when the client previously received the message.
async fn qos1_redelivery_on_resume(config: TestConfig<'_>) -> Result<Outcome> {
    let sub_id = "mqtt-test-qos1-redel-sub";
    let pub_id = "mqtt-test-qos1-redel-pub";
    let topic = "mqtt/test/session/qos1";

    // 1. Connect subscriber with persistent session and subscribe at QoS 1.
    let mut sub_params = ConnectParams::new(sub_id);
    sub_params.properties.session_expiry_interval = Some(60);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // 2. Disconnect the subscriber abruptly (no DISCONNECT packet) so messages queue.
    drop(sub_client.into_raw());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Publish a QoS 1 message while subscriber is offline.
    let pub_params_conn = ConnectParams::new(pub_id);
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params_conn, config.recv_timeout).await?;
    let pub_msg = PublishParams::qos1(topic, b"queued-qos1".to_vec(), 1);
    pub_client.send_publish(&pub_msg).await?;
    // Wait for PUBACK.
    for _ in 0..5 {
        if let Packet::PubAck(_) = pub_client.recv().await? {
            break;
        }
    }
    drop(pub_client); // AutoDisconnect sends DISCONNECT on drop.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Reconnect subscriber with Clean Start=0 — should receive the queued message.
    let mut sub_params2 = ConnectParams::new(sub_id);
    sub_params2.clean_start = false;
    sub_params2.properties.session_expiry_interval = Some(60);
    let (mut sub_client2, connack) =
        client::connect(config.addr, &sub_params2, config.recv_timeout).await?;

    if !connack.session_present {
        cleanup_session(config.addr, sub_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "Broker did not preserve session (session_present=0); cannot test redelivery",
        ));
    }

    // 5. Check for the redelivered message.
    let result = match sub_client2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Outcome::Pass,
        Ok(other) => Outcome::fail_packet("redelivered PUBLISH on session resume", &other),
        Err(RecvError::Timeout) | Err(RecvError::Closed) => {
            Outcome::fail("No queued QoS 1 message redelivered after session resume")
        }
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };
    // AutoDisconnect on sub_client2 sends DISCONNECT on drop.

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}

const QOS2_REDELIVER: TestContext = TestContext {
    refs: &["MQTT-4.4.0-2"],
    description: "Incomplete QoS 2 flows MUST be resumed on session reconnect",
    compliance: Compliance::Must,
};

/// When a client reconnects with Clean Start=0, incomplete QoS 2 flows
/// MUST be resumed [MQTT-4.3.3 / MQTT-4.4].
async fn qos2_redelivery_on_resume(config: TestConfig<'_>) -> Result<Outcome> {
    let sub_id = "mqtt-test-qos2-redel-sub";
    let pub_id = "mqtt-test-qos2-redel-pub";
    let topic = "mqtt/test/session/qos2";

    // 1. Connect subscriber with persistent session and subscribe at QoS 2.
    let mut sub_params = ConnectParams::new(sub_id);
    sub_params.properties.session_expiry_interval = Some(60);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::ExactlyOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // 2. Disconnect subscriber abruptly.
    drop(sub_client.into_raw());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Publish a QoS 2 message while subscriber is offline.
    let pub_params_conn = ConnectParams::new(pub_id);
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params_conn, config.recv_timeout).await?;
    let pub_msg = PublishParams::qos2(topic, b"queued-qos2".to_vec(), 1);
    pub_client.send_publish(&pub_msg).await?;

    // Complete the QoS 2 handshake on the publisher side.
    for _ in 0..5 {
        match pub_client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 1 => {
                pub_client.send_pubrel(1, 0x00).await?;
                // Wait for PUBCOMP.
                for _ in 0..5 {
                    if let Packet::PubComp(_) = pub_client.recv().await? {
                        break;
                    }
                }
                break;
            }
            _ => {}
        }
    }
    drop(pub_client); // AutoDisconnect sends DISCONNECT on drop.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Reconnect subscriber with Clean Start=0.
    let mut sub_params2 = ConnectParams::new(sub_id);
    sub_params2.clean_start = false;
    sub_params2.properties.session_expiry_interval = Some(60);
    let (mut sub_client2, connack) =
        client::connect(config.addr, &sub_params2, config.recv_timeout).await?;

    if !connack.session_present {
        cleanup_session(config.addr, sub_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "Broker did not preserve session (session_present=0); cannot test redelivery",
        ));
    }

    // 5. Should receive the queued QoS 2 message (as PUBLISH or PUBREL depending on state).
    let result = match sub_client2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Outcome::Pass,
        Ok(Packet::PubRel(_)) => {
            // The broker may resume at the PUBREL stage — this is also valid.
            Outcome::Pass
        }
        Ok(other) => {
            Outcome::fail_packet("redelivered PUBLISH or PUBREL on session resume", &other)
        }
        Err(RecvError::Timeout) | Err(RecvError::Closed) => {
            Outcome::fail("No queued QoS 2 message redelivered after session resume")
        }
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };
    // AutoDisconnect on sub_client2 sends DISCONNECT on drop.

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}

const SUB_PERSISTS: TestContext = TestContext {
    refs: &["MQTT-3.1.2-6"],
    description: "Subscriptions MUST persist across session reconnects",
    compliance: Compliance::Must,
};

/// When a client reconnects with Clean Start=0, its subscriptions from
/// the previous session MUST still be active [MQTT-3.1.2-6].
async fn subscription_persists_across_sessions(config: TestConfig<'_>) -> Result<Outcome> {
    let sub_id = "mqtt-test-sub-persist";
    let pub_id = "mqtt-test-sub-persist-pub";
    let topic = "mqtt/test/session/persist";

    // 1. Connect, subscribe, then disconnect gracefully.
    let mut params = ConnectParams::new(sub_id);
    params.properties.session_expiry_interval = Some(60);
    let (mut c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtMostOnce);
    c1.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut c1).await {
        return Ok(r);
    }
    drop(c1); // AutoDisconnect sends DISCONNECT on drop.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Reconnect with Clean Start=0 — do NOT re-subscribe.
    let mut params2 = ConnectParams::new(sub_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (mut c2, connack) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    if !connack.session_present {
        cleanup_session(config.addr, sub_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "Broker did not preserve session (session_present=0); cannot test subscription persistence",
        ));
    }

    // 3. Publish a message from a different client.
    let pub_params_conn = ConnectParams::new(pub_id);
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params_conn, config.recv_timeout).await?;
    let pub_msg = PublishParams::qos0(topic, b"persist-test".to_vec());
    pub_client.send_publish(&pub_msg).await?;
    // AutoDisconnect on pub_client sends DISCONNECT on drop.

    // 4. The reconnected subscriber should receive it without re-subscribing.
    let result = match c2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Outcome::Pass,
        Ok(other) => Outcome::fail_packet("PUBLISH from persisted subscription", &other),
        Err(RecvError::Timeout) | Err(RecvError::Closed) => {
            Outcome::fail("No message received — subscription did not persist across reconnect")
        }
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };
    // AutoDisconnect on c2 sends DISCONNECT on drop.

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}

const SESSION_EXPIRY_ZERO: TestContext = TestContext {
    refs: &["MQTT-3.1.2-10"],
    description: "Session Expiry Interval of 0 means session ends on disconnect",
    compliance: Compliance::Must,
};

/// A Session Expiry Interval of 0 means the session state MUST be discarded
/// when the connection closes [MQTT-3.1.2-10].
async fn session_expiry_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-session-exp-zero";

    // First connection: Session Expiry Interval = 0 (explicit).
    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(0);
    let (c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;
    drop(c1);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Reconnect with Clean Start=0 — session should NOT exist.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    let (_c2, connack) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    cleanup_session(config.addr, client_id, config.recv_timeout).await;

    if !connack.session_present {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(
            "session_present=1 despite Session Expiry Interval=0",
        ))
    }
}

const SESSION_EXPIRY_MAX: TestContext = TestContext {
    refs: &["MQTT-3.1.2-11a"],
    description: "Session Expiry Interval of 0xFFFFFFFF means session never expires",
    compliance: Compliance::Must,
};

/// Session Expiry Interval of 0xFFFFFFFF means the session does not expire.
/// Reconnecting with Clean Start=0 should find the session [MQTT-3.1.2-11].
async fn session_expiry_max(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-session-exp-max";

    // First connection with max session expiry.
    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(0xFFFF_FFFF);
    let (c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;
    drop(c1);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Reconnect with Clean Start=0 — session MUST still exist.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(0xFFFF_FFFF);
    let (_c2, connack) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    cleanup_session(config.addr, client_id, config.recv_timeout).await;

    if connack.session_present {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(
            "session_present=0 despite Session Expiry Interval=0xFFFFFFFF",
        ))
    }
}

const SESSION_TAKEOVER: TestContext = TestContext {
    refs: &["MQTT-3.1.4-3"],
    description: "Server MUST disconnect existing client when new client uses same Client ID",
    compliance: Compliance::Must,
};

/// If a client connects with a Client Identifier already in use, the server
/// MUST disconnect the existing client [MQTT-3.1.4-3].
async fn session_takeover(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-session-takeover";

    // First connection.
    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(60);
    let (mut c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Second connection with the same Client ID — should disconnect c1.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (_c2, _) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    // c1 should have been disconnected by the server.
    let result = match c1.recv().await {
        Err(RecvError::Closed) => Outcome::Pass,
        Err(RecvError::Timeout) => Outcome::fail("broker did not disconnect (timed out)"),
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
        Ok(Packet::Disconnect(_)) => Outcome::Pass,
        Ok(other) => Outcome::fail_packet("DISCONNECT or connection close", &other),
    };

    cleanup_session(config.addr, client_id, config.recv_timeout).await;

    Ok(result)
}

const SESSION_EXPIRY_DISCARD: TestContext = TestContext {
    refs: &["MQTT-4.1.0-1"],
    description: "Server MUST discard session state when Session Expiry Interval has passed",
    compliance: Compliance::Must,
};

/// The server MUST discard session state when the network connection is closed
/// and the Session Expiry Interval has passed [MQTT-4.1.0-1/2]. Connect with a
/// 2-second expiry, disconnect, wait 3 seconds, then verify the session is gone.
async fn session_expiry_discard(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-session-exp-discard";
    let topic = "mqtt/test/session/expiry_discard";

    // 1. Connect with a 2-second session expiry and subscribe.
    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(2);
    let (mut c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    c1.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut c1).await {
        return Ok(r);
    }

    drop(c1); // Graceful disconnect
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Verify session exists before expiry.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(2);
    let (_c2, connack_before) = client::connect(config.addr, &params2, config.recv_timeout).await?;
    drop(_c2);

    if !connack_before.session_present {
        cleanup_session(config.addr, client_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "Session not present immediately after disconnect (expected session_present=1)",
        ));
    }

    // 3. Wait for the session to expire (3 seconds > 2-second expiry).
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 4. Reconnect — session should be gone.
    let mut params3 = ConnectParams::new(client_id);
    params3.clean_start = false;
    let (_c3, connack_after) = client::connect(config.addr, &params3, config.recv_timeout).await?;

    cleanup_session(config.addr, client_id, config.recv_timeout).await;

    if !connack_after.session_present {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(
            "Session still present after Session Expiry Interval passed (expected session_present=0)",
        ))
    }
}

const SESSION_PRESENT_PERSISTENCE: TestContext = TestContext {
    refs: &["MQTT-3.2.2-2"],
    description: "Session Present=1 when Clean Start=0 and session exists, verifying subscription persistence",
    compliance: Compliance::Must,
};

/// When a client reconnects with Clean Start=0 and the server has session state,
/// the CONNACK MUST contain Session Present=1 [MQTT-3.2.2-2] and the subscription
/// must deliver messages without re-subscribing. This verifies the end-to-end
/// persistence guarantee beyond just the session_present flag.
async fn session_present_verify_persistence(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = "mqtt-test-session-pres-persist";
    let pub_id = "mqtt-test-session-pres-pub";
    let topic = "mqtt/test/session/present_persist";

    // 1. Connect with persistent session, subscribe at QoS 1, disconnect abruptly.
    let mut params = ConnectParams::new(client_id);
    params.properties.session_expiry_interval = Some(60);
    let (mut c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    c1.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut c1).await {
        return Ok(r);
    }

    // Disconnect abruptly so messages queue
    drop(c1.into_raw());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 2. Publish a QoS 1 message while subscriber is offline.
    let pub_conn = ConnectParams::new(pub_id);
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    pub_client
        .send_publish(&PublishParams::qos1(topic, b"persist-verify".to_vec(), 1))
        .await?;
    for _ in 0..5 {
        if let Ok(Packet::PubAck(_)) = pub_client.recv().await {
            break;
        }
    }
    drop(pub_client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Reconnect with Clean Start=0.
    let mut params2 = ConnectParams::new(client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (mut c2, connack) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    if !connack.session_present {
        cleanup_session(config.addr, client_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "Session Present=0 on reconnect with Clean Start=0 (expected 1)",
        ));
    }

    // 4. Verify queued message is delivered — proves session state was preserved.
    let result = match c2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Outcome::Pass,
        Ok(other) => Outcome::fail_packet("queued PUBLISH from persisted session", &other),
        Err(RecvError::Timeout) | Err(RecvError::Closed) => Outcome::fail(
            "Session Present=1 but queued message not delivered — session state incomplete",
        ),
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };

    cleanup_session(config.addr, client_id, config.recv_timeout).await;

    Ok(result)
}

const QOS1_DUP_FLAG: TestContext = TestContext {
    refs: &["MQTT-3.3.1-1"],
    description: "DUP MUST be 1 when re-delivering a QoS 1 PUBLISH the client already received",
    compliance: Compliance::Must,
};

/// When a QoS 1 PUBLISH was delivered to a connected client but not acknowledged,
/// the broker MUST set DUP=1 when re-delivering it after session resume [MQTT-3.3.1-1].
///
/// This differs from `qos1_redelivery_on_resume` which publishes while the subscriber
/// is offline (first delivery, DUP=0 is correct). Here the subscriber is online when
/// the message arrives, does not PUBACK, disconnects abruptly, and reconnects.
async fn qos1_dup_on_redelivery(config: TestConfig<'_>) -> Result<Outcome> {
    let sub_id = "mqtt-test-qos1-dup-sub";
    let pub_id = "mqtt-test-qos1-dup-pub";
    let topic = "mqtt/test/session/qos1dup";

    // 1. Connect subscriber with persistent session and subscribe at QoS 1.
    let mut sub_params = ConnectParams::new(sub_id);
    sub_params.properties.session_expiry_interval = Some(60);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // 2. Publish a QoS 1 message from another client while subscriber is online.
    let pub_conn = ConnectParams::new(pub_id);
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    pub_client
        .send_publish(&PublishParams::qos1(topic, b"dup-test".to_vec(), 1))
        .await?;
    for _ in 0..5 {
        if let Ok(Packet::PubAck(_)) = pub_client.recv().await {
            break;
        }
    }
    drop(pub_client);

    // 3. Subscriber receives the PUBLISH but does NOT send PUBACK.
    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => {}
        Ok(other) => return Ok(Outcome::fail_packet("PUBLISH", &other)),
        Err(RecvError::Timeout) => {
            cleanup_session(config.addr, sub_id, config.recv_timeout).await;
            return Ok(Outcome::fail("subscriber did not receive PUBLISH (timed out)"));
        }
        Err(RecvError::Closed) => {
            cleanup_session(config.addr, sub_id, config.recv_timeout).await;
            return Ok(Outcome::fail("connection closed before PUBLISH received"));
        }
        Err(RecvError::Other(e)) => return Err(e),
    }

    // 4. Disconnect abruptly (no PUBACK, no DISCONNECT) so the message is unacknowledged.
    drop(sub_client.into_raw());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 5. Reconnect with Clean Start=0 — broker should redeliver with DUP=1.
    let mut sub_params2 = ConnectParams::new(sub_id);
    sub_params2.clean_start = false;
    sub_params2.properties.session_expiry_interval = Some(60);
    let (mut sub_client2, connack) =
        client::connect(config.addr, &sub_params2, config.recv_timeout).await?;

    if !connack.session_present {
        cleanup_session(config.addr, sub_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "Broker did not preserve session (session_present=0); cannot test DUP redelivery",
        ));
    }

    let result = match sub_client2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => {
            if p.dup {
                Outcome::Pass
            } else {
                Outcome::fail("Redelivered QoS 1 PUBLISH has DUP=0, expected DUP=1")
            }
        }
        Ok(other) => Outcome::fail_packet("redelivered PUBLISH with DUP=1", &other),
        Err(RecvError::Timeout) | Err(RecvError::Closed) => {
            Outcome::fail("No QoS 1 message redelivered after session resume")
        }
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}
