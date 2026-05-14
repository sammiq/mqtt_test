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

    // MQTT-3.1.2-4 — Clean Start=1 MUST discard any existing Session
    suite.add(
        CLEAN_START_DISCARDS,
        clean_start_discards_existing_session(config),
    );

    // MQTT-3.1.2-5 / MQTT-3.2.2-3 — Clean Start=0 with existing Session: MUST resume
    // communications and CONNACK Session Present MUST be 1
    suite.add(SESSION_PRESENT, session_present_on_resume(config));
    suite.add(SUB_PERSISTS, subscription_persists_across_sessions(config));
    suite.add(
        SESSION_PRESENT_PERSISTENCE,
        session_present_verify_persistence(config),
    );

    // MQTT-3.1.2-6 — Clean Start=0 with no existing Session MUST create a new Session
    suite.add(
        CLEAN_START_FALSE_CREATES,
        clean_start_false_creates_new_session(config),
    );

    // MQTT-3.1.2-23 — Session State MUST be stored when Session Expiry Interval > 0
    suite.add(SESSION_EXPIRY_MAX, session_expiry_max(config));

    // MQTT-3.1.4-3 — Duplicate ClientID: Server MUST close the existing Client's connection
    suite.add(SESSION_TAKEOVER, session_takeover(config));

    // ── reviewed up to here ─────────────────────────────────────────────────

    suite.add(QOS1_REDELIVER, qos1_redelivery_on_resume(config));
    suite.add(QOS2_REDELIVER, qos2_redelivery_on_resume(config));
    suite.add(SESSION_EXPIRY_ZERO, session_expiry_zero(config));
    suite.add(SESSION_EXPIRY_DISCARD, session_expiry_discard(config));
    suite.add(QOS1_DUP_FLAG, qos1_dup_on_redelivery(config));

    suite
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const CLEAN_START_DISCARDS: TestContext = TestContext {
    refs: &["MQTT-3.1.2-4"],
    description: "Clean Start=1 MUST discard any existing Session and start a new Session",
    compliance: Compliance::Must,
};

/// If a CONNECT packet is received with Clean Start is set to 1, the Client and Server MUST discard
/// any existing Session and start a new Session. [MQTT-3.1.2-4]
///
/// This test:
/// 1. Connects with Clean Start=1 + Session Expiry Interval=60 (creating a persistent session),
///    subscribes to a topic, and disconnects gracefully — leaving the session resident on the
///    broker with an active subscription.
/// 2. Reconnects with the same Client ID and Clean Start=1 — the broker MUST discard the prior
///    session. Asserts CONNACK session_present=0.
/// 3. Publishes to the subscribed topic from a third client and verifies the reconnected subscriber
///    receives nothing, confirming the prior subscription was discarded along with the session.
async fn clean_start_discards_existing_session(config: TestConfig<'_>) -> Result<Outcome> {
    let sub_id = "mqtt-test-clean-start-discards";
    let pub_id = "mqtt-test-clean-start-discards-pub";
    let topic = "mqtt/test/session/clean-start-discards";

    // 1. Establish a persistent session with a subscription.
    let mut params = ConnectParams::new(sub_id);
    params.properties.session_expiry_interval = Some(60);
    let (mut c1, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    c1.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut c1).await {
        cleanup_session(config.addr, sub_id, config.recv_timeout).await;
        return Ok(r);
    }
    drop(c1); // AutoDisconnect sends DISCONNECT on drop — session persists (SEI=60).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Reconnect with Clean Start=1 — broker MUST discard the prior session.
    let mut params2 = ConnectParams::new(sub_id);
    params2.clean_start = true;
    params2.properties.session_expiry_interval = Some(60);
    let (mut c2, connack) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    if connack.session_present {
        cleanup_session(config.addr, sub_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "CONNACK session_present=1 on Clean Start=1 reconnect — prior session not discarded",
        ));
    }

    // 3. Publish to the previously-subscribed topic from a separate client.
    let pub_params = ConnectParams::new(pub_id);
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params, config.recv_timeout).await?;
    let pub_msg = PublishParams::qos1(topic, b"should-not-arrive".to_vec(), 1);
    pub_client.send_publish(&pub_msg).await?;
    // Wait for PUBACK so we know the broker has processed the publish.
    for _ in 0..5 {
        if let Ok(Packet::PubAck(_)) = pub_client.recv().await {
            break;
        }
    }
    drop(pub_client);

    // 4. Reconnected subscriber MUST NOT receive the message — subscription was discarded.
    let result = match c2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Outcome::fail(
            "Received PUBLISH on topic from prior session — subscription was not discarded",
        ),
        Ok(other) => Outcome::fail_packet("no delivery (subscription discarded)", &other),
        Err(RecvError::Timeout) | Err(RecvError::Closed) => Outcome::Pass,
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}

const SESSION_PRESENT: TestContext = TestContext {
    refs: &["MQTT-3.1.2-5", "MQTT-3.2.2-3"],
    description: "Clean Start=0 with existing Session: resume MUST set CONNACK Session Present=1",
    compliance: Compliance::Must,
};

/// If a CONNECT packet is received with Clean Start set to 0 and there is a Session associated with
/// the Client Identifier, the Server MUST resume communications with the Client based on state from
/// the existing Session. [MQTT-3.1.2-5]
///
/// If the Server accepts a connection with Clean Start set to 0 and the Server has Session State
/// for the ClientID, it MUST set Session Present to 1 in the CONNACK packet, otherwise it MUST set
/// Session Present to 0 in the CONNACK packet. In both cases it MUST set a 0x00 (Success) Reason
/// Code in the CONNACK packet. [MQTT-3.2.2-3]
///
/// This test connects with Clean Start=1 + Session Expiry Interval=60 (creating a persistent
/// session), disconnects gracefully, then reconnects with the same Client ID and Clean Start=0, and
/// verifies CONNACK session_present=1 — covering the "Session State exists" branch of -3.2.2-3
/// and demonstrating the broker resumed the existing Session per -3.1.2-5. The complementary
/// "no Session State" branch of -3.2.2-3 is covered by `clean_start_false_no_session` in
/// [connect.rs]. End-to-end resume + queued-delivery is covered by
/// `session_present_verify_persistence`.
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

const SUB_PERSISTS: TestContext = TestContext {
    refs: &["MQTT-3.1.2-5"],
    description: "Subscriptions from a resumed Session MUST continue delivering messages",
    compliance: Compliance::Must,
};

/// If a CONNECT packet is received with Clean Start set to 0 and there is a Session associated with
/// the Client Identifier, the Server MUST resume communications with the Client based on state from
/// the existing Session. [MQTT-3.1.2-5]
///
/// This test subscribes with a persistent session, disconnects gracefully, reconnects with
/// Clean Start=0 (without re-subscribing), then publishes to the subscribed topic from a separate
/// client and verifies the reconnected subscriber receives the message — confirming the broker
/// resumed the subscription state as part of the Session.
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

const SESSION_PRESENT_PERSISTENCE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-5", "MQTT-3.2.2-3"],
    description: "On resume, Session Present=1 AND queued messages MUST be delivered",
    compliance: Compliance::Must,
};

/// If a CONNECT packet is received with Clean Start set to 0 and there is a Session associated with
/// the Client Identifier, the Server MUST resume communications with the Client based on state from
/// the existing Session [MQTT-3.1.2-5]. If the Server accepts a connection with Clean Start set to 0
/// and already has Session State for the ClientID, it MUST set Session Present to 1 in the CONNACK
/// packet [MQTT-3.2.2-3].
///
/// This test verifies end-to-end persistence: connects with a persistent session, subscribes at
/// QoS 1, disconnects abruptly so a subsequent publish queues, reconnects with Clean Start=0, and
/// checks both CONNACK session_present=1 AND delivery of the queued message — confirming the broker
/// resumed the Session's subscription and inflight-message state.
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

const CLEAN_START_FALSE_CREATES: TestContext = TestContext {
    refs: &["MQTT-3.1.2-6"],
    description: "Clean Start=0 with no existing Session MUST create a new Session",
    compliance: Compliance::Must,
};

/// If a CONNECT packet is received with Clean Start set to 0 and there is no Session associated with
/// the Client Identifier, the Server MUST create a new Session. [MQTT-3.1.2-6]
///
/// This test goes beyond checking the CONNACK field — it verifies the broker actually *created* a
/// Session:
/// 1. Connects with Clean Start=0, a fresh (timestamp-derived) Client ID, and Session Expiry
///    Interval=60. Asserts CONNACK session_present=0 (no prior session).
/// 2. Disconnects gracefully.
/// 3. Reconnects with Clean Start=0 and the same Client ID. Asserts CONNACK session_present=1 —
///    proving the broker stored the Session from step 1. A broker that returned session_present=0
///    in step 1 but silently dropped state would fail at step 3.
async fn clean_start_false_creates_new_session(config: TestConfig<'_>) -> Result<Outcome> {
    let client_id = format!(
        "mqtt-test-cs-false-create-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );

    // 1. First connect with Clean Start=0 — no prior session for this fresh client ID.
    let mut params = ConnectParams::new(&client_id);
    params.clean_start = false;
    params.properties.session_expiry_interval = Some(60);
    let (c1, connack1) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack1.session_present {
        cleanup_session(config.addr, &client_id, config.recv_timeout).await;
        return Ok(Outcome::fail(
            "CONNACK session_present=1 on first Clean Start=0 connect with unused Client ID",
        ));
    }
    drop(c1); // AutoDisconnect sends DISCONNECT on drop.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Reconnect with Clean Start=0 and same Client ID — broker must have a Session.
    let mut params2 = ConnectParams::new(&client_id);
    params2.clean_start = false;
    params2.properties.session_expiry_interval = Some(60);
    let (_c2, connack2) = client::connect(config.addr, &params2, config.recv_timeout).await?;

    let result = if connack2.session_present {
        Outcome::Pass
    } else {
        Outcome::fail(
            "CONNACK session_present=0 on reconnect — broker did not create a Session on first Clean Start=0 connect",
        )
    };

    cleanup_session(config.addr, &client_id, config.recv_timeout).await;

    Ok(result)
}

const QOS1_REDELIVER: TestContext = TestContext {
    refs: &["MQTT-4.4.0-1", "MQTT-4.5.0-1"],
    description: "Unacknowledged QoS 1 messages MUST be redelivered on session resume",
    compliance: Compliance::Must,
};

/// When a new Network Connection to this Session is made, the Client and Server MUST resend any unacknowledged
/// PUBLISH packets using their original Packet Identifiers. This is the only circumstance where a Client or Server
/// is REQUIRED to resend messages [MQTT-4.4.0-1]. When a Server takes ownership of an incoming Application Message
/// it MUST add it to the Session State for those Clients that have matching Subscriptions [MQTT-4.5.0-1].
///
/// This test publishes a QoS 1 message while the subscriber is offline, then reconnects with Clean Start=0 and
/// verifies the queued message is delivered. Since the subscriber was offline, this is a first delivery (DUP=0 is
/// correct). See `qos1_dup_on_redelivery` for the DUP=1 check.
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
    refs: &["MQTT-4.4.0-1"],
    description: "Incomplete QoS 2 flows MUST be resumed on session reconnect",
    compliance: Compliance::Must,
};

/// When a new Network Connection to this Session is made, the Client and Server MUST resend any unacknowledged
/// PUBLISH packets using their original Packet Identifiers [MQTT-4.4.0-1].
///
/// This test publishes a QoS 2 message while the subscriber is offline, then reconnects with Clean Start=0 and
/// verifies the queued message is delivered on session resume.
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

    // 5. Should receive the queued QoS 2 message as a PUBLISH. A PUBREL would only
    //    be valid if the subscriber had previously received the PUBLISH and sent
    //    PUBREC — but the subscriber was offline when the message was published.
    let result = match sub_client2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Outcome::Pass,
        Ok(other) => Outcome::fail_packet("PUBLISH on session resume", &other),
        Err(RecvError::Timeout) | Err(RecvError::Closed) => {
            Outcome::fail("No queued QoS 2 message redelivered after session resume")
        }
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };
    // AutoDisconnect on sub_client2 sends DISCONNECT on drop.

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}

const SESSION_EXPIRY_ZERO: TestContext = TestContext {
    refs: &["MQTT-4.1.0-2"],
    description: "Session Expiry Interval of 0 means session ends on disconnect",
    compliance: Compliance::Must,
};

/// The Server MUST discard the Session State when the Network Connection is closed and the Session Expiry Interval
/// has passed [MQTT-4.1.0-2].
///
/// This test connects with Session Expiry Interval=0, disconnects, then reconnects with Clean Start=0 and verifies
/// the session is gone (session_present=0).
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
    refs: &["MQTT-3.1.2-23"],
    description: "Session State MUST persist across reconnect when Session Expiry Interval > 0",
    compliance: Compliance::Must,
};

/// The Client and Server MUST store the Session State after the Network Connection is closed if
/// the Session Expiry Interval is greater than 0. [MQTT-3.1.2-23]
///
/// This test exercises the non-expiring boundary: connects with Session Expiry Interval=0xFFFFFFFF
/// (UINT_MAX, which per §3.1.2.11.2 means "the Session does not expire"), cleanly disconnects, and
/// then reconnects with Clean Start=0 and verifies `session_present=1` — confirming the broker
/// stored the Session State. The inverse cases (SEI=0 → discard, finite SEI elapsed → discard) are
/// covered by `session_expiry_zero` and `session_expiry_discard` under MQTT-4.1.0-2. A finite-SEI
/// resume within the window is additionally covered by `session_present_on_resume`.
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
    description: "Server MUST close existing client's connection on duplicate Client ID",
    compliance: Compliance::Must,
};

/// If the ClientID represents a Client already connected to the Server, the Server sends a
/// DISCONNECT packet to the existing Client with Reason Code of 0x8E (Session taken over) as
/// described in section 4.13 and MUST close the Network Connection of the existing Client.
/// [MQTT-3.1.4-3]
///
/// This test connects two clients with the same Client ID and verifies the first has its network
/// connection closed — the MUST portion of the requirement. Either a clean TCP close or a received
/// DISCONNECT packet satisfies the MUST. The companion test
/// `disconnect_reason_session_takeover` in [disconnect.rs] covers the prescriptive "sends a
/// DISCONNECT ... with Reason Code 0x8E" part at SHOULD level.
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
    refs: &["MQTT-4.1.0-2"],
    description: "Server MUST discard session state when Session Expiry Interval has passed",
    compliance: Compliance::Must,
};

/// The Server MUST discard the Session State when the Network Connection is closed and the Session Expiry Interval
/// has passed [MQTT-4.1.0-2].
///
/// This test connects with a 2-second session expiry, subscribes, disconnects, waits 3 seconds, then verifies the
/// session is gone.
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

const QOS1_DUP_FLAG: TestContext = TestContext {
    refs: &["MQTT-3.3.1-1"],
    description: "DUP MUST be 1 when re-delivering a QoS 1 PUBLISH the client already received",
    compliance: Compliance::Must,
};

/// The DUP flag MUST be set to 1 by the Client or Server when it attempts to re-deliver a PUBLISH
/// packet [MQTT-3.3.1-1].
///
/// This test delivers a QoS 1 message to a connected subscriber that does not PUBACK, disconnects abruptly, then
/// reconnects with Clean Start=0 and verifies the redelivered message has DUP=1.
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
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
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
            return Ok(Outcome::fail(
                "subscriber did not receive PUBLISH (timed out)",
            ));
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
