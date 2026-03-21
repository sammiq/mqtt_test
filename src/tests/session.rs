//! Session state and message redelivery compliance tests [MQTT-4.4 / MQTT-3.1.2].

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client;
use crate::codec::{ConnectParams, Packet, PublishParams, QoS, SubscribeParams};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 7;

/// Clean up a persistent session by reconnecting with clean_start=true.
async fn cleanup_session(addr: &str, client_id: &str, recv_timeout: Duration) {
    let params = ConnectParams::new(client_id);
    if let Ok((_c, _)) = client::connect(addr, &params, recv_timeout).await {
        // AutoDisconnect handles the clean disconnect on drop.
    }
}

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "SESSION",
        results: vec![
            session_present_on_resume(addr, recv_timeout, pb).await,
            qos1_redelivery_on_resume(addr, recv_timeout, pb).await,
            qos2_redelivery_on_resume(addr, recv_timeout, pb).await,
            subscription_persists_across_sessions(addr, recv_timeout, pb).await,
            session_expiry_zero(addr, recv_timeout, pb).await,
            session_expiry_max(addr, recv_timeout, pb).await,
            session_takeover(addr, recv_timeout, pb).await,
        ],
    }
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const SESSION_PRESENT: TestContext = TestContext {
    id: "MQTT-3.1.2-5",
    description: "Clean Start=0 with prior session: session_present MUST be 1",
    compliance: Compliance::Must,
};

/// If a session exists and the client reconnects with Clean Start=0,
/// session_present MUST be 1 in the CONNACK [MQTT-3.1.2-5].
async fn session_present_on_resume(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SESSION_PRESENT;
    run_test(ctx, pb, async {
        let client_id = "mqtt-test-session-present";

        // First connection: Clean Start=1, set Session Expiry so the session survives.
        let mut params = ConnectParams::new(client_id);
        params.properties.session_expiry_interval = Some(60);
        let (c1, _) = client::connect(addr, &params, recv_timeout).await?;
        drop(c1); // AutoDisconnect sends DISCONNECT on drop.

        // Small delay so the broker has processed the disconnect.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second connection: Clean Start=0 — broker should find the session.
        let mut params2 = ConnectParams::new(client_id);
        params2.clean_start = false;
        params2.properties.session_expiry_interval = Some(60);
        let (_c2, connack) = client::connect(addr, &params2, recv_timeout).await?;

        // Clean up the session.
        cleanup_session(addr, client_id, recv_timeout).await;

        if connack.session_present {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                "session_present=0 on reconnect with Clean Start=0 (expected 1)",
            ))
        }
    })
    .await
}

const QOS1_REDELIVER: TestContext = TestContext {
    id: "MQTT-4.4.0-1",
    description: "Unacknowledged QoS 1 messages MUST be redelivered on session resume",
    compliance: Compliance::Must,
};

/// When a client reconnects with Clean Start=0, any QoS 1 messages that were
/// not acknowledged MUST be redelivered [MQTT-4.4.0-1].
async fn qos1_redelivery_on_resume(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = QOS1_REDELIVER;
    run_test(ctx, pb, async {
        let sub_id = "mqtt-test-qos1-redel-sub";
        let pub_id = "mqtt-test-qos1-redel-pub";
        let topic = "mqtt/test/session/qos1";

        // 1. Connect subscriber with persistent session and subscribe at QoS 1.
        let mut sub_params = ConnectParams::new(sub_id);
        sub_params.properties.session_expiry_interval = Some(60);
        let (mut sub_client, _) = client::connect(addr, &sub_params, recv_timeout).await?;

        let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        // 2. Disconnect the subscriber abruptly (no DISCONNECT packet) so messages queue.
        drop(sub_client.into_raw());
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 3. Publish a QoS 1 message while subscriber is offline.
        let pub_params_conn = ConnectParams::new(pub_id);
        let (mut pub_client, _) = client::connect(addr, &pub_params_conn, recv_timeout).await?;
        let pub_msg = PublishParams::qos1(topic, b"queued-qos1".to_vec(), 1);
        pub_client.send_publish(&pub_msg).await?;
        // Wait for PUBACK.
        for _ in 0..5 {
            if let Packet::PubAck(_) = pub_client.recv(recv_timeout).await? { break }
        }
        drop(pub_client); // AutoDisconnect sends DISCONNECT on drop.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 4. Reconnect subscriber with Clean Start=0 — should receive the queued message.
        let mut sub_params2 = ConnectParams::new(sub_id);
        sub_params2.clean_start = false;
        sub_params2.properties.session_expiry_interval = Some(60);
        let (mut sub_client2, connack) = client::connect(addr, &sub_params2, recv_timeout).await?;

        if !connack.session_present {
            cleanup_session(addr, sub_id, recv_timeout).await;
            return Ok(TestResult::fail(
                &ctx,
                "Broker did not preserve session (session_present=0); cannot test redelivery",
            ));
        }

        // 5. Check for the redelivered message.
        let result = match sub_client2.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                TestResult::pass(&ctx)
            }
            Ok(other) => {
                TestResult::fail_packet(&ctx, "redelivered PUBLISH on session resume", &other)
            }
            Err(_) => {
                TestResult::fail(
                    &ctx,
                    "No queued QoS 1 message redelivered after session resume",
                )
            }
        };
        // AutoDisconnect on sub_client2 sends DISCONNECT on drop.

        cleanup_session(addr, sub_id, recv_timeout).await;

        Ok(result)
    })
    .await
}

const QOS2_REDELIVER: TestContext = TestContext {
    id: "MQTT-4.4.0-2",
    description: "Incomplete QoS 2 flows MUST be resumed on session reconnect",
    compliance: Compliance::Must,
};

/// When a client reconnects with Clean Start=0, incomplete QoS 2 flows
/// MUST be resumed [MQTT-4.3.3 / MQTT-4.4].
async fn qos2_redelivery_on_resume(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = QOS2_REDELIVER;
    run_test(ctx, pb, async {
        let sub_id = "mqtt-test-qos2-redel-sub";
        let pub_id = "mqtt-test-qos2-redel-pub";
        let topic = "mqtt/test/session/qos2";

        // 1. Connect subscriber with persistent session and subscribe at QoS 2.
        let mut sub_params = ConnectParams::new(sub_id);
        sub_params.properties.session_expiry_interval = Some(60);
        let (mut sub_client, _) = client::connect(addr, &sub_params, recv_timeout).await?;

        let sub = SubscribeParams::simple(1, topic, QoS::ExactlyOnce);
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        // 2. Disconnect subscriber abruptly.
        drop(sub_client.into_raw());
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 3. Publish a QoS 2 message while subscriber is offline.
        let pub_params_conn = ConnectParams::new(pub_id);
        let (mut pub_client, _) = client::connect(addr, &pub_params_conn, recv_timeout).await?;
        let pub_msg = PublishParams::qos2(topic, b"queued-qos2".to_vec(), 1);
        pub_client.send_publish(&pub_msg).await?;

        // Complete the QoS 2 handshake on the publisher side.
        for _ in 0..5 {
            match pub_client.recv(recv_timeout).await? {
                Packet::PubRec(rec) if rec.packet_id == 1 => {
                    pub_client.send_pubrel(1, 0x00).await?;
                    // Wait for PUBCOMP.
                    for _ in 0..5 {
                        if let Packet::PubComp(_) = pub_client.recv(recv_timeout).await? { break }
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
        let (mut sub_client2, connack) = client::connect(addr, &sub_params2, recv_timeout).await?;

        if !connack.session_present {
            cleanup_session(addr, sub_id, recv_timeout).await;
            return Ok(TestResult::fail(
                &ctx,
                "Broker did not preserve session (session_present=0); cannot test redelivery",
            ));
        }

        // 5. Should receive the queued QoS 2 message (as PUBLISH or PUBREL depending on state).
        let result = match sub_client2.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                TestResult::pass(&ctx)
            }
            Ok(Packet::PubRel(_)) => {
                // The broker may resume at the PUBREL stage — this is also valid.
                TestResult::pass(&ctx)
            }
            Ok(other) => {
                TestResult::fail_packet(&ctx, "redelivered PUBLISH or PUBREL on session resume", &other)
            }
            Err(_) => {
                TestResult::fail(
                    &ctx,
                    "No queued QoS 2 message redelivered after session resume",
                )
            }
        };
        // AutoDisconnect on sub_client2 sends DISCONNECT on drop.

        cleanup_session(addr, sub_id, recv_timeout).await;

        Ok(result)
    })
    .await
}

const SUB_PERSISTS: TestContext = TestContext {
    id: "MQTT-3.1.2-6",
    description: "Subscriptions MUST persist across session reconnects",
    compliance: Compliance::Must,
};

/// When a client reconnects with Clean Start=0, its subscriptions from
/// the previous session MUST still be active [MQTT-3.1.2-6].
async fn subscription_persists_across_sessions(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUB_PERSISTS;
    run_test(ctx, pb, async {
        let sub_id = "mqtt-test-sub-persist";
        let pub_id = "mqtt-test-sub-persist-pub";
        let topic = "mqtt/test/session/persist";

        // 1. Connect, subscribe, then disconnect gracefully.
        let mut params = ConnectParams::new(sub_id);
        params.properties.session_expiry_interval = Some(60);
        let (mut c1, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams::simple(1, topic, QoS::AtMostOnce);
        c1.send_subscribe(&sub).await?;
        c1.recv(recv_timeout).await?; // SUBACK
        drop(c1); // AutoDisconnect sends DISCONNECT on drop.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 2. Reconnect with Clean Start=0 — do NOT re-subscribe.
        let mut params2 = ConnectParams::new(sub_id);
        params2.clean_start = false;
        params2.properties.session_expiry_interval = Some(60);
        let (mut c2, connack) = client::connect(addr, &params2, recv_timeout).await?;

        if !connack.session_present {
            cleanup_session(addr, sub_id, recv_timeout).await;
            return Ok(TestResult::fail(
                &ctx,
                "Broker did not preserve session (session_present=0); cannot test subscription persistence",
            ));
        }

        // 3. Publish a message from a different client.
        let pub_params_conn = ConnectParams::new(pub_id);
        let (mut pub_client, _) = client::connect(addr, &pub_params_conn, recv_timeout).await?;
        let pub_msg = PublishParams::qos0(topic, b"persist-test".to_vec());
        pub_client.send_publish(&pub_msg).await?;
        // AutoDisconnect on pub_client sends DISCONNECT on drop.

        // 4. The reconnected subscriber should receive it without re-subscribing.
        let result = match c2.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                TestResult::pass(&ctx)
            }
            Ok(other) => {
                TestResult::fail_packet(&ctx, "PUBLISH from persisted subscription", &other)
            }
            Err(_) => {
                TestResult::fail(
                    &ctx,
                    "No message received — subscription did not persist across reconnect",
                )
            }
        };
        // AutoDisconnect on c2 sends DISCONNECT on drop.

        cleanup_session(addr, sub_id, recv_timeout).await;

        Ok(result)
    })
    .await
}

const SESSION_EXPIRY_ZERO: TestContext = TestContext {
    id: "MQTT-3.1.2-10",
    description: "Session Expiry Interval of 0 means session ends on disconnect",
    compliance: Compliance::Must,
};

/// A Session Expiry Interval of 0 means the session state MUST be discarded
/// when the connection closes [MQTT-3.1.2-10].
async fn session_expiry_zero(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SESSION_EXPIRY_ZERO;
    run_test(ctx, pb, async {
        let client_id = "mqtt-test-session-exp-zero";

        // First connection: Session Expiry Interval = 0 (explicit).
        let mut params = ConnectParams::new(client_id);
        params.properties.session_expiry_interval = Some(0);
        let (c1, _) = client::connect(addr, &params, recv_timeout).await?;
        drop(c1);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Reconnect with Clean Start=0 — session should NOT exist.
        let mut params2 = ConnectParams::new(client_id);
        params2.clean_start = false;
        let (_c2, connack) = client::connect(addr, &params2, recv_timeout).await?;

        cleanup_session(addr, client_id, recv_timeout).await;

        if !connack.session_present {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                "session_present=1 despite Session Expiry Interval=0",
            ))
        }
    })
    .await
}

const SESSION_EXPIRY_MAX: TestContext = TestContext {
    id: "MQTT-3.1.2-11a",
    description: "Session Expiry Interval of 0xFFFFFFFF means session never expires",
    compliance: Compliance::Must,
};

/// Session Expiry Interval of 0xFFFFFFFF means the session does not expire.
/// Reconnecting with Clean Start=0 should find the session [MQTT-3.1.2-11].
async fn session_expiry_max(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SESSION_EXPIRY_MAX;
    run_test(ctx, pb, async {
        let client_id = "mqtt-test-session-exp-max";

        // First connection with max session expiry.
        let mut params = ConnectParams::new(client_id);
        params.properties.session_expiry_interval = Some(0xFFFF_FFFF);
        let (c1, _) = client::connect(addr, &params, recv_timeout).await?;
        drop(c1);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Reconnect with Clean Start=0 — session MUST still exist.
        let mut params2 = ConnectParams::new(client_id);
        params2.clean_start = false;
        params2.properties.session_expiry_interval = Some(0xFFFF_FFFF);
        let (_c2, connack) = client::connect(addr, &params2, recv_timeout).await?;

        cleanup_session(addr, client_id, recv_timeout).await;

        if connack.session_present {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                "session_present=0 despite Session Expiry Interval=0xFFFFFFFF",
            ))
        }
    })
    .await
}

const SESSION_TAKEOVER: TestContext = TestContext {
    id: "MQTT-3.1.4-3",
    description: "Server MUST disconnect existing client when new client uses same Client ID",
    compliance: Compliance::Must,
};

/// If a client connects with a Client Identifier already in use, the server
/// MUST disconnect the existing client [MQTT-3.1.4-3].
async fn session_takeover(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SESSION_TAKEOVER;
    run_test(ctx, pb, async {
        let client_id = "mqtt-test-session-takeover";

        // First connection.
        let mut params = ConnectParams::new(client_id);
        params.properties.session_expiry_interval = Some(60);
        let (mut c1, _) = client::connect(addr, &params, recv_timeout).await?;

        // Second connection with the same Client ID — should disconnect c1.
        let mut params2 = ConnectParams::new(client_id);
        params2.clean_start = false;
        params2.properties.session_expiry_interval = Some(60);
        let (_c2, _) = client::connect(addr, &params2, recv_timeout).await?;

        // c1 should have been disconnected by the server.
        let result = match c1.recv(recv_timeout).await {
            Err(_) => TestResult::pass(&ctx), // Connection closed
            Ok(Packet::Disconnect(_)) => TestResult::pass(&ctx),
            Ok(other) => TestResult::fail_packet(&ctx, "DISCONNECT or connection close", &other),
        };

        cleanup_session(addr, client_id, recv_timeout).await;

        Ok(result)
    })
    .await
}

