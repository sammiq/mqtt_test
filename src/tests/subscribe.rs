//! SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK compliance tests [MQTT-3.8 / MQTT-3.10].

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client;
use crate::codec::{
    ConnectParams, Packet, Properties, PublishParams, QoS, SubscribeOptions, SubscribeParams,
    UnsubscribeParams,
};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 21;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "SUBSCRIBE / UNSUBSCRIBE",
        results: vec![
            basic_subscribe(addr, recv_timeout, pb).await,
            wildcard_plus(addr, recv_timeout, pb).await,
            wildcard_hash(addr, recv_timeout, pb).await,
            unsubscribe(addr, recv_timeout, pb).await,
            dollar_topic_no_wildcard_match(addr, recv_timeout, pb).await,
            suback_reason_code_count(addr, recv_timeout, pb).await,
            unsuback_reason_code_count(addr, recv_timeout, pb).await,
            shared_subscription(addr, recv_timeout, pb).await,
            subscription_identifier(addr, recv_timeout, pb).await,
            no_local_flag(addr, recv_timeout, pb).await,
            retain_as_published(addr, recv_timeout, pb).await,
            retain_handling_1(addr, recv_timeout, pb).await,
            retain_handling_2(addr, recv_timeout, pb).await,
            unsubscribe_stops_delivery(addr, recv_timeout, pb).await,
            overlapping_subscriptions_max_qos(addr, recv_timeout, pb).await,
            subscription_id_overlapping(addr, recv_timeout, pb).await,
            multi_level_topic(addr, recv_timeout, pb).await,
            wildcard_middle_level(addr, recv_timeout, pb).await,
            multiple_filters_single_subscribe(addr, recv_timeout, pb).await,
            subscription_upgrade_qos(addr, recv_timeout, pb).await,
            empty_topic_level(addr, recv_timeout, pb).await,
        ],
    }
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const BASIC_SUB: TestContext = TestContext {
    id: "MQTT-3.8.4-1",
    description: "Server MUST send SUBACK in response to SUBSCRIBE",
    compliance: Compliance::Must,
};

/// Server MUST send SUBACK in response to SUBSCRIBE [MQTT-3.8.4-1].
async fn basic_subscribe(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = BASIC_SUB;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-subscribe");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams::simple(1, "mqtt/test/sub/basic", QoS::AtMostOnce);
        client.send_subscribe(&sub).await?;

        match client.recv(recv_timeout).await? {
            Packet::SubAck(ack) if ack.packet_id == 1 => {
                if ack.reason_codes.first().map(|&c| c < 0x80).unwrap_or(false) {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!("SUBACK reason code indicates failure: {:?}", ack.reason_codes),
                    ))
                }
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "SUBACK(1)", &other))
            }
        }
    })
    .await
}

const WILDCARD_PLUS: TestContext = TestContext {
    id: "MQTT-4.7.1-2",
    description: "'+' wildcard MUST match exactly one topic level",
    compliance: Compliance::Must,
};

/// `+` wildcard MUST match exactly one level [MQTT-4.7.1-2].
async fn wildcard_plus(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = WILDCARD_PLUS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-wildcard-plus");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams::simple(1, "mqtt/test/sub/wc_plus/+", QoS::AtMostOnce);
        client.send_subscribe(&sub).await?;
        match client.recv(recv_timeout).await? {
            Packet::SubAck(_) => {}
            other => {
                return Ok(TestResult::fail_packet(&ctx, "SUBACK", &other));
            }
        }

        client
            .send_publish(&PublishParams::qos0("mqtt/test/sub/wc_plus/match", b"plus".to_vec()))
            .await?;

        match client.recv(recv_timeout).await? {
            Packet::Publish(p) if p.topic == "mqtt/test/sub/wc_plus/match" => {
                Ok(TestResult::pass(&ctx))
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "PUBLISH on topic \"mqtt/test/sub/wc_plus/match\"", &other))
            }
        }
    })
    .await
}

const WILDCARD_HASH: TestContext = TestContext {
    id: "MQTT-4.7.1-3",
    description: "'#' wildcard MUST match all sub-levels",
    compliance: Compliance::Must,
};

/// `#` wildcard MUST match the parent and all sub-levels [MQTT-4.7.1-2].
async fn wildcard_hash(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = WILDCARD_HASH;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-wildcard-hash");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams::simple(1, "mqtt/test/sub/wc_hash/#", QoS::AtMostOnce);
        client.send_subscribe(&sub).await?;
        match client.recv(recv_timeout).await? {
            Packet::SubAck(_) => {}
            other => {
                return Ok(TestResult::fail_packet(&ctx, "SUBACK", &other));
            }
        }

        client
            .send_publish(&PublishParams::qos0(
                "mqtt/test/sub/wc_hash/deep/nested/topic",
                b"hash".to_vec(),
            ))
            .await?;

        match client.recv(recv_timeout).await? {
            Packet::Publish(p) if p.topic == "mqtt/test/sub/wc_hash/deep/nested/topic" => {
                Ok(TestResult::pass(&ctx))
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "PUBLISH on topic \"mqtt/test/sub/wc_hash/deep/nested/topic\"", &other))
            }
        }
    })
    .await
}

const UNSUB: TestContext = TestContext {
    id: "MQTT-3.10.4-4",
    description: "Server MUST send UNSUBACK in response to UNSUBSCRIBE",
    compliance: Compliance::Must,
};

/// Server MUST send UNSUBACK in response to UNSUBSCRIBE [MQTT-3.10.4-4].
async fn unsubscribe(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = UNSUB;
    run_test(ctx, pb, async {
        let mut client = client::connect_and_subscribe(addr, "mqtt-test-unsubscribe", "mqtt/test/sub/unsub", QoS::AtMostOnce, recv_timeout).await?;

        let unsub = UnsubscribeParams::simple(2, "mqtt/test/sub/unsub");
        client.send_unsubscribe(&unsub).await?;

        match client.recv(recv_timeout).await? {
            Packet::UnsubAck(ack) if ack.packet_id == 2 => {
                Ok(TestResult::pass(&ctx))
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "UNSUBACK(2)", &other))
            }
        }
    })
    .await
}

const DOLLAR_TOPIC: TestContext = TestContext {
    id: "MQTT-4.7.2-1",
    description: "Topics starting with $ MUST NOT match wildcard subscriptions (#, +/...)",
    compliance: Compliance::Must,
};

/// Topics starting with `$` MUST NOT be matched by subscriptions starting with `#` or `+` [MQTT-4.7.2-1].
async fn dollar_topic_no_wildcard_match(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = DOLLAR_TOPIC;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-dollar-topic");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        // Subscribe to "#" which should match everything EXCEPT $-prefixed topics
        let sub = SubscribeParams::simple(1, "#", QoS::AtMostOnce);
        client.send_subscribe(&sub).await?;
        match client.recv(recv_timeout).await? {
            Packet::SubAck(_) => {}
            other => {
                return Ok(TestResult::fail_packet(&ctx, "SUBACK", &other));
            }
        }

        // Publish to a $SYS topic — subscriber to "#" should NOT receive it
        client
            .send_publish(&PublishParams::qos0(
                "$SYS/mqtt/test/dollar",
                b"dollar-test".to_vec(),
            ))
            .await?;

        // Also publish a normal message so we know the subscription is active
        client
            .send_publish(&PublishParams::qos0(
                "mqtt/test/sub/dollar_canary",
                b"canary".to_vec(),
            ))
            .await?;

        // We should receive the canary but NOT the $SYS message
        let mut received_dollar = false;
        let mut received_canary = false;
        for _ in 0..5 {
            match client.recv(Duration::from_secs(2)).await {
                Ok(Packet::Publish(p)) if p.topic.starts_with("$SYS") => {
                    received_dollar = true;
                }
                Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/dollar_canary" => {
                    received_canary = true;
                    break;
                }
                Ok(Packet::Publish(_)) => {} // other messages on # — ignore
                Err(_) => break,
                Ok(_) => {}
            }
        }

        if received_dollar {
            Ok(TestResult::fail(
                &ctx,
                "$SYS topic was delivered to '#' subscriber",
            ))
        } else if received_canary {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                "Canary message not received — '#' subscription may not be working",
            ))
        }
    })
    .await
}

const SUBACK_REASON_COUNT: TestContext = TestContext {
    id: "MQTT-3.8.4-6",
    description: "SUBACK MUST contain one reason code for each topic filter",
    compliance: Compliance::Must,
};

/// SUBACK MUST contain a reason code for each Topic Filter in the SUBSCRIBE [MQTT-3.8.4-6].
async fn suback_reason_code_count(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUBACK_REASON_COUNT;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-suback-count");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![
                (
                    "mqtt/test/sub/count/a".to_string(),
                    SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
                ),
                (
                    "mqtt/test/sub/count/b".to_string(),
                    SubscribeOptions { qos: QoS::AtLeastOnce, ..Default::default() },
                ),
                (
                    "mqtt/test/sub/count/c".to_string(),
                    SubscribeOptions { qos: QoS::ExactlyOnce, ..Default::default() },
                ),
            ],
            properties: Properties::default(),
        };
        client.send_subscribe(&sub).await?;

        match client.recv(recv_timeout).await? {
            Packet::SubAck(ack) if ack.packet_id == 1 => {
                if ack.reason_codes.len() == 3 {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!(
                            "Expected 3 reason codes, got {}",
                            ack.reason_codes.len()
                        ),
                    ))
                }
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "SUBACK(1)", &other))
            }
        }
    })
    .await
}

const UNSUBACK_REASON_COUNT: TestContext = TestContext {
    id: "MQTT-3.10.4-5",
    description: "UNSUBACK MUST contain one reason code for each topic filter",
    compliance: Compliance::Must,
};

/// UNSUBACK MUST contain a reason code for each Topic Filter in the UNSUBSCRIBE [MQTT-3.10.4-5].
async fn unsuback_reason_code_count(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = UNSUBACK_REASON_COUNT;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-unsuback-count");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        // Subscribe to 3 topics first
        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![
                (
                    "mqtt/test/unsub/count/a".to_string(),
                    SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
                ),
                (
                    "mqtt/test/unsub/count/b".to_string(),
                    SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
                ),
                (
                    "mqtt/test/unsub/count/c".to_string(),
                    SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
                ),
            ],
            properties: Properties::default(),
        };
        client.send_subscribe(&sub).await?;
        client.recv(recv_timeout).await?; // SUBACK

        // Unsubscribe from all 3
        let unsub = UnsubscribeParams {
            packet_id:  2,
            filters:    vec![
                "mqtt/test/unsub/count/a".to_string(),
                "mqtt/test/unsub/count/b".to_string(),
                "mqtt/test/unsub/count/c".to_string(),
            ],
            properties: Properties::default(),
        };
        client.send_unsubscribe(&unsub).await?;

        match client.recv(recv_timeout).await? {
            Packet::UnsubAck(ack) if ack.packet_id == 2 => {
                if ack.reason_codes.len() == 3 {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!(
                            "Expected 3 reason codes, got {}",
                            ack.reason_codes.len()
                        ),
                    ))
                }
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "UNSUBACK(2)", &other))
            }
        }
    })
    .await
}

// ── MAY ──────────────────────────────────────────────────────────────────────

const SHARED_SUB: TestContext = TestContext {
    id: "MQTT-4.8.2-1",
    description: "Shared subscriptions ($share/...) are supported",
    compliance: Compliance::May,
};

/// Shared subscriptions ($share/group/topic) are accepted [MQTT-4.8.2].
async fn shared_subscription(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SHARED_SUB;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-shared-sub");
        let (mut client, connack) = client::connect(addr, &params, recv_timeout).await?;

        if connack.properties.shared_subscription_available == Some(false) {
            return Ok(TestResult::skip(
                &ctx,
                "Broker reported Shared Subscription Available = false",
            ));
        }

        let sub = SubscribeParams::simple(1, "$share/testgroup/mqtt/test/sub/shared", QoS::AtMostOnce);
        client.send_subscribe(&sub).await?;

        match client.recv(recv_timeout).await? {
            Packet::SubAck(ack) if ack.packet_id == 1 => {
                if ack.reason_codes.first().map(|&c| c < 0x80).unwrap_or(false) {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!("SUBACK reason code indicates failure: {:?}", ack.reason_codes),
                    ))
                }
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "SUBACK(1)", &other))
            }
        }
    })
    .await
}

// ── Subscribe options ───────────────────────────────────────────────────────

const SUB_ID: TestContext = TestContext {
    id: "MQTT-3.8.2-2",
    description: "Subscription Identifier MUST be returned in matching PUBLISH",
    compliance: Compliance::Must,
};

/// Subscription Identifier MUST be returned in matching PUBLISH [MQTT-3.8.2-2].
async fn subscription_identifier(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUB_ID;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-sub-id");
        let (mut client, connack) = client::connect(addr, &params, recv_timeout).await?;

        if connack.properties.subscription_ids_available == Some(false) {
            return Ok(TestResult::skip(
                &ctx,
                "Broker reported Subscription Identifiers Available = false",
            ));
        }

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                "mqtt/test/sub/subid".to_string(),
                SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
            )],
            properties: Properties { subscription_identifier: Some(42), ..Properties::default() },
        };
        client.send_subscribe(&sub).await?;
        client.recv(recv_timeout).await?; // SUBACK

        client
            .send_publish(&PublishParams::qos0("mqtt/test/sub/subid", b"subid-test".to_vec()))
            .await?;

        match client.recv(recv_timeout).await? {
            Packet::Publish(p) if p.topic == "mqtt/test/sub/subid" => {
                if p.properties.subscription_identifier == Some(42) {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!(
                            "Expected subscription_identifier=42, got {:?}",
                            p.properties.subscription_identifier
                        ),
                    ))
                }
            }
            other => {
                Ok(TestResult::fail_packet(&ctx, "PUBLISH on topic \"mqtt/test/sub/subid\"", &other))
            }
        }
    })
    .await
}

const NO_LOCAL: TestContext = TestContext {
    id: "MQTT-3.8.3-3",
    description: "no_local=true: server MUST NOT deliver messages from the same client",
    compliance: Compliance::Must,
};

/// no_local=true: server MUST NOT send messages published by the same client [MQTT-3.8.3-3].
async fn no_local_flag(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = NO_LOCAL;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-no-local");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                "mqtt/test/sub/no_local".to_string(),
                SubscribeOptions {
                    qos:      QoS::AtMostOnce,
                    no_local: true,
                    ..Default::default()
                },
            )],
            properties: Properties::default(),
        };
        client.send_subscribe(&sub).await?;
        client.recv(recv_timeout).await?; // SUBACK

        client
            .send_publish(&PublishParams::qos0(
                "mqtt/test/sub/no_local",
                b"no-local-test".to_vec(),
            ))
            .await?;

        // Expect NO message — short timeout is sufficient to confirm absence.
        match client.recv(Duration::from_secs(1)).await {
            Err(_) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/no_local" => {
                Ok(TestResult::fail(
                    &ctx,
                    "Received own PUBLISH despite no_local=true",
                ))
            }
            Ok(other) => {
                Ok(TestResult::fail_packet(&ctx, "no packet (no_local)", &other))
            }
        }
    })
    .await
}

const RETAIN_AS_PUB: TestContext = TestContext {
    id: "MQTT-3.8.3-4",
    description: "retain_as_published=true: retain flag MUST be preserved on delivery",
    compliance: Compliance::Must,
};

/// retain_as_published=true: retain flag MUST be preserved on delivery [MQTT-3.8.3-4].
async fn retain_as_published(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = RETAIN_AS_PUB;
    run_test(ctx, pb, async {
        let pub_params_conn = ConnectParams::new("mqtt-test-rap-pub");
        let (mut pub_client, connack) =
            client::connect(addr, &pub_params_conn, recv_timeout).await?;

        if connack.properties.retain_available == Some(false) {
            return Ok(TestResult::skip(
                &ctx,
                "Broker reported Retain Available = false",
            ));
        }

        // Publish retained message
        pub_client
            .send_publish(&PublishParams::retained("mqtt/test/sub/rap", b"rap-test".to_vec()))
            .await?;

        // New client subscribes with retain_as_published
        let sub_conn = ConnectParams::new("mqtt-test-rap-sub");
        let (mut sub_client, _) = client::connect(addr, &sub_conn, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                "mqtt/test/sub/rap".to_string(),
                SubscribeOptions {
                    qos:                  QoS::AtMostOnce,
                    retain_as_published:  true,
                    ..Default::default()
                },
            )],
            properties: Properties::default(),
        };
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        match sub_client.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rap" => {
                if p.retain {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        "Received PUBLISH but retain flag was cleared",
                    ))
                }
            }
            Ok(other) => {
                Ok(TestResult::fail_packet(&ctx, "PUBLISH on topic \"mqtt/test/sub/rap\"", &other))
            }
            Err(_) => {
                Ok(TestResult::fail(
                    &ctx,
                    "No retained message delivered to subscriber",
                ))
            }
        }
    })
    .await
}

const RETAIN_HANDLING_1: TestContext = TestContext {
    id: "MQTT-3.8.3-5a",
    description: "retain_handling=1: retained messages only on new subscription",
    compliance: Compliance::Must,
};

/// retain_handling=1: retained messages sent only on NEW subscription [MQTT-3.8.3-5].
async fn retain_handling_1(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = RETAIN_HANDLING_1;
    run_test(ctx, pb, async {
        // Publish a retained message
        let pub_conn = ConnectParams::new("mqtt-test-rh1-pub");
        let (mut pub_client, connack) =
            client::connect(addr, &pub_conn, recv_timeout).await?;

        if connack.properties.retain_available == Some(false) {
            return Ok(TestResult::skip(
                &ctx,
                "Broker reported Retain Available = false",
            ));
        }

        pub_client
            .send_publish(&PublishParams::retained("mqtt/test/sub/rh1", b"rh1-test".to_vec()))
            .await?;

        // Subscribe with retain_handling=1
        let sub_conn = ConnectParams::new("mqtt-test-rh1-sub");
        let (mut sub_client, _) = client::connect(addr, &sub_conn, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                "mqtt/test/sub/rh1".to_string(),
                SubscribeOptions {
                    qos:              QoS::AtMostOnce,
                    retain_handling:  1,
                    ..Default::default()
                },
            )],
            properties: Properties::default(),
        };
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        // Should receive retained message on first subscribe
        match sub_client.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rh1" => {}
            _ => {
                return Ok(TestResult::fail(
                    &ctx,
                    "No retained message on first subscription",
                ));
            }
        }

        // Subscribe again on same connection (not a new subscription)
        let sub2 = SubscribeParams {
            packet_id:  2,
            filters:    vec![(
                "mqtt/test/sub/rh1".to_string(),
                SubscribeOptions {
                    qos:              QoS::AtMostOnce,
                    retain_handling:  1,
                    ..Default::default()
                },
            )],
            properties: Properties::default(),
        };
        sub_client.send_subscribe(&sub2).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        // Should NOT receive retained message again — short timeout.
        match sub_client.recv(Duration::from_secs(1)).await {
            Err(_) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rh1" => {
                Ok(TestResult::fail(
                    &ctx,
                    "Retained message sent again on re-subscription",
                ))
            }
            Ok(other) => {
                Ok(TestResult::fail_packet(&ctx, "no packet on re-subscription", &other))
            }
        }
    })
    .await
}

const RETAIN_HANDLING_2: TestContext = TestContext {
    id: "MQTT-3.8.3-5b",
    description: "retain_handling=2: retained messages MUST NOT be sent on subscribe",
    compliance: Compliance::Must,
};

/// retain_handling=2: retained messages MUST NOT be sent on subscribe [MQTT-3.8.3-5].
async fn retain_handling_2(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = RETAIN_HANDLING_2;
    run_test(ctx, pb, async {
        // Publish a retained message
        let pub_conn = ConnectParams::new("mqtt-test-rh2-pub");
        let (mut pub_client, connack) =
            client::connect(addr, &pub_conn, recv_timeout).await?;

        if connack.properties.retain_available == Some(false) {
            return Ok(TestResult::skip(
                &ctx,
                "Broker reported Retain Available = false",
            ));
        }

        pub_client
            .send_publish(&PublishParams::retained("mqtt/test/sub/rh2", b"rh2-test".to_vec()))
            .await?;

        // Subscribe with retain_handling=2
        let sub_conn = ConnectParams::new("mqtt-test-rh2-sub");
        let (mut sub_client, _) = client::connect(addr, &sub_conn, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                "mqtt/test/sub/rh2".to_string(),
                SubscribeOptions {
                    qos:              QoS::AtMostOnce,
                    retain_handling:  2,
                    ..Default::default()
                },
            )],
            properties: Properties::default(),
        };
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        // Should NOT receive any retained message — short timeout.
        match sub_client.recv(Duration::from_secs(1)).await {
            Err(_) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rh2" => {
                Ok(TestResult::fail(
                    &ctx,
                    "Retained message delivered despite retain_handling=2",
                ))
            }
            Ok(other) => {
                Ok(TestResult::fail_packet(&ctx, "no packet (retain_handling=2)", &other))
            }
        }
    })
    .await
}

// ── Unsubscribe behaviour ──────────────────────────────────────────────────

const UNSUB_STOPS: TestContext = TestContext {
    id: "MQTT-3.10.4-6",
    description: "After UNSUBSCRIBE, server MUST stop delivering messages on that topic",
    compliance: Compliance::Must,
};

/// After receiving a valid UNSUBSCRIBE, the server MUST stop adding new
/// messages matching the removed filter [MQTT-3.10.4-6].
async fn unsubscribe_stops_delivery(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = UNSUB_STOPS;
    run_test(ctx, pb, async {
        let topic = "mqtt/test/sub/unsub_stops";
        let mut client = client::connect_and_subscribe(addr, "mqtt-test-unsub-stops", topic, QoS::AtMostOnce, recv_timeout).await?;

        // Verify subscription works
        client.send_publish(&PublishParams::qos0(topic, b"before".to_vec())).await?;
        match client.recv(recv_timeout).await? {
            Packet::Publish(p) if p.topic == topic => {}
            other => return Ok(TestResult::fail_packet(&ctx, "PUBLISH before unsubscribe", &other)),
        }

        // Unsubscribe
        let unsub = UnsubscribeParams::simple(2, topic);
        client.send_unsubscribe(&unsub).await?;
        match client.recv(recv_timeout).await? {
            Packet::UnsubAck(_) => {}
            other => return Ok(TestResult::fail_packet(&ctx, "UNSUBACK", &other)),
        }

        // Publish again — should NOT be delivered
        client.send_publish(&PublishParams::qos0(topic, b"after".to_vec())).await?;

        match client.recv(Duration::from_secs(1)).await {
            Err(_) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::Publish(p)) if p.topic == topic => {
                Ok(TestResult::fail(&ctx, "Message delivered after UNSUBSCRIBE"))
            }
            Ok(_) => Ok(TestResult::pass(&ctx)),
        }
    })
    .await
}

// ── Overlapping subscriptions ──────────────────────────────────────────────

const OVERLAP_QOS: TestContext = TestContext {
    id: "MQTT-3.3.4-2",
    description: "Overlapping subscriptions MUST deliver at maximum granted QoS",
    compliance: Compliance::Must,
};

/// When a client has overlapping subscriptions, the server MUST deliver
/// the message at the maximum QoS of all matching subscriptions [MQTT-3.3.4-2].
async fn overlapping_subscriptions_max_qos(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = OVERLAP_QOS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-overlap-qos");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        // Subscribe to wildcard at QoS 0
        let sub1 = SubscribeParams::simple(1, "mqtt/test/sub/overlap/#", QoS::AtMostOnce);
        client.send_subscribe(&sub1).await?;
        client.recv(recv_timeout).await?; // SUBACK

        // Subscribe to exact topic at QoS 1
        let sub2 = SubscribeParams::simple(2, "mqtt/test/sub/overlap/exact", QoS::AtLeastOnce);
        client.send_subscribe(&sub2).await?;
        client.recv(recv_timeout).await?; // SUBACK

        // Publish QoS 1 from another client
        let pub_conn = ConnectParams::new("mqtt-test-overlap-pub");
        let (mut pub_client, _) = client::connect(addr, &pub_conn, recv_timeout).await?;
        pub_client.send_publish(&PublishParams::qos1("mqtt/test/sub/overlap/exact", b"overlap".to_vec(), 1)).await?;

        // Drain publisher PUBACK
        for _ in 0..5 {
            if let Ok(Packet::PubAck(_)) = pub_client.recv(recv_timeout).await { break; }
        }

        // Subscriber should receive at QoS 1 (the higher of the two)
        match client.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/overlap/exact" => {
                if let Some(pid) = p.packet_id {
                    client.send_puback(pid, 0x00).await?;
                }
                if p.qos == QoS::AtLeastOnce {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(&ctx, format!("Delivered at {:?}, expected AtLeastOnce", p.qos)))
                }
            }
            Ok(other) => Ok(TestResult::fail_packet(&ctx, "PUBLISH on overlap/exact", &other)),
            Err(_) => Ok(TestResult::fail(&ctx, "No message delivered")),
        }
    })
    .await
}

// ── Subscription Identifier with overlapping subscriptions ─────────────────

const SUB_ID_OVERLAP: TestContext = TestContext {
    id: "MQTT-3.3.4-3",
    description: "Overlapping subscriptions with Subscription IDs MUST include all IDs",
    compliance: Compliance::Must,
};

/// When multiple subscriptions match a publish and each has a Subscription
/// Identifier, the delivered PUBLISH MUST include all matching IDs [MQTT-3.3.4-3].
async fn subscription_id_overlapping(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUB_ID_OVERLAP;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-subid-overlap");
        let (mut client, connack) = client::connect(addr, &params, recv_timeout).await?;

        if connack.properties.subscription_ids_available == Some(false) {
            return Ok(TestResult::skip(&ctx, "Broker reported Subscription Identifiers Available = false"));
        }

        // Subscribe with sub-id 10 on wildcard
        let sub1 = SubscribeParams {
            packet_id: 1,
            filters: vec![("mqtt/test/sub/sid_overlap/#".to_string(), SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() })],
            properties: Properties { subscription_identifier: Some(10), ..Properties::default() },
        };
        client.send_subscribe(&sub1).await?;
        client.recv(recv_timeout).await?; // SUBACK

        // Subscribe with sub-id 20 on exact
        let sub2 = SubscribeParams {
            packet_id: 2,
            filters: vec![("mqtt/test/sub/sid_overlap/exact".to_string(), SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() })],
            properties: Properties { subscription_identifier: Some(20), ..Properties::default() },
        };
        client.send_subscribe(&sub2).await?;
        client.recv(recv_timeout).await?; // SUBACK

        // Publish to the overlapping topic
        client.send_publish(&PublishParams::qos0("mqtt/test/sub/sid_overlap/exact", b"sid-test".to_vec())).await?;

        // The broker may deliver one message with both IDs, or two messages with one ID each.
        // Both approaches are valid per the spec.
        let mut ids_seen: Vec<u32> = Vec::new();
        for _ in 0..3 {
            match client.recv(Duration::from_secs(2)).await {
                Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/sid_overlap/exact" => {
                    if let Some(id) = p.properties.subscription_identifier {
                        ids_seen.push(id);
                    }
                }
                _ => break,
            }
        }

        ids_seen.sort();
        if ids_seen.contains(&10) && ids_seen.contains(&20) {
            Ok(TestResult::pass(&ctx))
        } else if ids_seen.is_empty() {
            Ok(TestResult::fail(&ctx, "No subscription identifiers in delivered PUBLISH"))
        } else {
            Ok(TestResult::fail(&ctx, format!("Expected subscription IDs [10, 20], got {ids_seen:?}")))
        }
    })
    .await
}

// ── Topic edge cases ────────────────────────────────────────────────────────

const MULTI_LEVEL_TOPIC: TestContext = TestContext {
    id: "MQTT-4.7.1-6",
    description: "Multi-level topic filter MUST match deep topic hierarchies",
    compliance: Compliance::Must,
};

/// A subscription to `a/b/#` MUST match `a/b/c/d/e` [MQTT-4.7.1-3].
async fn multi_level_topic(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = MULTI_LEVEL_TOPIC;
    run_test(ctx, pb, async {
        let mut sub = client::connect_and_subscribe(
            addr, "mqtt-test-multi-level-sub", "mqtt/test/deep/#", QoS::AtMostOnce, recv_timeout,
        ).await?;

        let params = ConnectParams::new("mqtt-test-multi-level-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

        let publish = PublishParams::qos0("mqtt/test/deep/a/b/c/d", b"deep".to_vec());
        pub_client.send_publish(&publish).await?;

        match sub.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/deep/a/b/c/d" => {
                Ok(TestResult::pass(&ctx))
            }
            Ok(other) => Ok(TestResult::fail_packet(&ctx, "PUBLISH matching a/b/#", &other)),
            Err(_) => Ok(TestResult::fail(&ctx, "No message received for deep topic hierarchy")),
        }
    })
    .await
}

const WILDCARD_MIDDLE: TestContext = TestContext {
    id: "MQTT-4.7.1-7",
    description: "'+' wildcard in middle position MUST match exactly one level",
    compliance: Compliance::Must,
};

/// A subscription to `a/+/c` MUST match `a/b/c` but NOT `a/b/d` or `a/b/c/d`.
async fn wildcard_middle_level(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = WILDCARD_MIDDLE;
    run_test(ctx, pb, async {
        let mut sub = client::connect_and_subscribe(
            addr, "mqtt-test-wc-mid-sub", "mqtt/test/wc/+/end", QoS::AtMostOnce, recv_timeout,
        ).await?;

        let params = ConnectParams::new("mqtt-test-wc-mid-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

        // Should match
        let p1 = PublishParams::qos0("mqtt/test/wc/any/end", b"match".to_vec());
        pub_client.send_publish(&p1).await?;

        // Should NOT match (extra level)
        let p2 = PublishParams::qos0("mqtt/test/wc/any/extra/end", b"no-match".to_vec());
        pub_client.send_publish(&p2).await?;

        match sub.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test/wc/any/end" => {
                // Verify no second message arrives (the non-matching one)
                match sub.recv(Duration::from_millis(500)).await {
                    Err(_) => Ok(TestResult::pass(&ctx)), // No extra message — correct
                    Ok(Packet::Publish(p2)) if p2.topic == "mqtt/test/wc/any/extra/end" => {
                        Ok(TestResult::fail(&ctx, "'+' wildcard matched across multiple levels"))
                    }
                    _ => Ok(TestResult::pass(&ctx)),
                }
            }
            Ok(other) => Ok(TestResult::fail_packet(&ctx, "PUBLISH matching a/+/c", &other)),
            Err(_) => Ok(TestResult::fail(&ctx, "No message received for wildcard match")),
        }
    })
    .await
}

const MULTI_FILTERS: TestContext = TestContext {
    id: "MQTT-3.8.4-5",
    description: "Multiple topic filters in single SUBSCRIBE MUST each get a reason code",
    compliance: Compliance::Must,
};

/// A SUBSCRIBE with multiple topic filters MUST return a SUBACK with
/// a reason code for each filter [MQTT-3.8.4-6].
async fn multiple_filters_single_subscribe(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = MULTI_FILTERS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-multi-filter");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id: 1,
            filters: vec![
                ("mqtt/test/mf/a".into(), SubscribeOptions::default()),
                ("mqtt/test/mf/b".into(), SubscribeOptions::default()),
                ("mqtt/test/mf/c".into(), SubscribeOptions::default()),
            ],
            properties: Properties::default(),
        };
        client.send_subscribe(&sub).await?;

        match client.recv(recv_timeout).await? {
            Packet::SubAck(ack) => {
                if ack.reason_codes.len() == 3 {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!("Expected 3 reason codes, got {}", ack.reason_codes.len()),
                    ))
                }
            }
            other => Ok(TestResult::fail_packet(&ctx, "SUBACK with 3 reason codes", &other)),
        }
    })
    .await
}

const SUB_UPGRADE_QOS: TestContext = TestContext {
    id: "MQTT-3.8.4-3",
    description: "Re-subscribing at higher QoS MUST upgrade the subscription",
    compliance: Compliance::Must,
};

/// Re-subscribing to the same topic with a higher QoS MUST upgrade the
/// subscription. Messages should then be delivered at the new QoS.
async fn subscription_upgrade_qos(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = SUB_UPGRADE_QOS;
    run_test(ctx, pb, async {
        let params = ConnectParams::new("mqtt-test-sub-upgrade");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        // Subscribe at QoS 0
        let sub0 = SubscribeParams::simple(1, "mqtt/test/upgrade", QoS::AtMostOnce);
        client.send_subscribe(&sub0).await?;
        client.recv(recv_timeout).await?; // SUBACK

        // Re-subscribe at QoS 1
        let sub1 = SubscribeParams::simple(2, "mqtt/test/upgrade", QoS::AtLeastOnce);
        client.send_subscribe(&sub1).await?;
        match client.recv(recv_timeout).await? {
            Packet::SubAck(ack) => {
                if ack.reason_codes.first().copied() == Some(0x01) {
                    // Granted QoS 1
                    Ok(TestResult::pass(&ctx))
                } else if ack.reason_codes.first().copied() == Some(0x00) {
                    // Granted QoS 0 — downgraded
                    Ok(TestResult::fail(
                        &ctx,
                        "Re-subscribe at QoS 1 returned QoS 0 — subscription not upgraded",
                    ))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!("Unexpected SUBACK reason code: {:?}", ack.reason_codes),
                    ))
                }
            }
            other => Ok(TestResult::fail_packet(&ctx, "SUBACK", &other)),
        }
    })
    .await
}

const EMPTY_TOPIC_LEVEL: TestContext = TestContext {
    id: "MQTT-4.7.3-1",
    description: "Empty topic level (e.g. a//b) is valid and MUST match exactly",
    compliance: Compliance::Must,
};

/// An empty topic level like `a//b` is valid per the spec. The broker MUST
/// deliver messages published to `a//b` to subscribers of `a//b`.
async fn empty_topic_level(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = EMPTY_TOPIC_LEVEL;
    run_test(ctx, pb, async {
        let mut sub = client::connect_and_subscribe(
            addr, "mqtt-test-empty-level-sub", "mqtt/test//empty", QoS::AtMostOnce, recv_timeout,
        ).await?;

        let params = ConnectParams::new("mqtt-test-empty-level-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

        let publish = PublishParams::qos0("mqtt/test//empty", b"empty-level".to_vec());
        pub_client.send_publish(&publish).await?;

        match sub.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == "mqtt/test//empty" => {
                Ok(TestResult::pass(&ctx))
            }
            Ok(other) => Ok(TestResult::fail_packet(&ctx, "PUBLISH on topic with empty level", &other)),
            Err(_) => Ok(TestResult::fail(&ctx, "No message received for topic with empty level")),
        }
    })
    .await
}
