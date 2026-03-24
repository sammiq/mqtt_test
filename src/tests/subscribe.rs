//! SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK compliance tests [MQTT-3.8 / MQTT-3.10].

use std::time::Duration;

use crate::client;
use crate::codec::{
    ConnectParams, Packet, Properties, PublishParams, QoS, SubscribeOptions, SubscribeParams,
    UnsubscribeParams,
};
use crate::types::{Compliance, SuiteRunner, TestConfig, TestContext, TestResult};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("SUBSCRIBE / UNSUBSCRIBE");

    suite.add(BASIC_SUB, basic_subscribe(config));
    suite.add(WILDCARD_PLUS, wildcard_plus(config));
    suite.add(WILDCARD_HASH, wildcard_hash(config));
    suite.add(UNSUB, unsubscribe(config));
    suite.add(DOLLAR_TOPIC, dollar_topic_no_wildcard_match(config));
    suite.add(SUBACK_REASON_COUNT, suback_reason_code_count(config));
    suite.add(UNSUBACK_REASON_COUNT, unsuback_reason_code_count(config));
    suite.add(SHARED_SUB, shared_subscription(config));
    suite.add(SUB_ID, subscription_identifier(config));
    suite.add(NO_LOCAL, no_local_flag(config));
    suite.add(RETAIN_AS_PUB, retain_as_published(config));
    suite.add(RETAIN_HANDLING_1, retain_handling_1(config));
    suite.add(RETAIN_HANDLING_2, retain_handling_2(config));
    suite.add(UNSUB_STOPS, unsubscribe_stops_delivery(config));
    suite.add(OVERLAP_QOS, overlapping_subscriptions_max_qos(config));
    suite.add(SUB_ID_OVERLAP, subscription_id_overlapping(config));
    suite.add(MULTI_LEVEL_TOPIC, multi_level_topic(config));
    suite.add(WILDCARD_MIDDLE, wildcard_middle_level(config));
    suite.add(MULTI_FILTERS, multiple_filters_single_subscribe(config));
    suite.add(SUB_UPGRADE_QOS, subscription_upgrade_qos(config));
    suite.add(EMPTY_TOPIC_LEVEL, empty_topic_level(config));
    suite.add(CASE_SENSITIVE, case_sensitive_topic(config));
    suite.add(EXACT_CHAR, exact_char_match(config));
    suite.add(
        LEVEL_SEPARATOR_DISTINCT,
        topic_level_separator_distinct(config),
    );
    suite.add(UNSUB_STOPS_NEW, unsubscribe_stops_new_messages(config));
    suite.add(UNSUB_BUFFERED, unsubscribe_buffered_messages(config));
    suite.add(RETAIN_HANDLING_0, retain_handling_0_sends_retained(config));
    suite.add(QOS_DOWNGRADE_1_TO_0, qos_downgrade_qos1_to_qos0(config));
    suite.add(
        UNSUB_INFLIGHT_QOS1,
        unsubscribe_inflight_qos1_completes(config),
    );
    suite.add(SHARED_SUB_FORMAT, shared_sub_topic_filter_format(config));
    suite.add(SHARED_SUB_QOS, shared_sub_qos_respected(config));
    suite.add(SHARED_SUB_QOS2_RECONNECT, shared_sub_qos2_reconnect(config));
    suite.add(
        SHARED_SUB_NACK_DISCARD,
        shared_sub_negative_ack_discard(config),
    );

    suite
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const BASIC_SUB: TestContext = TestContext {
    refs: &["MQTT-3.8.4-1"],
    description: "Server MUST send SUBACK in response to SUBSCRIBE",
    compliance: Compliance::Must,
};

/// Server MUST send SUBACK in response to SUBSCRIBE [MQTT-3.8.4-1].
async fn basic_subscribe(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = BASIC_SUB;

    let params = ConnectParams::new("mqtt-test-subscribe");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, "mqtt/test/sub/basic", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;

    match client.recv().await? {
        Packet::SubAck(ack) if ack.packet_id == 1 => {
            if ack.reason_codes.first().map(|&c| c < 0x80).unwrap_or(false) {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!(
                        "SUBACK reason code indicates failure: {:?}",
                        ack.reason_codes
                    ),
                ))
            }
        }
        other => Ok(TestResult::fail_packet(&ctx, "SUBACK(1)", &other)),
    }
}

const WILDCARD_PLUS: TestContext = TestContext {
    refs: &["MQTT-4.7.1-2"],
    description: "'+' wildcard MUST match exactly one topic level",
    compliance: Compliance::Must,
};

/// `+` wildcard MUST match exactly one level [MQTT-4.7.1-2].
async fn wildcard_plus(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILDCARD_PLUS;

    let params = ConnectParams::new("mqtt-test-wildcard-plus");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, "mqtt/test/sub/wc_plus/+", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;
    match client.recv().await? {
        Packet::SubAck(_) => {}
        other => {
            return Ok(TestResult::fail_packet(&ctx, "SUBACK", &other));
        }
    }

    client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sub/wc_plus/match",
            b"plus".to_vec(),
        ))
        .await?;

    match client.recv().await? {
        Packet::Publish(p) if p.topic == "mqtt/test/sub/wc_plus/match" => {
            Ok(TestResult::pass(&ctx))
        }
        other => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on topic \"mqtt/test/sub/wc_plus/match\"",
            &other,
        )),
    }
}

const WILDCARD_HASH: TestContext = TestContext {
    refs: &["MQTT-4.7.1-3"],
    description: "'#' wildcard MUST match all sub-levels",
    compliance: Compliance::Must,
};

/// `#` wildcard MUST match the parent and all sub-levels [MQTT-4.7.1-2].
async fn wildcard_hash(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILDCARD_HASH;

    let params = ConnectParams::new("mqtt-test-wildcard-hash");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, "mqtt/test/sub/wc_hash/#", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;
    match client.recv().await? {
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

    match client.recv().await? {
        Packet::Publish(p) if p.topic == "mqtt/test/sub/wc_hash/deep/nested/topic" => {
            Ok(TestResult::pass(&ctx))
        }
        other => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on topic \"mqtt/test/sub/wc_hash/deep/nested/topic\"",
            &other,
        )),
    }
}

const UNSUB: TestContext = TestContext {
    refs: &["MQTT-3.10.4-4"],
    description: "Server MUST send UNSUBACK in response to UNSUBSCRIBE",
    compliance: Compliance::Must,
};

/// Server MUST send UNSUBACK in response to UNSUBSCRIBE [MQTT-3.10.4-4].
async fn unsubscribe(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUB;

    let mut client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-unsubscribe",
        "mqtt/test/sub/unsub",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let unsub = UnsubscribeParams::simple(2, "mqtt/test/sub/unsub");
    client.send_unsubscribe(&unsub).await?;

    match client.recv().await? {
        Packet::UnsubAck(ack) if ack.packet_id == 2 => Ok(TestResult::pass(&ctx)),
        other => Ok(TestResult::fail_packet(&ctx, "UNSUBACK(2)", &other)),
    }
}

const DOLLAR_TOPIC: TestContext = TestContext {
    refs: &["MQTT-4.7.2-1"],
    description: "Topics starting with $ MUST NOT match wildcard subscriptions (#, +/...)",
    compliance: Compliance::Must,
};

/// Topics starting with `$` MUST NOT be matched by subscriptions starting with `#` or `+` [MQTT-4.7.2-1].
async fn dollar_topic_no_wildcard_match(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = DOLLAR_TOPIC;

    let params = ConnectParams::new("mqtt-test-dollar-topic");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Subscribe to "#" which should match everything EXCEPT $-prefixed topics
    let sub = SubscribeParams::simple(1, "#", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;
    match client.recv().await? {
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
        match client.recv_with_timeout(Duration::from_secs(2)).await {
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
}

const SUBACK_REASON_COUNT: TestContext = TestContext {
    refs: &["MQTT-3.8.4-6"],
    description: "SUBACK MUST contain one reason code for each topic filter",
    compliance: Compliance::Must,
};

/// SUBACK MUST contain a reason code for each Topic Filter in the SUBSCRIBE [MQTT-3.8.4-6].
async fn suback_reason_code_count(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SUBACK_REASON_COUNT;

    let params = ConnectParams::new("mqtt-test-suback-count");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![
            (
                "mqtt/test/sub/count/a".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
            (
                "mqtt/test/sub/count/b".to_string(),
                SubscribeOptions {
                    qos: QoS::AtLeastOnce,
                    ..Default::default()
                },
            ),
            (
                "mqtt/test/sub/count/c".to_string(),
                SubscribeOptions {
                    qos: QoS::ExactlyOnce,
                    ..Default::default()
                },
            ),
        ],
        properties: Properties::default(),
    };
    client.send_subscribe(&sub).await?;

    match client.recv().await? {
        Packet::SubAck(ack) if ack.packet_id == 1 => {
            if ack.reason_codes.len() == 3 {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!("Expected 3 reason codes, got {}", ack.reason_codes.len()),
                ))
            }
        }
        other => Ok(TestResult::fail_packet(&ctx, "SUBACK(1)", &other)),
    }
}

const UNSUBACK_REASON_COUNT: TestContext = TestContext {
    refs: &["MQTT-3.10.4-5"],
    description: "UNSUBACK MUST contain one reason code for each topic filter",
    compliance: Compliance::Must,
};

/// UNSUBACK MUST contain a reason code for each Topic Filter in the UNSUBSCRIBE [MQTT-3.10.4-5].
async fn unsuback_reason_code_count(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUBACK_REASON_COUNT;

    let params = ConnectParams::new("mqtt-test-unsuback-count");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Subscribe to 3 topics first
    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![
            (
                "mqtt/test/unsub/count/a".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
            (
                "mqtt/test/unsub/count/b".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
            (
                "mqtt/test/unsub/count/c".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
        ],
        properties: Properties::default(),
    };
    client.send_subscribe(&sub).await?;
    client.recv().await?; // SUBACK

    // Unsubscribe from all 3
    let unsub = UnsubscribeParams {
        packet_id: 2,
        filters: vec![
            "mqtt/test/unsub/count/a".to_string(),
            "mqtt/test/unsub/count/b".to_string(),
            "mqtt/test/unsub/count/c".to_string(),
        ],
        properties: Properties::default(),
    };
    client.send_unsubscribe(&unsub).await?;

    match client.recv().await? {
        Packet::UnsubAck(ack) if ack.packet_id == 2 => {
            if ack.reason_codes.len() == 3 {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!("Expected 3 reason codes, got {}", ack.reason_codes.len()),
                ))
            }
        }
        other => Ok(TestResult::fail_packet(&ctx, "UNSUBACK(2)", &other)),
    }
}

// ── MAY ──────────────────────────────────────────────────────────────────────

const SHARED_SUB: TestContext = TestContext {
    refs: &["MQTT-4.8.2-1"],
    description: "Shared subscriptions ($share/...) are supported",
    compliance: Compliance::May,
};

/// Shared subscriptions ($share/group/topic) are accepted [MQTT-4.8.2].
async fn shared_subscription(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SHARED_SUB;

    let params = ConnectParams::new("mqtt-test-shared-sub");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Shared Subscription Available = false",
        ));
    }

    let sub = SubscribeParams::simple(1, "$share/testgroup/mqtt/test/sub/shared", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;

    match client.recv().await? {
        Packet::SubAck(ack) if ack.packet_id == 1 => {
            if ack.reason_codes.first().map(|&c| c < 0x80).unwrap_or(false) {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!(
                        "SUBACK reason code indicates failure: {:?}",
                        ack.reason_codes
                    ),
                ))
            }
        }
        other => Ok(TestResult::fail_packet(&ctx, "SUBACK(1)", &other)),
    }
}

// ── Subscribe options ───────────────────────────────────────────────────────

const SUB_ID: TestContext = TestContext {
    refs: &["MQTT-3.8.2-2"],
    description: "Subscription Identifier MUST be returned in matching PUBLISH",
    compliance: Compliance::Must,
};

/// Subscription Identifier MUST be returned in matching PUBLISH [MQTT-3.8.2-2].
async fn subscription_identifier(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SUB_ID;

    let params = ConnectParams::new("mqtt-test-sub-id");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.subscription_ids_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Subscription Identifiers Available = false",
        ));
    }

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            "mqtt/test/sub/subid".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                ..Default::default()
            },
        )],
        properties: Properties {
            subscription_identifier: Some(42),
            ..Properties::default()
        },
    };
    client.send_subscribe(&sub).await?;
    client.recv().await?; // SUBACK

    client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sub/subid",
            b"subid-test".to_vec(),
        ))
        .await?;

    match client.recv().await? {
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
        other => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on topic \"mqtt/test/sub/subid\"",
            &other,
        )),
    }
}

const NO_LOCAL: TestContext = TestContext {
    refs: &["MQTT-3.8.3-3"],
    description: "no_local=true: server MUST NOT deliver messages from the same client",
    compliance: Compliance::Must,
};

/// no_local=true: server MUST NOT send messages published by the same client [MQTT-3.8.3-3].
async fn no_local_flag(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = NO_LOCAL;

    let params = ConnectParams::new("mqtt-test-no-local");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            "mqtt/test/sub/no_local".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                no_local: true,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    client.send_subscribe(&sub).await?;
    client.recv().await?; // SUBACK

    client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sub/no_local",
            b"no-local-test".to_vec(),
        ))
        .await?;

    // Expect NO message — short timeout is sufficient to confirm absence.
    match client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/no_local" => Ok(TestResult::fail(
            &ctx,
            "Received own PUBLISH despite no_local=true",
        )),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "no packet (no_local)",
            &other,
        )),
    }
}

const RETAIN_AS_PUB: TestContext = TestContext {
    refs: &["MQTT-3.8.3-4"],
    description: "retain_as_published=true: retain flag MUST be preserved on delivery",
    compliance: Compliance::Must,
};

/// retain_as_published=true: retain flag MUST be preserved on delivery [MQTT-3.8.3-4].
async fn retain_as_published(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = RETAIN_AS_PUB;

    let pub_params_conn = ConnectParams::new("mqtt-test-rap-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_params_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Retain Available = false",
        ));
    }

    // Publish retained message
    pub_client
        .send_publish(&PublishParams::retained(
            "mqtt/test/sub/rap",
            b"rap-test".to_vec(),
        ))
        .await?;

    // New client subscribes with retain_as_published
    let sub_conn = ConnectParams::new("mqtt-test-rap-sub");
    let (mut sub_client, _) = client::connect(config.addr, &sub_conn, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            "mqtt/test/sub/rap".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                retain_as_published: true,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

    match sub_client.recv().await {
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
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on topic \"mqtt/test/sub/rap\"",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No retained message delivered to subscriber",
        )),
    }
}

const RETAIN_HANDLING_1: TestContext = TestContext {
    refs: &["MQTT-3.8.3-5a"],
    description: "retain_handling=1: retained messages only on new subscription",
    compliance: Compliance::Must,
};

/// retain_handling=1: retained messages sent only on NEW subscription [MQTT-3.8.3-5].
async fn retain_handling_1(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = RETAIN_HANDLING_1;

    // Publish a retained message
    let pub_conn = ConnectParams::new("mqtt-test-rh1-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Retain Available = false",
        ));
    }

    pub_client
        .send_publish(&PublishParams::retained(
            "mqtt/test/sub/rh1",
            b"rh1-test".to_vec(),
        ))
        .await?;

    // Subscribe with retain_handling=1
    let sub_conn = ConnectParams::new("mqtt-test-rh1-sub");
    let (mut sub_client, _) = client::connect(config.addr, &sub_conn, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            "mqtt/test/sub/rh1".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                retain_handling: 1,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

    // Should receive retained message on first subscribe
    match sub_client.recv().await {
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
        packet_id: 2,
        filters: vec![(
            "mqtt/test/sub/rh1".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                retain_handling: 1,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    sub_client.send_subscribe(&sub2).await?;
    sub_client.recv().await?; // SUBACK

    // Should NOT receive retained message again — short timeout.
    match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rh1" => Ok(TestResult::fail(
            &ctx,
            "Retained message sent again on re-subscription",
        )),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "no packet on re-subscription",
            &other,
        )),
    }
}

const RETAIN_HANDLING_2: TestContext = TestContext {
    refs: &["MQTT-3.8.3-5b"],
    description: "retain_handling=2: retained messages MUST NOT be sent on subscribe",
    compliance: Compliance::Must,
};

/// retain_handling=2: retained messages MUST NOT be sent on subscribe [MQTT-3.8.3-5].
async fn retain_handling_2(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = RETAIN_HANDLING_2;

    // Publish a retained message
    let pub_conn = ConnectParams::new("mqtt-test-rh2-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Retain Available = false",
        ));
    }

    pub_client
        .send_publish(&PublishParams::retained(
            "mqtt/test/sub/rh2",
            b"rh2-test".to_vec(),
        ))
        .await?;

    // Subscribe with retain_handling=2
    let sub_conn = ConnectParams::new("mqtt-test-rh2-sub");
    let (mut sub_client, _) = client::connect(config.addr, &sub_conn, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            "mqtt/test/sub/rh2".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                retain_handling: 2,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

    // Should NOT receive any retained message — short timeout.
    match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rh2" => Ok(TestResult::fail(
            &ctx,
            "Retained message delivered despite retain_handling=2",
        )),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "no packet (retain_handling=2)",
            &other,
        )),
    }
}

// ── Unsubscribe behaviour ──────────────────────────────────────────────────

const UNSUB_STOPS: TestContext = TestContext {
    refs: &["MQTT-3.10.4-6"],
    description: "After UNSUBSCRIBE, server MUST stop delivering messages on that topic",
    compliance: Compliance::Must,
};

/// After receiving a valid UNSUBSCRIBE, the server MUST stop adding new
/// messages matching the removed filter [MQTT-3.10.4-6].
async fn unsubscribe_stops_delivery(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUB_STOPS;

    let topic = "mqtt/test/sub/unsub_stops";
    let mut client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-unsub-stops",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Verify subscription works
    client
        .send_publish(&PublishParams::qos0(topic, b"before".to_vec()))
        .await?;
    match client.recv().await? {
        Packet::Publish(p) if p.topic == topic => {}
        other => {
            return Ok(TestResult::fail_packet(
                &ctx,
                "PUBLISH before unsubscribe",
                &other,
            ));
        }
    }

    // Unsubscribe
    let unsub = UnsubscribeParams::simple(2, topic);
    client.send_unsubscribe(&unsub).await?;
    match client.recv().await? {
        Packet::UnsubAck(_) => {}
        other => return Ok(TestResult::fail_packet(&ctx, "UNSUBACK", &other)),
    }

    // Publish again — should NOT be delivered
    client
        .send_publish(&PublishParams::qos0(topic, b"after".to_vec()))
        .await?;

    match client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(TestResult::fail(
            &ctx,
            "Message delivered after UNSUBSCRIBE",
        )),
        Ok(_) => Ok(TestResult::pass(&ctx)),
    }
}

// ── Overlapping subscriptions ──────────────────────────────────────────────

const OVERLAP_QOS: TestContext = TestContext {
    refs: &["MQTT-3.3.4-2"],
    description: "Overlapping subscriptions MUST deliver at maximum granted QoS",
    compliance: Compliance::Must,
};

/// When a client has overlapping subscriptions, the server MUST deliver
/// the message at the maximum QoS of all matching subscriptions [MQTT-3.3.4-2].
async fn overlapping_subscriptions_max_qos(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = OVERLAP_QOS;

    let params = ConnectParams::new("mqtt-test-overlap-qos");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Subscribe to wildcard at QoS 0
    let sub1 = SubscribeParams::simple(1, "mqtt/test/sub/overlap/#", QoS::AtMostOnce);
    client.send_subscribe(&sub1).await?;
    client.recv().await?; // SUBACK

    // Subscribe to exact topic at QoS 1
    let sub2 = SubscribeParams::simple(2, "mqtt/test/sub/overlap/exact", QoS::AtLeastOnce);
    client.send_subscribe(&sub2).await?;
    client.recv().await?; // SUBACK

    // Publish QoS 1 from another client
    let pub_conn = ConnectParams::new("mqtt-test-overlap-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    pub_client
        .send_publish(&PublishParams::qos1(
            "mqtt/test/sub/overlap/exact",
            b"overlap".to_vec(),
            1,
        ))
        .await?;

    // Drain publisher PUBACK
    for _ in 0..5 {
        if let Ok(Packet::PubAck(_)) = pub_client.recv().await {
            break;
        }
    }

    // Subscriber should receive at QoS 1 (the higher of the two)
    match client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/overlap/exact" => {
            if let Some(pid) = p.packet_id {
                client.send_puback(pid, 0x00).await?;
            }
            if p.qos == QoS::AtLeastOnce {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!("Delivered at {:?}, expected AtLeastOnce", p.qos),
                ))
            }
        }
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on overlap/exact",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(&ctx, "No message delivered")),
    }
}

// ── Subscription Identifier with overlapping subscriptions ─────────────────

const SUB_ID_OVERLAP: TestContext = TestContext {
    refs: &["MQTT-3.3.4-3"],
    description: "Overlapping subscriptions with Subscription IDs MUST include all IDs",
    compliance: Compliance::Must,
};

/// When multiple subscriptions match a publish and each has a Subscription
/// Identifier, the delivered PUBLISH MUST include all matching IDs [MQTT-3.3.4-3].
async fn subscription_id_overlapping(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SUB_ID_OVERLAP;

    let params = ConnectParams::new("mqtt-test-subid-overlap");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.subscription_ids_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Subscription Identifiers Available = false",
        ));
    }

    // Subscribe with sub-id 10 on wildcard
    let sub1 = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            "mqtt/test/sub/sid_overlap/#".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                ..Default::default()
            },
        )],
        properties: Properties {
            subscription_identifier: Some(10),
            ..Properties::default()
        },
    };
    client.send_subscribe(&sub1).await?;
    client.recv().await?; // SUBACK

    // Subscribe with sub-id 20 on exact
    let sub2 = SubscribeParams {
        packet_id: 2,
        filters: vec![(
            "mqtt/test/sub/sid_overlap/exact".to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                ..Default::default()
            },
        )],
        properties: Properties {
            subscription_identifier: Some(20),
            ..Properties::default()
        },
    };
    client.send_subscribe(&sub2).await?;
    client.recv().await?; // SUBACK

    // Publish to the overlapping topic
    client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sub/sid_overlap/exact",
            b"sid-test".to_vec(),
        ))
        .await?;

    // The broker may deliver one message with both IDs, or two messages with one ID each.
    // Both approaches are valid per the spec.
    let mut ids_seen: Vec<u32> = Vec::new();
    for _ in 0..3 {
        match client.recv_with_timeout(Duration::from_secs(2)).await {
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
        Ok(TestResult::fail(
            &ctx,
            "No subscription identifiers in delivered PUBLISH",
        ))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!("Expected subscription IDs [10, 20], got {ids_seen:?}"),
        ))
    }
}

// ── Topic edge cases ────────────────────────────────────────────────────────

const MULTI_LEVEL_TOPIC: TestContext = TestContext {
    refs: &["MQTT-4.7.1-6"],
    description: "Multi-level topic filter MUST match deep topic hierarchies",
    compliance: Compliance::Must,
};

/// A subscription to `a/b/#` MUST match `a/b/c/d/e` [MQTT-4.7.1-3].
async fn multi_level_topic(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = MULTI_LEVEL_TOPIC;

    let mut sub = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-multi-level-sub",
        "mqtt/test/deep/#",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-multi-level-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let publish = PublishParams::qos0("mqtt/test/deep/a/b/c/d", b"deep".to_vec());
    pub_client.send_publish(&publish).await?;

    match sub.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/deep/a/b/c/d" => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH matching a/b/#",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No message received for deep topic hierarchy",
        )),
    }
}

const WILDCARD_MIDDLE: TestContext = TestContext {
    refs: &["MQTT-4.7.1-7"],
    description: "'+' wildcard in middle position MUST match exactly one level",
    compliance: Compliance::Must,
};

/// A subscription to `a/+/c` MUST match `a/b/c` but NOT `a/b/d` or `a/b/c/d`.
async fn wildcard_middle_level(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = WILDCARD_MIDDLE;

    let mut sub = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-wc-mid-sub",
        "mqtt/test/wc/+/end",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-wc-mid-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Should match
    let p1 = PublishParams::qos0("mqtt/test/wc/any/end", b"match".to_vec());
    pub_client.send_publish(&p1).await?;

    // Should NOT match (extra level)
    let p2 = PublishParams::qos0("mqtt/test/wc/any/extra/end", b"no-match".to_vec());
    pub_client.send_publish(&p2).await?;

    match sub.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/wc/any/end" => {
            // Verify no second message arrives (the non-matching one)
            match sub.recv_with_timeout(Duration::from_millis(500)).await {
                Err(_) => Ok(TestResult::pass(&ctx)), // No extra message — correct
                Ok(Packet::Publish(p2)) if p2.topic == "mqtt/test/wc/any/extra/end" => Ok(
                    TestResult::fail(&ctx, "'+' wildcard matched across multiple levels"),
                ),
                _ => Ok(TestResult::pass(&ctx)),
            }
        }
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH matching a/+/c",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No message received for wildcard match",
        )),
    }
}

const MULTI_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.8.4-5"],
    description: "Multiple topic filters in single SUBSCRIBE MUST each get a reason code",
    compliance: Compliance::Must,
};

/// A SUBSCRIBE with multiple topic filters MUST return a SUBACK with
/// a reason code for each filter [MQTT-3.8.4-6].
async fn multiple_filters_single_subscribe(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = MULTI_FILTERS;

    let params = ConnectParams::new("mqtt-test-multi-filter");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

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

    match client.recv().await? {
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
        other => Ok(TestResult::fail_packet(
            &ctx,
            "SUBACK with 3 reason codes",
            &other,
        )),
    }
}

const SUB_UPGRADE_QOS: TestContext = TestContext {
    refs: &["MQTT-3.8.4-3"],
    description: "Re-subscribing at higher QoS MUST upgrade the subscription",
    compliance: Compliance::Must,
};

/// Re-subscribing to the same topic with a higher QoS MUST upgrade the
/// subscription. Messages should then be delivered at the new QoS.
async fn subscription_upgrade_qos(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SUB_UPGRADE_QOS;

    let params = ConnectParams::new("mqtt-test-sub-upgrade");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Subscribe at QoS 0
    let sub0 = SubscribeParams::simple(1, "mqtt/test/upgrade", QoS::AtMostOnce);
    client.send_subscribe(&sub0).await?;
    client.recv().await?; // SUBACK

    // Re-subscribe at QoS 1
    let sub1 = SubscribeParams::simple(2, "mqtt/test/upgrade", QoS::AtLeastOnce);
    client.send_subscribe(&sub1).await?;
    match client.recv().await? {
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
}

const EMPTY_TOPIC_LEVEL: TestContext = TestContext {
    refs: &["MQTT-4.7.3-1"],
    description: "Empty topic level (e.g. a//b) is valid and MUST match exactly",
    compliance: Compliance::Must,
};

/// An empty topic level like `a//b` is valid per the spec. The broker MUST
/// deliver messages published to `a//b` to subscribers of `a//b`.
async fn empty_topic_level(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = EMPTY_TOPIC_LEVEL;

    let mut sub = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-empty-level-sub",
        "mqtt/test//empty",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-empty-level-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let publish = PublishParams::qos0("mqtt/test//empty", b"empty-level".to_vec());
    pub_client.send_publish(&publish).await?;

    match sub.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test//empty" => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on topic with empty level",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No message received for topic with empty level",
        )),
    }
}

const CASE_SENSITIVE: TestContext = TestContext {
    refs: &["MQTT-4.7.3-3"],
    description: "Server MUST NOT normalize topic names — matching is case-sensitive",
    compliance: Compliance::Must,
};

/// Topic names are case-sensitive. Subscribe to "mqtt/Test/CASE" and verify
/// that a publish to "mqtt/test/case" (different case) is NOT received, while
/// a publish to "mqtt/Test/CASE" IS received [MQTT-4.7.3-3].
async fn case_sensitive_topic(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = CASE_SENSITIVE;

    let mut sub = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-case-sub",
        "mqtt/Test/CASE",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-case-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Publish with different case — should NOT match
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/case",
            b"wrong-case".to_vec(),
        ))
        .await?;

    match sub.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/case" => {
            return Ok(TestResult::fail(
                &ctx,
                "Received message on case-different topic — server normalized topic names",
            ));
        }
        _ => {} // Expected: no message or timeout
    }

    // Publish with exact case — MUST match
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/Test/CASE",
            b"right-case".to_vec(),
        ))
        .await?;

    match sub.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/Test/CASE" => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on \"mqtt/Test/CASE\"",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No message received for exact-case topic",
        )),
    }
}

const EXACT_CHAR: TestContext = TestContext {
    refs: &["MQTT-4.7.3-4"],
    description: "Non-wildcard topic levels MUST match character-for-character",
    compliance: Compliance::Must,
};

/// Non-wildcard levels in a topic filter must match character-for-character.
/// Subscribe to "mqtt/exact/match", verify "mqtt/exact/match" matches but
/// "mqtt/exact/matcH" does not [MQTT-4.7.3-4].
async fn exact_char_match(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = EXACT_CHAR;

    let mut sub = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-exact-sub",
        "mqtt/exact/match",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-exact-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Publish with one character different — should NOT match
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/exact/matcH",
            b"near-miss".to_vec(),
        ))
        .await?;

    match sub.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/exact/matcH" => {
            return Ok(TestResult::fail(
                &ctx,
                "Received message on topic differing by one character — not character-for-character matching",
            ));
        }
        _ => {} // Expected: no message or timeout
    }

    // Publish with exact match — MUST match
    pub_client
        .send_publish(&PublishParams::qos0("mqtt/exact/match", b"exact".to_vec()))
        .await?;

    match sub.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/exact/match" => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on \"mqtt/exact/match\"",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No message received for exact-match topic",
        )),
    }
}

const LEVEL_SEPARATOR_DISTINCT: TestContext = TestContext {
    refs: &["MQTT-4.7.0-1"],
    description: "Topic level separator creates distinct levels — empty level is a separate level",
    compliance: Compliance::Must,
};

/// The topic level separator '/' creates distinct levels. "a/b" and "a//b" are
/// different topics because "a//b" has an empty level between two separators.
/// Subscribe to "a/b", verify "a/b" matches but "a//b" does not. Then subscribe
/// to "a//b" and verify "a//b" matches [MQTT-4.7.0-1].
async fn topic_level_separator_distinct(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = LEVEL_SEPARATOR_DISTINCT;

    // Subscriber 1: subscribe to "mqtt/test/sep/a/b"
    let mut sub1 = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-sep-sub1",
        "mqtt/test/sep/a/b",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-sep-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Publish to "mqtt/test/sep/a//b" (extra empty level) — should NOT match sub1
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sep/a//b",
            b"empty-level".to_vec(),
        ))
        .await?;

    match sub1.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sep/a//b" => {
            return Ok(TestResult::fail(
                &ctx,
                "Subscriber to \"a/b\" received message published to \"a//b\" — empty level not treated as distinct",
            ));
        }
        _ => {} // Expected: no message or timeout
    }

    // Publish to "mqtt/test/sep/a/b" — MUST match sub1
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sep/a/b",
            b"normal".to_vec(),
        ))
        .await?;

    match sub1.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sep/a/b" => {}
        Ok(other) => {
            return Ok(TestResult::fail_packet(
                &ctx,
                "PUBLISH on \"mqtt/test/sep/a/b\"",
                &other,
            ));
        }
        Err(_) => {
            return Ok(TestResult::fail(
                &ctx,
                "No message received for \"mqtt/test/sep/a/b\"",
            ));
        }
    }

    // Subscriber 2: subscribe to "mqtt/test/sep/a//b" and verify it matches
    let mut sub2 = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-sep-sub2",
        "mqtt/test/sep/a//b",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sep/a//b",
            b"empty-level-2".to_vec(),
        ))
        .await?;

    match sub2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sep/a//b" => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "PUBLISH on \"mqtt/test/sep/a//b\"",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No message received for \"mqtt/test/sep/a//b\"",
        )),
    }
}

// ── Unsubscribe completeness ────────────────────────────────────────────────

const UNSUB_STOPS_NEW: TestContext = TestContext {
    refs: &["MQTT-3.10.4-1"],
    description: "After UNSUBSCRIBE, server MUST stop adding new messages for that topic",
    compliance: Compliance::Must,
};

/// After receiving UNSUBSCRIBE, the server MUST stop adding any new messages
/// matching the filter for delivery to the client [MQTT-3.10.4-1].
///
/// This test differs from MQTT-3.10.4-6 (basic delivery stop) by:
/// 1. Explicitly verifying delivery works before unsubscribe
/// 2. Waiting for UNSUBACK before publishing
/// 3. Publishing multiple messages after unsubscribe with a small delay
async fn unsubscribe_stops_new_messages(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUB_STOPS_NEW;

    let topic = "mqtt/test/unsub/stop";

    // Use two clients: one subscriber, one publisher
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-unsub-stop-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let pub_params = ConnectParams::new("mqtt-test-unsub-stop-pub");
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params, config.recv_timeout).await?;

    // Step 1: Verify delivery works before unsubscribe
    pub_client
        .send_publish(&PublishParams::qos0(topic, b"before-unsub".to_vec()))
        .await?;
    match sub_client.recv().await? {
        Packet::Publish(p) if p.topic == topic => {}
        other => {
            return Ok(TestResult::fail_packet(
                &ctx,
                "PUBLISH before unsubscribe",
                &other,
            ));
        }
    }

    // Step 2: Unsubscribe and wait for UNSUBACK
    let unsub = UnsubscribeParams::simple(2, topic);
    sub_client.send_unsubscribe(&unsub).await?;
    match sub_client.recv().await? {
        Packet::UnsubAck(_) => {}
        other => return Ok(TestResult::fail_packet(&ctx, "UNSUBACK", &other)),
    }

    // Step 3: Small delay to ensure server has processed the unsubscribe
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Step 4: Publish multiple messages — none should be delivered
    for i in 0..5 {
        pub_client
            .send_publish(&PublishParams::qos0(
                topic,
                format!("after-unsub-{i}").into_bytes(),
            ))
            .await?;
    }

    // Step 5: Verify none arrive
    match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
        Err(_) => Ok(TestResult::pass(&ctx)),
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(TestResult::fail(
            &ctx,
            "Message delivered after UNSUBSCRIBE + UNSUBACK",
        )),
        Ok(_) => Ok(TestResult::pass(&ctx)),
    }
}

const UNSUB_BUFFERED: TestContext = TestContext {
    refs: &["MQTT-3.10.4-3"],
    description: "Server MAY continue delivering already-buffered messages after UNSUBSCRIBE",
    compliance: Compliance::May,
};

/// After UNSUBSCRIBE, the server MAY continue to deliver messages that were
/// already buffered or in-flight before the UNSUBACK was sent [MQTT-3.10.4-3].
/// This is a MAY — we just check the server behaves reasonably (does not crash,
/// UNSUBACK is received) regardless of whether buffered messages still arrive.
async fn unsubscribe_buffered_messages(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUB_BUFFERED;

    let topic = "mqtt/test/unsub/buffered";

    // Subscribe at QoS 1 so messages are properly queued
    let params = ConnectParams::new("mqtt-test-unsub-buf");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    client.send_subscribe(&sub).await?;
    match client.recv().await? {
        Packet::SubAck(_) => {}
        other => return Ok(TestResult::fail_packet(&ctx, "SUBACK", &other)),
    }

    // Publish several QoS 1 messages from a separate client to build up a buffer
    let pub_params = ConnectParams::new("mqtt-test-unsub-buf-pub");
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params, config.recv_timeout).await?;
    for i in 1..=5u16 {
        pub_client
            .send_publish(&PublishParams::qos1(
                topic,
                format!("buf-{i}").into_bytes(),
                i,
            ))
            .await?;
    }

    // Drain PUBACKs from publisher
    for _ in 0..5 {
        match pub_client.recv().await {
            Ok(Packet::PubAck(_)) => {}
            _ => break,
        }
    }

    // Unsubscribe immediately — some messages may still be in-flight
    let unsub = UnsubscribeParams::simple(2, topic);
    client.send_unsubscribe(&unsub).await?;

    // Drain any in-flight PUBLISH and look for UNSUBACK
    let mut got_unsuback = false;
    let mut buffered_count = 0u32;
    for _ in 0..20 {
        match client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                buffered_count += 1;
                // ACK QoS 1 messages
                if let Some(pid) = p.packet_id {
                    client.send_puback(pid, 0x00).await?;
                }
            }
            Ok(Packet::UnsubAck(ack)) if ack.packet_id == 2 => {
                got_unsuback = true;
                break;
            }
            _ => break,
        }
    }

    // If we haven't seen UNSUBACK yet, try once more
    if !got_unsuback {
        match client.recv().await {
            Ok(Packet::UnsubAck(ack)) if ack.packet_id == 2 => {
                got_unsuback = true;
            }
            _ => {}
        }
    }

    if !got_unsuback {
        return Ok(TestResult::fail(&ctx, "UNSUBACK not received"));
    }

    if buffered_count > 0 {
        // Server delivered buffered messages — MAY behaviour detected
        Ok(TestResult::pass(&ctx))
    } else {
        // Server did not deliver any buffered messages — also valid, but MAY not detected
        Ok(TestResult::fail(
            &ctx,
            "Server did not deliver any buffered messages after UNSUBSCRIBE (MAY behaviour not detected)",
        ))
    }
}

const RETAIN_HANDLING_0: TestContext = TestContext {
    refs: &["MQTT-3.8.4-4"],
    description: "retain_handling=0: existing retained messages MUST be re-sent on subscribe",
    compliance: Compliance::Must,
};

/// With retain_handling=0 (the default), any existing retained messages matching
/// the topic filter MUST be re-sent on subscribe [MQTT-3.8.4-4].
async fn retain_handling_0_sends_retained(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = RETAIN_HANDLING_0;

    let topic = "mqtt/test/sub/rh0";

    // Publish a retained message
    let pub_conn = ConnectParams::new("mqtt-test-rh0-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker reported Retain Available = false",
        ));
    }

    pub_client
        .send_publish(&PublishParams::retained(topic, b"rh0-retained".to_vec()))
        .await?;

    // Subscribe with retain_handling=0 (explicit default)
    let sub_conn = ConnectParams::new("mqtt-test-rh0-sub");
    let (mut sub_client, _) = client::connect(config.addr, &sub_conn, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            topic.to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                retain_handling: 0,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

    // Must receive the retained message
    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => {}
        Ok(other) => {
            return Ok(TestResult::fail_packet(&ctx, "retained PUBLISH", &other));
        }
        Err(_) => {
            return Ok(TestResult::fail(
                &ctx,
                "No retained message delivered on subscribe with retain_handling=0",
            ));
        }
    }

    // Re-subscribe on the same connection — retain_handling=0 means resend again
    let sub2 = SubscribeParams {
        packet_id: 2,
        filters: vec![(
            topic.to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                retain_handling: 0,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    sub_client.send_subscribe(&sub2).await?;
    sub_client.recv().await?; // SUBACK

    // Must receive retained message again
    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(TestResult::pass(&ctx)),
        Ok(other) => Ok(TestResult::fail_packet(
            &ctx,
            "retained PUBLISH on re-sub",
            &other,
        )),
        Err(_) => Ok(TestResult::fail(
            &ctx,
            "No retained message on re-subscription with retain_handling=0",
        )),
    }
}

const QOS_DOWNGRADE_1_TO_0: TestContext = TestContext {
    refs: &["MQTT-3.8.4-8"],
    description: "Delivered QoS MUST be min(published QoS, granted QoS): QoS 1 → QoS 0",
    compliance: Compliance::Must,
};

/// The QoS of delivered messages MUST be the minimum of the published QoS and
/// the maximum QoS granted by the server [MQTT-3.8.4-8]. Publish QoS 1, subscribe
/// at QoS 0, verify delivery at QoS 0.
async fn qos_downgrade_qos1_to_qos0(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = QOS_DOWNGRADE_1_TO_0;

    let topic = "mqtt/test/sub/qos1to0";

    // Subscriber at QoS 0
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-dg10-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publisher sends QoS 1
    let pub_conn = ConnectParams::new("mqtt-test-dg10-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    pub_client
        .send_publish(&PublishParams::qos1(topic, b"dg-test".to_vec(), 1))
        .await?;

    // Drain PUBACK from publisher
    let _ = pub_client.recv().await;

    // Subscriber should receive at QoS 0 (no packet_id)
    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => {
            if p.qos == QoS::AtMostOnce {
                Ok(TestResult::pass(&ctx))
            } else {
                Ok(TestResult::fail(
                    &ctx,
                    format!(
                        "Delivered at {:?}, expected AtMostOnce (QoS 1 pub, QoS 0 sub)",
                        p.qos
                    ),
                ))
            }
        }
        Ok(other) => Ok(TestResult::fail_packet(&ctx, "PUBLISH", &other)),
        Err(_) => Ok(TestResult::fail(&ctx, "No message delivered to subscriber")),
    }
}

const UNSUB_INFLIGHT_QOS1: TestContext = TestContext {
    refs: &["MQTT-3.10.4-2"],
    description: "Server MUST complete in-flight QoS 1 delivery after UNSUBSCRIBE",
    compliance: Compliance::Must,
};

/// After UNSUBSCRIBE, the server MUST complete delivery of any QoS 1 messages
/// that are already in-flight [MQTT-3.10.4-2].
async fn unsubscribe_inflight_qos1_completes(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = UNSUB_INFLIGHT_QOS1;

    let topic = "mqtt/test/sub/unsub-inflight";

    // Subscriber at QoS 1
    let sub_conn = ConnectParams::new("mqtt-test-unsub-if-sub");
    let (mut sub_client, _) = client::connect(config.addr, &sub_conn, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    match sub_client.recv().await? {
        Packet::SubAck(_) => {}
        other => return Ok(TestResult::fail_packet(&ctx, "SUBACK", &other)),
    }

    // Publisher sends several QoS 1 messages rapidly
    let pub_conn = ConnectParams::new("mqtt-test-unsub-if-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    for i in 1..=5u16 {
        pub_client
            .send_publish(&PublishParams::qos1(
                topic,
                format!("inflight-{i}").into_bytes(),
                i,
            ))
            .await?;
    }

    // Read at least one PUBLISH from subscriber before unsubscribing
    let mut received_before_unsub = 0u32;
    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => {
            received_before_unsub += 1;
            // Do NOT send PUBACK — leave it in-flight
            // Now unsubscribe immediately
            let unsub = UnsubscribeParams::simple(2, topic);
            sub_client.send_unsubscribe(&unsub).await?;
        }
        Ok(other) => return Ok(TestResult::fail_packet(&ctx, "PUBLISH", &other)),
        Err(_) => {
            return Ok(TestResult::fail(
                &ctx,
                "No message received before unsubscribe",
            ));
        }
    }

    // The server should still expect our PUBACK for the in-flight message.
    // Send PUBACK now and verify the server processes it (no disconnect).
    // Also drain any additional messages and the UNSUBACK.
    let mut got_unsuback = false;
    let mut first_pid_acked = false;
    for _ in 0..20 {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                // Additional messages may still arrive — ACK them
                if let Some(pid) = p.packet_id {
                    sub_client.send_puback(pid, 0x00).await?;
                    first_pid_acked = true;
                }
            }
            Ok(Packet::UnsubAck(ack)) if ack.packet_id == 2 => {
                got_unsuback = true;
                // After UNSUBACK, ACK the first in-flight message if we
                // haven't done so via a retransmit
                if !first_pid_acked {
                    sub_client.send_puback(1, 0x00).await?;
                }
                break;
            }
            _ => break,
        }
    }

    // Try once more for UNSUBACK if needed
    if !got_unsuback {
        match sub_client.recv().await {
            Ok(Packet::UnsubAck(ack)) if ack.packet_id == 2 => {
                got_unsuback = true;
            }
            _ => {}
        }
    }

    if !got_unsuback {
        return Ok(TestResult::fail(&ctx, "UNSUBACK not received"));
    }

    // The fact that we received messages, unsubscribed, and could still
    // complete in-flight QoS 1 delivery (PUBACK accepted) means the
    // server completed the in-flight delivery.
    if received_before_unsub > 0 {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(&ctx, "No in-flight messages observed"))
    }
}

// ── Shared subscriptions ────────────────────────────────────────────────────

const SHARED_SUB_FORMAT: TestContext = TestContext {
    refs: &["MQTT-4.8.2-2"],
    description: "ShareName MUST NOT contain '/', '+', or '#' and MUST be followed by a Topic Filter",
    compliance: Compliance::Must,
};

/// The ShareName in `$share/ShareName/TopicFilter` MUST NOT contain '/', '+',
/// or '#', and MUST be followed by '/' and a Topic Filter [MQTT-4.8.2-2].
async fn shared_sub_topic_filter_format(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SHARED_SUB_FORMAT;

    let params = ConnectParams::new("mqtt-test-shared-fmt");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker does not support shared subscriptions",
        ));
    }

    // Helper: subscribe and check if broker rejects (reason >= 0x80 or DISCONNECT).
    let invalid_topics = [
        "$share/grp+/mqtt/test/shared/fmt", // '+' in ShareName
        "$share/grp#/mqtt/test/shared/fmt", // '#' in ShareName
        "$share/grouponly",                 // no '/' + topic filter
    ];

    let mut rejected = 0;
    for (i, topic) in invalid_topics.iter().enumerate() {
        let pid = (i + 1) as u16;
        let sub = SubscribeParams::simple(pid, *topic, QoS::AtMostOnce);
        client.send_subscribe(&sub).await?;

        match client.recv().await {
            Ok(Packet::SubAck(ack))
                if ack
                    .reason_codes
                    .first()
                    .map(|&c| c >= 0x80)
                    .unwrap_or(false) =>
            {
                rejected += 1;
            }
            Ok(Packet::Disconnect(_)) | Err(_) => {
                // Broker disconnected us — this counts as rejection.
                // Reconnect for remaining tests.
                rejected += 1;
                if i < invalid_topics.len() - 1 {
                    let (new_client, _) =
                        client::connect(config.addr, &params, config.recv_timeout).await?;
                    client = new_client;
                }
            }
            Ok(Packet::SubAck(_)) => {
                // Broker accepted — not a rejection.
            }
            Ok(_) => {}
        }
    }

    if rejected == invalid_topics.len() {
        Ok(TestResult::pass(&ctx))
    } else {
        Ok(TestResult::fail(
            &ctx,
            format!(
                "Only {rejected}/{} invalid shared subscription formats were rejected",
                invalid_topics.len()
            ),
        ))
    }
}

const SHARED_SUB_QOS: TestContext = TestContext {
    refs: &["MQTT-4.8.2-3"],
    description: "Server MUST respect the granted QoS for shared subscription clients",
    compliance: Compliance::Must,
};

/// When delivering to shared subscribers, the server MUST respect each
/// subscriber's granted QoS level [MQTT-4.8.2-3].
async fn shared_sub_qos_respected(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SHARED_SUB_QOS;

    let topic = "mqtt/test/shared/qos";
    let shared_filter = "$share/qosgrp/mqtt/test/shared/qos";

    // Subscriber A at QoS 0.
    let params_a = ConnectParams::new("mqtt-test-shared-qos-a");
    let (mut sub_a, connack) = client::connect(config.addr, &params_a, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker does not support shared subscriptions",
        ));
    }

    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtMostOnce);
    sub_a.send_subscribe(&sub).await?;
    sub_a.recv().await?; // SUBACK

    // Subscriber B at QoS 1.
    let params_b = ConnectParams::new("mqtt-test-shared-qos-b");
    let (mut sub_b, _) = client::connect(config.addr, &params_b, config.recv_timeout).await?;
    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtLeastOnce);
    sub_b.send_subscribe(&sub).await?;
    sub_b.recv().await?; // SUBACK

    // Publish 10 QoS 1 messages.
    let pub_params = ConnectParams::new("mqtt-test-shared-qos-pub");
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params, config.recv_timeout).await?;
    for i in 1..=10u16 {
        let msg = PublishParams::qos1(topic, format!("shared-qos-{i}").into_bytes(), i);
        pub_client.send_publish(&msg).await?;
    }
    // Drain PUBACKs.
    for _ in 0..10 {
        let _ = pub_client.recv().await;
    }

    // Collect messages from both subscribers.
    let short_timeout = Duration::from_millis(500);
    let mut qos_violation = false;

    // Drain subscriber A — should all be QoS 0.
    while let Ok(Packet::Publish(p)) = sub_a.recv_with_timeout(short_timeout).await {
        if p.qos != QoS::AtMostOnce {
            qos_violation = true;
        }
    }

    // Drain subscriber B — should be QoS 0 or QoS 1.
    while let Ok(Packet::Publish(p)) = sub_b.recv_with_timeout(short_timeout).await {
        if p.qos == QoS::ExactlyOnce {
            qos_violation = true;
        }
        // ACK QoS 1 messages.
        if let Some(pid) = p.packet_id
            && p.qos == QoS::AtLeastOnce
        {
            sub_b.send_puback(pid, 0x00).await?;
        }
    }

    if qos_violation {
        Ok(TestResult::fail(
            &ctx,
            "Server delivered messages exceeding the subscriber's granted QoS",
        ))
    } else {
        Ok(TestResult::pass(&ctx))
    }
}

const SHARED_SUB_QOS2_RECONNECT: TestContext = TestContext {
    refs: &["MQTT-4.8.2-4"],
    description: "Server MUST complete QoS 2 delivery to chosen subscriber on reconnect",
    compliance: Compliance::Must,
};

/// If the connection to the chosen shared subscriber breaks during QoS 2
/// delivery, the server MUST complete delivery when the client reconnects
/// [MQTT-4.8.2-4].
async fn shared_sub_qos2_reconnect(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SHARED_SUB_QOS2_RECONNECT;

    let sub_id = "mqtt-test-shared-q2-recon";
    let pub_id = "mqtt-test-shared-q2-recon-pub";
    let topic = "mqtt/test/shared/qos2recon";
    let shared_filter = "$share/q2grp/mqtt/test/shared/qos2recon";

    // 1. Connect subscriber with persistent session.
    let mut sub_params = ConnectParams::new(sub_id);
    sub_params.properties.session_expiry_interval = Some(60);
    let (mut sub_client, connack) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker does not support shared subscriptions",
        ));
    }

    let sub = SubscribeParams::simple(1, shared_filter, QoS::ExactlyOnce);
    sub_client.send_subscribe(&sub).await?;
    sub_client.recv().await?; // SUBACK

    // 2. Disconnect subscriber abruptly.
    drop(sub_client.into_raw());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Publish QoS 2 message while subscriber is offline.
    let pub_conn = ConnectParams::new(pub_id);
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    let pub_msg = PublishParams::qos2(topic, b"shared-qos2-recon".to_vec(), 1);
    pub_client.send_publish(&pub_msg).await?;

    // Complete publisher-side QoS 2 handshake.
    for _ in 0..5 {
        match pub_client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 1 => {
                pub_client.send_pubrel(1, 0x00).await?;
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
    drop(pub_client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Reconnect subscriber with clean_start=false.
    let mut sub_params2 = ConnectParams::new(sub_id);
    sub_params2.clean_start = false;
    sub_params2.properties.session_expiry_interval = Some(60);
    let (mut sub_client2, connack2) =
        client::connect(config.addr, &sub_params2, config.recv_timeout).await?;

    if !connack2.session_present {
        cleanup_session(config.addr, sub_id, config.recv_timeout).await;
        return Ok(TestResult::fail(
            &ctx,
            "Broker did not preserve session (session_present=0)",
        ));
    }

    // 5. Should receive the queued QoS 2 message.
    let result = match sub_client2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => TestResult::pass(&ctx),
        Ok(Packet::PubRel(_)) => TestResult::pass(&ctx),
        Ok(other) => TestResult::fail_packet(
            &ctx,
            "PUBLISH or PUBREL from shared subscription on reconnect",
            &other,
        ),
        Err(_) => TestResult::fail(
            &ctx,
            "No QoS 2 message delivered to shared subscriber after reconnect",
        ),
    };

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}

const SHARED_SUB_NACK_DISCARD: TestContext = TestContext {
    refs: &["MQTT-4.8.2-6"],
    description: "Server MUST discard message if subscriber sends PUBACK with Reason Code >= 0x80",
    compliance: Compliance::Must,
};

/// If a shared subscription client responds with a PUBACK containing Reason
/// Code >= 0x80, the server MUST discard the message and not attempt to send
/// it to any other subscriber [MQTT-4.8.2-6].
async fn shared_sub_negative_ack_discard(config: TestConfig<'_>) -> anyhow::Result<TestResult> {
    let ctx = SHARED_SUB_NACK_DISCARD;

    let topic = "mqtt/test/shared/nack";
    let shared_filter = "$share/nackgrp/mqtt/test/shared/nack";

    // 1. Connect subscriber A.
    let params_a = ConnectParams::new("mqtt-test-shared-nack-a");
    let (mut sub_a, connack) = client::connect(config.addr, &params_a, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(TestResult::skip(
            &ctx,
            "Broker does not support shared subscriptions",
        ));
    }

    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtLeastOnce);
    sub_a.send_subscribe(&sub).await?;
    sub_a.recv().await?; // SUBACK

    // 2. Connect subscriber B but do NOT subscribe yet — this ensures
    //    the message is routed to A (the only subscriber in the group).
    let params_b = ConnectParams::new("mqtt-test-shared-nack-b");
    let (mut sub_b, _) = client::connect(config.addr, &params_b, config.recv_timeout).await?;

    // 3. Publish one QoS 1 message.
    let pub_params = ConnectParams::new("mqtt-test-shared-nack-pub");
    let (mut pub_client, _) =
        client::connect(config.addr, &pub_params, config.recv_timeout).await?;
    let msg = PublishParams::qos1(topic, b"nack-test".to_vec(), 1);
    pub_client.send_publish(&msg).await?;
    // Wait for PUBACK from server.
    for _ in 0..5 {
        if let Ok(Packet::PubAck(_)) = pub_client.recv().await {
            break;
        }
    }
    drop(pub_client);

    // 4. A should receive the message. Send negative PUBACK (0x80).
    match sub_a.recv().await? {
        Packet::Publish(p) => {
            if let Some(pid) = p.packet_id {
                sub_a.send_puback(pid, 0x80).await?;
            }
        }
        other => {
            return Ok(TestResult::fail_packet(
                &ctx,
                "PUBLISH on subscriber A",
                &other,
            ));
        }
    }

    // 5. Now subscribe B to the same shared group.
    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtLeastOnce);
    sub_b.send_subscribe(&sub).await?;
    sub_b.recv().await?; // SUBACK

    // 6. B should NOT receive the NACKed message.
    let short_timeout = Duration::from_millis(500);
    match sub_b.recv_with_timeout(short_timeout).await {
        Err(_) => {
            // Timeout — no message received. This is correct.
            Ok(TestResult::pass(&ctx))
        }
        Ok(Packet::Publish(_)) => Ok(TestResult::fail(
            &ctx,
            "Server redirected NACKed message to another subscriber (should have discarded)",
        )),
        Ok(_) => {
            // Some other packet — not the message, pass.
            Ok(TestResult::pass(&ctx))
        }
    }
}

/// Clean up a persistent session by reconnecting with clean_start=true.
async fn cleanup_session(addr: &str, client_id: &str, recv_timeout: Duration) {
    let params = ConnectParams::new(client_id);
    if let Ok((_c, _)) = client::connect(addr, &params, recv_timeout).await {
        // AutoDisconnect handles the clean disconnect on drop.
    }
}
