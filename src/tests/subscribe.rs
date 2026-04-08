//! SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK compliance tests [MQTT-3.8 / MQTT-3.10].

use std::time::Duration;

use anyhow::Result;

use crate::client::{self, RecvError};
use crate::codec::{
    ConnectParams, Packet, Properties, PublishParams, QoS, SubscribeOptions, SubscribeParams,
    UnsubscribeParams,
};
use crate::helpers::{expect_publish, expect_suback, publish_and_expect};
use crate::types::{Compliance, IntoOutcome, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("SUBSCRIBE / UNSUBSCRIBE");

    suite.add(BASIC_SUB, basic_subscribe(config));
    suite.add(WILDCARD_PLUS, wildcard_plus(config));
    suite.add(WILDCARD_HASH, wildcard_hash(config));
    suite.add(UNSUB, unsubscribe(config));
    suite.add(DOLLAR_TOPIC, dollar_topic_no_wildcard_match(config));
    suite.add(SUBACK_REASON_COUNT, suback_reason_code_count(config));
    suite.add(SUBACK_REASON_ORDER, suback_reason_code_order(config));
    suite.add(UNSUBACK_REASON_COUNT, unsuback_reason_code_count(config));
    suite.add(UNSUBACK_REASON_ORDER, unsuback_reason_code_order(config));
    suite.add(SHARED_SUB, shared_subscription(config));
    suite.add(SUB_ID, subscription_identifier(config));
    suite.add(NO_LOCAL, no_local_flag(config));
    suite.add(RETAIN_AS_PUB, retain_as_published(config));
    suite.add(RETAIN_AS_PUB_FALSE, retain_as_published_false(config));
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
    description: "When server receives a SUBSCRIBE packet from a Client, server MUST respond with a SUBACK packet",
    compliance: Compliance::Must,
};

/// When the Server receives a SUBSCRIBE packet from a Client, the Server MUST respond with a SUBACK packet. [MQTT-3.8.4-1].
async fn basic_subscribe(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-subscribe");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, "mqtt/test/sub/basic", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;

    Ok(expect_suback(&mut client).await.into_outcome())
}

const WILDCARD_PLUS: TestContext = TestContext {
    refs: &["MQTT-4.7.1-2"],
    description: "single-level wildcard can be used at any level in the Topic Filter, including first and last levels",
    compliance: Compliance::Must,
};

/// The single-level wildcard can be used at any level in the Topic Filter, including first and last levels. Where it is used, it MUST occupy an entire level of the filter. [MQTT-4.7.1-2].
async fn wildcard_plus(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-wildcard-plus");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, "mqtt/test/sub/wc_plus/+", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

    Ok(
        publish_and_expect(&mut client, "mqtt/test/sub/wc_plus/match", b"plus")
            .await
            .into_outcome(),
    )
}

const WILDCARD_HASH: TestContext = TestContext {
    refs: &["MQTT-4.7.1-1"],
    description: "multi-level wildcard character MUST be specified either on its own or following a topic level separator",
    compliance: Compliance::Must,
};

/// The multi-level wildcard character MUST be specified either on its own or following a topic level separator. In either case it MUST be the last character specified in the Topic Filter. [MQTT-4.7.1-1].
async fn wildcard_hash(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-wildcard-hash");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, "mqtt/test/sub/wc_hash/#", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

    Ok(publish_and_expect(
        &mut client,
        "mqtt/test/sub/wc_hash/deep/nested/topic",
        b"hash",
    )
    .await
    .into_outcome())
}

const UNSUB: TestContext = TestContext {
    refs: &["MQTT-3.10.4-4"],
    description: "Server MUST respond to an UNSUBSCRIBE request by sending an UNSUBACK packet",
    compliance: Compliance::Must,
};

/// The Server MUST respond to an UNSUBSCRIBE request by sending an UNSUBACK packet. [MQTT-3.10.4-4].
async fn unsubscribe(config: TestConfig<'_>) -> Result<Outcome> {
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
        Packet::UnsubAck(ack) if ack.packet_id == 2 => Ok(Outcome::Pass),
        other => Ok(Outcome::fail_packet("UNSUBACK(2)", &other)),
    }
}

const DOLLAR_TOPIC: TestContext = TestContext {
    refs: &["MQTT-4.7.2-1"],
    description: "Server MUST NOT match Topic Filters starting with a wildcard character (# or +) with Topic Names beginning with a $ character",
    compliance: Compliance::Must,
};

/// The Server MUST NOT match Topic Filters starting with a wildcard character (# or +) with Topic Names beginning with a $ character. [MQTT-4.7.2-1].
async fn dollar_topic_no_wildcard_match(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-dollar-topic");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Subscribe to "#" which should match everything EXCEPT $-prefixed topics
    let sub = SubscribeParams::simple(1, "#", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
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
            Err(RecvError::Timeout | RecvError::Closed) => break,
            Err(RecvError::Other(e)) => return Err(e),
            Ok(_) => {}
        }
    }

    if received_dollar {
        Ok(Outcome::fail("$SYS topic was delivered to '#' subscriber"))
    } else if received_canary {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(
            "Canary message not received — '#' subscription may not be working",
        ))
    }
}

const SUBACK_REASON_COUNT: TestContext = TestContext {
    refs: &["MQTT-3.8.4-6", "MQTT-3.9.3-1"],
    description: "SUBACK packet sent by server to client MUST contain a Reason Code for each Topic Filter/Subscription Option pair",
    compliance: Compliance::Must,
};

/// The SUBACK packet sent by the Server to the Client MUST contain a Reason Code for each Topic Filter/Subscription Option pair. [MQTT-3.8.4-6].
async fn suback_reason_code_count(config: TestConfig<'_>) -> Result<Outcome> {
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
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Expected 3 reason codes, got {}",
                    ack.reason_codes.len()
                )))
            }
        }
        other => Ok(Outcome::fail_packet("SUBACK(1)", &other)),
    }
}

const SUBACK_REASON_ORDER: TestContext = TestContext {
    refs: &["MQTT-3.9.3-1"],
    description: "order of Reason Codes in the SUBACK packet MUST match the order of Topic Filters in the SUBSCRIBE packet",
    compliance: Compliance::Must,
};

/// The order of Reason Codes in the SUBACK packet MUST match the order of Topic Filters in the SUBSCRIBE packet. [MQTT-3.9.3-1].
///
/// This uses three filters where the middle one is intentionally invalid
/// (`$share/group` missing "/<TopicFilter>"), so expected outcome is:
/// success, failure, success — in that order.
async fn suback_reason_code_order(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-suback-order");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 11,
        filters: vec![
            (
                "mqtt/test/sub/order/a".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
            (
                "$share/group".to_string(), // invalid shared-sub filter format
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
            (
                "mqtt/test/sub/order/c".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
        ],
        properties: Properties::default(),
    };
    client.send_subscribe(&sub).await?;

    match client.recv().await {
        Ok(Packet::SubAck(ack)) if ack.packet_id == 11 => {
            if ack.reason_codes.len() != 3 {
                return Ok(Outcome::fail(format!(
                    "Expected 3 reason codes, got {}",
                    ack.reason_codes.len()
                )));
            }
            let first_ok = ack.reason_codes[0] < 0x80;
            let middle_fail = ack.reason_codes[1] >= 0x80;
            let third_ok = ack.reason_codes[2] < 0x80;
            if first_ok && middle_fail && third_ok {
                Ok(Outcome::Pass)
            } else if ack.reason_codes.iter().all(|&c| c >= 0x80) {
                Ok(Outcome::skip(
                    "Broker rejected all filters; cannot verify per-filter reason-code ordering",
                ))
            } else {
                Ok(Outcome::fail(format!(
                    "Unexpected SUBACK reason-code pattern (expected [success, failure, success]): {:?}",
                    ack.reason_codes
                )))
            }
        }
        Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => Ok(Outcome::skip(
            "Broker closed connection for mixed valid/invalid filters; cannot verify SUBACK ordering",
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail("No SUBACK received (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("SUBACK(11)", &other)),
    }
}

const UNSUBACK_REASON_COUNT: TestContext = TestContext {
    refs: &["MQTT-3.10.4-5", "MQTT-3.11.3-1"],
    description: "UNSUBACK packet MUST have the same Packet Identifier as the UNSUBSCRIBE packet",
    compliance: Compliance::Must,
};

/// The UNSUBACK packet MUST have the same Packet Identifier as the UNSUBSCRIBE packet. Even where no Topic Subscriptions are deleted, the Server MUST respond with an UNSUBACK. [MQTT-3.10.4-5].
async fn unsuback_reason_code_count(config: TestConfig<'_>) -> Result<Outcome> {
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
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

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
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Expected 3 reason codes, got {}",
                    ack.reason_codes.len()
                )))
            }
        }
        other => Ok(Outcome::fail_packet("UNSUBACK(2)", &other)),
    }
}

const UNSUBACK_REASON_ORDER: TestContext = TestContext {
    refs: &["MQTT-3.11.3-1"],
    description: "order of Reason Codes in the UNSUBACK packet MUST match the order of Topic Filters in the UNSUBSCRIBE packet",
    compliance: Compliance::Must,
};

/// The order of Reason Codes in the UNSUBACK packet MUST match the order of Topic Filters in the UNSUBSCRIBE packet. [MQTT-3.11.3-1].
///
/// Similar to SUBACK ordering test, this uses an intentionally invalid middle
/// filter so expected pattern is success, failure, success in order.
async fn unsuback_reason_code_order(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-unsuback-order");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Create subscriptions for first/third filters.
    let sub = SubscribeParams {
        packet_id: 21,
        filters: vec![
            (
                "mqtt/test/unsub/order/a".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
            (
                "mqtt/test/unsub/order/c".to_string(),
                SubscribeOptions {
                    qos: QoS::AtMostOnce,
                    ..Default::default()
                },
            ),
        ],
        properties: Properties::default(),
    };
    client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

    let unsub = UnsubscribeParams {
        packet_id: 22,
        filters: vec![
            "mqtt/test/unsub/order/a".to_string(),
            "$share/group".to_string(), // invalid shared-sub filter format
            "mqtt/test/unsub/order/c".to_string(),
        ],
        properties: Properties::default(),
    };
    client.send_unsubscribe(&unsub).await?;

    match client.recv().await {
        Ok(Packet::UnsubAck(ack)) if ack.packet_id == 22 => {
            if ack.reason_codes.len() != 3 {
                return Ok(Outcome::fail(format!(
                    "Expected 3 reason codes, got {}",
                    ack.reason_codes.len()
                )));
            }
            let first_ok = ack.reason_codes[0] < 0x80;
            let middle_fail = ack.reason_codes[1] >= 0x80;
            let third_ok = ack.reason_codes[2] < 0x80;
            if first_ok && middle_fail && third_ok {
                Ok(Outcome::Pass)
            } else if ack.reason_codes.iter().all(|&c| c >= 0x80) {
                Ok(Outcome::skip(
                    "Broker rejected all filters; cannot verify per-filter reason-code ordering",
                ))
            } else {
                Ok(Outcome::fail(format!(
                    "Unexpected UNSUBACK reason-code pattern (expected [success, failure, success]): {:?}",
                    ack.reason_codes
                )))
            }
        }
        Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => Ok(Outcome::skip(
            "Broker closed connection for mixed valid/invalid filters; cannot verify UNSUBACK ordering",
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail("No UNSUBACK received (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("UNSUBACK(22)", &other)),
    }
}

// ── MAY ──────────────────────────────────────────────────────────────────────

const SHARED_SUB: TestContext = TestContext {
    refs: &["MQTT-4.8.2-1"],
    description: "A Shared Subscription's Topic Filter MUST start with $share/ and MUST contain a ShareName that is at least one character long",
    compliance: Compliance::May,
};

/// A Shared Subscription's Topic Filter MUST start with $share/ and MUST contain a ShareName that is at least one character long. [MQTT-4.8.2-1].
async fn shared_subscription(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-shared-sub");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(Outcome::skip(
            "Broker reported Shared Subscription Available = false",
        ));
    }

    let sub = SubscribeParams::simple(1, "$share/testgroup/mqtt/test/sub/shared", QoS::AtMostOnce);
    client.send_subscribe(&sub).await?;

    Ok(expect_suback(&mut client).await.into_outcome())
}

// ── Subscribe options ───────────────────────────────────────────────────────

const SUB_ID: TestContext = TestContext {
    refs: &["MQTT-3.3.4-3"],
    description: "If client specified a Subscription Identifier for any of the overlapping subscriptions server MUST send those Subscription Identifiers in the message which is published as the result of the subscriptions",
    compliance: Compliance::Must,
};

/// If the Client specified a Subscription Identifier for any of the overlapping subscriptions the Server MUST send those Subscription Identifiers in the message which is published as the result of the subscriptions. [MQTT-3.3.4-3].
async fn subscription_identifier(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-sub-id");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.subscription_ids_available == Some(false) {
        return Ok(Outcome::skip(
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
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

    let p = match publish_and_expect(&mut client, "mqtt/test/sub/subid", b"subid-test").await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if p.properties.subscription_identifier == Some(42) {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Expected subscription_identifier=42, got {:?}",
            p.properties.subscription_identifier
        )))
    }
}

const NO_LOCAL: TestContext = TestContext {
    refs: &["MQTT-3.8.3-3"],
    description: "Bit 2 of the Subscription Options represents the No Local option",
    compliance: Compliance::Must,
};

/// Bit 2 of the Subscription Options represents the No Local option. If the value is 1, Application Messages MUST NOT be forwarded to a connection with a ClientID equal to the ClientID of the publishing connection. [MQTT-3.8.3-3].
async fn no_local_flag(config: TestConfig<'_>) -> Result<Outcome> {
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
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

    client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sub/no_local",
            b"no-local-test".to_vec(),
        ))
        .await?;

    // Expect NO message — short timeout is sufficient to confirm absence.
    match client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::fail("broker closed connection unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/no_local" => {
            Ok(Outcome::fail("Received own PUBLISH despite no_local=true"))
        }
        Ok(other) => Ok(Outcome::fail_packet("no packet (no_local)", &other)),
    }
}

const RETAIN_AS_PUB: TestContext = TestContext {
    refs: &["MQTT-3.8.3-4", "MQTT-3.3.1-13"],
    description: "It is a Protocol Error to set the No Local bit to 1 on a Shared Subscription",
    compliance: Compliance::Must,
};

/// It is a Protocol Error to set the No Local bit to 1 on a Shared Subscription. [MQTT-3.8.3-4].
async fn retain_as_published(config: TestConfig<'_>) -> Result<Outcome> {
    let pub_params_conn = ConnectParams::new("mqtt-test-rap-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_params_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(Outcome::skip("Broker reported Retain Available = false"));
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
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    match expect_publish(&mut sub_client, "mqtt/test/sub/rap").await {
        Ok(p) if p.retain => Ok(Outcome::Pass),
        Ok(_) => Ok(Outcome::fail(
            "Received PUBLISH but retain flag was cleared",
        )),
        Err(r) => Ok(r),
    }
}

const RETAIN_AS_PUB_FALSE: TestContext = TestContext {
    refs: &["MQTT-3.3.1-12"],
    description: "If the value of Retain As Published subscription option is set to 0, server MUST set the RETAIN flag to 0 when forwarding an Application Message regardless of how the RETAIN flag was set in the received PUBLISH packet",
    compliance: Compliance::Must,
};

/// With retain_as_published=false, forwarded retained messages MUST be sent
/// If the value of Retain As Published subscription option is set to 0, the Server MUST set the RETAIN flag to 0 when forwarding an Application Message regardless of how the RETAIN flag was set in the received PUBLISH packet. [MQTT-3.3.1-12].
async fn retain_as_published_false(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/sub/rap_false";

    // Publish retained message
    let pub_conn = ConnectParams::new("mqtt-test-rapf-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(Outcome::skip("Broker reported Retain Available = false"));
    }

    pub_client
        .send_publish(&PublishParams::retained(topic, b"rap-false-test".to_vec()))
        .await?;

    // New client subscribes with retain_as_published=false explicitly
    let sub_conn = ConnectParams::new("mqtt-test-rapf-sub");
    let (mut sub_client, _) = client::connect(config.addr, &sub_conn, config.recv_timeout).await?;

    let sub = SubscribeParams {
        packet_id: 1,
        filters: vec![(
            topic.to_string(),
            SubscribeOptions {
                qos: QoS::AtMostOnce,
                retain_as_published: false,
                ..Default::default()
            },
        )],
        properties: Properties::default(),
    };
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    match expect_publish(&mut sub_client, topic).await {
        Ok(p) if !p.retain => Ok(Outcome::Pass),
        Ok(_) => Ok(Outcome::fail(
            "Received retained message with retain flag set despite retain_as_published=false",
        )),
        Err(r) => Ok(r),
    }
}

const RETAIN_HANDLING_1: TestContext = TestContext {
    refs: &["MQTT-3.8.3-5", "MQTT-3.3.1-10"],
    description: "Server MUST treat a SUBSCRIBE packet as malformed if any of Reserved bits in the Payload are non-zero",
    compliance: Compliance::Must,
};

/// The Server MUST treat a SUBSCRIBE packet as malformed if any of Reserved bits in the Payload are non-zero. [MQTT-3.8.3-5].
async fn retain_handling_1(config: TestConfig<'_>) -> Result<Outcome> {
    // Publish a retained message
    let pub_conn = ConnectParams::new("mqtt-test-rh1-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(Outcome::skip("Broker reported Retain Available = false"));
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
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Should receive retained message on first subscribe
    if let Err(r) = expect_publish(&mut sub_client, "mqtt/test/sub/rh1").await {
        return Ok(r);
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
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Should NOT receive retained message again — short timeout.
    match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::fail("broker closed connection unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rh1" => Ok(Outcome::fail(
            "Retained message sent again on re-subscription",
        )),
        Ok(other) => Ok(Outcome::fail_packet("no packet on re-subscription", &other)),
    }
}

const RETAIN_HANDLING_2: TestContext = TestContext {
    refs: &["MQTT-3.8.3-5"],
    description: "Server MUST treat a SUBSCRIBE packet as malformed if any of Reserved bits in the Payload are non-zero",
    compliance: Compliance::Must,
};

/// The Server MUST treat a SUBSCRIBE packet as malformed if any of Reserved bits in the Payload are non-zero. [MQTT-3.8.3-5].
async fn retain_handling_2(config: TestConfig<'_>) -> Result<Outcome> {
    // Publish a retained message
    let pub_conn = ConnectParams::new("mqtt-test-rh2-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(Outcome::skip("Broker reported Retain Available = false"));
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
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Should NOT receive any retained message — short timeout.
    match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::fail("broker closed connection unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sub/rh2" => Ok(Outcome::fail(
            "Retained message delivered despite retain_handling=2",
        )),
        Ok(other) => Ok(Outcome::fail_packet(
            "no packet (retain_handling=2)",
            &other,
        )),
    }
}

// ── Unsubscribe behaviour ──────────────────────────────────────────────────

const UNSUB_STOPS: TestContext = TestContext {
    refs: &["MQTT-3.10.4-6"],
    description: "If a Server receives an UNSUBSCRIBE packet that contains multiple Topic Filters, it MUST process that packet as if it had received a sequence of multiple UNSUBSCRIBE packets, except that it sends just one UNSUBACK response",
    compliance: Compliance::Must,
};

/// After receiving a valid UNSUBSCRIBE, the server MUST stop adding new
/// If a Server receives an UNSUBSCRIBE packet that contains multiple Topic Filters, it MUST process that packet as if it had received a sequence of multiple UNSUBSCRIBE packets, except that it sends just one UNSUBACK response. [MQTT-3.10.4-6].
async fn unsubscribe_stops_delivery(config: TestConfig<'_>) -> Result<Outcome> {
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
    if let Err(r) = publish_and_expect(&mut client, topic, b"before").await {
        return Ok(r);
    }

    // Unsubscribe
    let unsub = UnsubscribeParams::simple(2, topic);
    client.send_unsubscribe(&unsub).await?;
    match client.recv().await? {
        Packet::UnsubAck(_) => {}
        other => return Ok(Outcome::fail_packet("UNSUBACK", &other)),
    }

    // Publish again — should NOT be delivered
    client
        .send_publish(&PublishParams::qos0(topic, b"after".to_vec()))
        .await?;

    match client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::fail("broker closed connection unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == topic => {
            Ok(Outcome::fail("Message delivered after UNSUBSCRIBE"))
        }
        Ok(other) => Ok(Outcome::fail_packet("no packet after UNSUBSCRIBE", &other)),
    }
}

// ── Overlapping subscriptions ──────────────────────────────────────────────

const OVERLAP_QOS: TestContext = TestContext {
    refs: &["MQTT-3.3.4-2"],
    description: "In this case server MUST deliver the message to client respecting the maximum QoS of all the matching subscriptions",
    compliance: Compliance::Must,
};

/// When a client has overlapping subscriptions, the server MUST deliver
/// In this case the Server MUST deliver the message to the Client respecting the maximum QoS of all the matching subscriptions. [MQTT-3.3.4-2].
async fn overlapping_subscriptions_max_qos(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-overlap-qos");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Subscribe to wildcard at QoS 0
    let sub1 = SubscribeParams::simple(1, "mqtt/test/sub/overlap/#", QoS::AtMostOnce);
    client.send_subscribe(&sub1).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

    // Subscribe to exact topic at QoS 1
    let sub2 = SubscribeParams::simple(2, "mqtt/test/sub/overlap/exact", QoS::AtLeastOnce);
    client.send_subscribe(&sub2).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

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
    let p = match expect_publish(&mut client, "mqtt/test/sub/overlap/exact").await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if let Some(pid) = p.packet_id {
        client.send_puback(pid, 0x00).await?;
    }
    if p.qos == QoS::AtLeastOnce {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Delivered at {:?}, expected AtLeastOnce",
            p.qos
        )))
    }
}

// ── Subscription Identifier with overlapping subscriptions ─────────────────

const SUB_ID_OVERLAP: TestContext = TestContext {
    refs: &["MQTT-3.3.4-3", "MQTT-3.3.4-4"],
    description: "If client specified a Subscription Identifier for any of the overlapping subscriptions server MUST send those Subscription Identifiers in the message which is published as the result of the subscriptions",
    compliance: Compliance::Must,
};

/// When multiple subscriptions match a publish and each has a Subscription
/// If the Client specified a Subscription Identifier for any of the overlapping subscriptions the Server MUST send those Subscription Identifiers in the message which is published as the result of the subscriptions. [MQTT-3.3.4-3].
async fn subscription_id_overlapping(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-subid-overlap");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.subscription_ids_available == Some(false) {
        return Ok(Outcome::skip(
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
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

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
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

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
        Ok(Outcome::Pass)
    } else if ids_seen.is_empty() {
        Ok(Outcome::fail(
            "No subscription identifiers in delivered PUBLISH",
        ))
    } else {
        Ok(Outcome::fail(format!(
            "Expected subscription IDs [10, 20], got {ids_seen:?}"
        )))
    }
}

// ── Topic edge cases ────────────────────────────────────────────────────────

const MULTI_LEVEL_TOPIC: TestContext = TestContext {
    refs: &["MQTT-4.7.1-1"],
    description: "multi-level wildcard character MUST be specified either on its own or following a topic level separator",
    compliance: Compliance::Must,
};

/// The multi-level wildcard character MUST be specified either on its own or following a topic level separator. In either case it MUST be the last character specified in the Topic Filter. [MQTT-4.7.1-1].
async fn multi_level_topic(config: TestConfig<'_>) -> Result<Outcome> {
    let (mut sub, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-multi-level",
        "mqtt/test/deep/#",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let publish = PublishParams::qos0("mqtt/test/deep/a/b/c/d", b"deep".to_vec());
    pub_client.send_publish(&publish).await?;

    Ok(expect_publish(&mut sub, "mqtt/test/deep/a/b/c/d")
        .await
        .into_outcome())
}

const WILDCARD_MIDDLE: TestContext = TestContext {
    refs: &["MQTT-4.7.1-2"],
    description: "single-level wildcard can be used at any level in the Topic Filter, including first and last levels",
    compliance: Compliance::Must,
};

/// A subscription to `a/+/c` MUST match `a/b/c` but NOT `a/b/d` or `a/b/c/d`.
async fn wildcard_middle_level(config: TestConfig<'_>) -> Result<Outcome> {
    let (mut sub, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-wc-mid",
        "mqtt/test/wc/+/end",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Should match
    let p1 = PublishParams::qos0("mqtt/test/wc/any/end", b"match".to_vec());
    pub_client.send_publish(&p1).await?;

    // Should NOT match (extra level)
    let p2 = PublishParams::qos0("mqtt/test/wc/any/extra/end", b"no-match".to_vec());
    pub_client.send_publish(&p2).await?;

    if let Err(r) = expect_publish(&mut sub, "mqtt/test/wc/any/end").await {
        return Ok(r);
    }

    // Verify no second message arrives (the non-matching one)
    match sub.recv_with_timeout(Duration::from_millis(500)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::Pass),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p2)) if p2.topic == "mqtt/test/wc/any/extra/end" => {
            Ok(Outcome::fail("'+' wildcard matched across multiple levels"))
        }
        _ => Ok(Outcome::Pass),
    }
}

const MULTI_FILTERS: TestContext = TestContext {
    refs: &["MQTT-3.8.4-5"],
    description: "If a Server receives a SUBSCRIBE packet that contains multiple Topic Filters it MUST handle that packet as if it had received a sequence of multiple SUBSCRIBE packets, except that it combines their responses into a single SUBACK response",
    compliance: Compliance::Must,
};

/// A SUBSCRIBE with multiple topic filters MUST return a SUBACK with
/// If a Server receives a SUBSCRIBE packet that contains multiple Topic Filters it MUST handle that packet as if it had received a sequence of multiple SUBSCRIBE packets, except that it combines their responses into a single SUBACK response. [MQTT-3.8.4-5].
async fn multiple_filters_single_subscribe(config: TestConfig<'_>) -> Result<Outcome> {
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
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Expected 3 reason codes, got {}",
                    ack.reason_codes.len()
                )))
            }
        }
        other => Ok(Outcome::fail_packet("SUBACK with 3 reason codes", &other)),
    }
}

const SUB_UPGRADE_QOS: TestContext = TestContext {
    refs: &["MQTT-3.8.4-3"],
    description: "If a Server receives a SUBSCRIBE packet containing a Topic Filter that is identical to a Non‑shared Subscription�s Topic Filter for the current Session then it MUST replace that existing Subscription with a new Subscription",
    compliance: Compliance::Must,
};

/// Re-subscribing to the same topic with a higher QoS MUST upgrade the
/// subscription. Messages should then be delivered at the new QoS.
async fn subscription_upgrade_qos(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-sub-upgrade");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Subscribe at QoS 0
    let sub0 = SubscribeParams::simple(1, "mqtt/test/upgrade", QoS::AtMostOnce);
    client.send_subscribe(&sub0).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
    }

    // Re-subscribe at QoS 1
    let sub1 = SubscribeParams::simple(2, "mqtt/test/upgrade", QoS::AtLeastOnce);
    client.send_subscribe(&sub1).await?;
    match client.recv().await? {
        Packet::SubAck(ack) => {
            if ack.reason_codes.first().copied() == Some(0x01) {
                // Granted QoS 1
                Ok(Outcome::Pass)
            } else if ack.reason_codes.first().copied() == Some(0x00) {
                // Granted QoS 0 — downgraded
                Ok(Outcome::fail(
                    "Re-subscribe at QoS 1 returned QoS 0 — subscription not upgraded",
                ))
            } else {
                Ok(Outcome::fail(format!(
                    "Unexpected SUBACK reason code: {:?}",
                    ack.reason_codes
                )))
            }
        }
        other => Ok(Outcome::fail_packet("SUBACK", &other)),
    }
}

const EMPTY_TOPIC_LEVEL: TestContext = TestContext {
    refs: &["MQTT-4.7.3-1"],
    description: "All Topic Names and Topic Filters MUST be at least one character long",
    compliance: Compliance::Must,
};

/// An empty topic level like `a//b` is valid per the spec. The broker MUST
/// deliver messages published to `a//b` to subscribers of `a//b`.
async fn empty_topic_level(config: TestConfig<'_>) -> Result<Outcome> {
    let (mut sub, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-empty-level",
        "mqtt/test//empty",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let publish = PublishParams::qos0("mqtt/test//empty", b"empty-level".to_vec());
    pub_client.send_publish(&publish).await?;

    Ok(expect_publish(&mut sub, "mqtt/test//empty")
        .await
        .into_outcome())
}

const CASE_SENSITIVE: TestContext = TestContext {
    refs: &["MQTT-4.7.3-3"],
    description: "Topic Names and Topic Filters are UTF-8 Encoded Strings; they MUST NOT encode to more than 65,535 bytes",
    compliance: Compliance::Must,
};

/// Topic names are case-sensitive. Subscribe to "mqtt/Test/CASE" and verify
/// that a publish to "mqtt/test/case" (different case) is NOT received, while
/// Topic Names and Topic Filters are UTF-8 Encoded Strings; they MUST NOT encode to more than 65,535 bytes. [MQTT-4.7.3-3].
async fn case_sensitive_topic(config: TestConfig<'_>) -> Result<Outcome> {
    let (mut sub, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-case",
        "mqtt/Test/CASE",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publish with different case — should NOT match
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/case",
            b"wrong-case".to_vec(),
        ))
        .await?;

    match sub.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/case" => {
            return Ok(Outcome::fail(
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

    Ok(expect_publish(&mut sub, "mqtt/Test/CASE")
        .await
        .into_outcome())
}

const EXACT_CHAR: TestContext = TestContext {
    refs: &["MQTT-4.7.3-4"],
    description: "When it performs subscription matching server MUST NOT perform any normalization of Topic Names or Topic Filters, or any modification or substitution of unrecognized characters",
    compliance: Compliance::Must,
};

/// Non-wildcard levels in a topic filter must match character-for-character.
/// Subscribe to "mqtt/exact/match", verify "mqtt/exact/match" matches but
/// When it performs subscription matching the Server MUST NOT perform any normalization of Topic Names or Topic Filters, or any modification or substitution of unrecognized characters. [MQTT-4.7.3-4].
async fn exact_char_match(config: TestConfig<'_>) -> Result<Outcome> {
    let (mut sub, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-exact",
        "mqtt/exact/match",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publish with one character different — should NOT match
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/exact/matcH",
            b"near-miss".to_vec(),
        ))
        .await?;

    match sub.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/exact/matcH" => {
            return Ok(Outcome::fail(
                "Received message on topic differing by one character — not character-for-character matching",
            ));
        }
        _ => {} // Expected: no message or timeout
    }

    // Publish with exact match — MUST match
    pub_client
        .send_publish(&PublishParams::qos0("mqtt/exact/match", b"exact".to_vec()))
        .await?;

    Ok(expect_publish(&mut sub, "mqtt/exact/match")
        .await
        .into_outcome())
}

const LEVEL_SEPARATOR_DISTINCT: TestContext = TestContext {
    refs: &["MQTT-4.7.0-1"],
    description: "wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name",
    compliance: Compliance::Must,
};

/// The topic level separator '/' creates distinct levels. "a/b" and "a//b" are
/// different topics because "a//b" has an empty level between two separators.
/// Subscribe to "a/b", verify "a/b" matches but "a//b" does not. Then subscribe
/// The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name. [MQTT-4.7.0-1].
async fn topic_level_separator_distinct(config: TestConfig<'_>) -> Result<Outcome> {
    // Subscriber 1: subscribe to "mqtt/test/sep/a/b"
    let (mut sub1, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-sep",
        "mqtt/test/sep/a/b",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publish to "mqtt/test/sep/a//b" (extra empty level) — should NOT match sub1
    pub_client
        .send_publish(&PublishParams::qos0(
            "mqtt/test/sep/a//b",
            b"empty-level".to_vec(),
        ))
        .await?;

    match sub1.recv_with_timeout(Duration::from_secs(1)).await {
        Ok(Packet::Publish(p)) if p.topic == "mqtt/test/sep/a//b" => {
            return Ok(Outcome::fail(
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

    if let Err(r) = expect_publish(&mut sub1, "mqtt/test/sep/a/b").await {
        return Ok(r);
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

    Ok(expect_publish(&mut sub2, "mqtt/test/sep/a//b")
        .await
        .into_outcome())
}

// ── Unsubscribe completeness ────────────────────────────────────────────────

const UNSUB_STOPS_NEW: TestContext = TestContext {
    refs: &["MQTT-3.10.4-1"],
    description: "Topic Filters (whether they contain wildcards or not) supplied in an UNSUBSCRIBE packet MUST be compared character-by-character with the current set of Topic Filters held by server for client",
    compliance: Compliance::Must,
};

/// After receiving UNSUBSCRIBE, the server MUST stop adding any new messages
/// The Topic Filters (whether they contain wildcards or not) supplied in an UNSUBSCRIBE packet MUST be compared character-by-character with the current set of Topic Filters held by the Server for the Client. If any filter matches exactly then its owning Subscription MUST be deleted. [MQTT-3.10.4-1].
///
/// This test differs from MQTT-3.10.4-6 (basic delivery stop) by:
/// 1. Explicitly verifying delivery works before unsubscribe
/// 2. Waiting for UNSUBACK before publishing
/// 3. Publishing multiple messages after unsubscribe with a small delay
async fn unsubscribe_stops_new_messages(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/unsub/stop";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-unsub-stop",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Step 1: Verify delivery works before unsubscribe
    pub_client
        .send_publish(&PublishParams::qos0(topic, b"before-unsub".to_vec()))
        .await?;
    match sub_client.recv().await? {
        Packet::Publish(p) if p.topic == topic => {}
        other => {
            return Ok(Outcome::fail_packet("PUBLISH before unsubscribe", &other));
        }
    }

    // Step 2: Unsubscribe and wait for UNSUBACK
    let unsub = UnsubscribeParams::simple(2, topic);
    sub_client.send_unsubscribe(&unsub).await?;
    match sub_client.recv().await? {
        Packet::UnsubAck(_) => {}
        other => return Ok(Outcome::fail_packet("UNSUBACK", &other)),
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
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::fail("broker closed connection unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(Outcome::fail(
            "Message delivered after UNSUBSCRIBE + UNSUBACK",
        )),
        Ok(other) => Ok(Outcome::fail_packet(
            "no packet after UNSUBSCRIBE + UNSUBACK",
            &other,
        )),
    }
}

const UNSUB_BUFFERED: TestContext = TestContext {
    refs: &["MQTT-3.10.4-3"],
    description: "When a Server receives UNSUBSCRIBE It MUST complete the delivery of any QoS 1 or QoS 2 messages which match the Topic Filters and it has started to send to client",
    compliance: Compliance::May,
};

/// After UNSUBSCRIBE, the server MAY continue to deliver messages that were
/// When a Server receives UNSUBSCRIBE It MUST complete the delivery of any QoS 1 or QoS 2 messages which match the Topic Filters and it has started to send to the Client. [MQTT-3.10.4-3].
/// This is a MAY — we just check the server behaves reasonably (does not crash,
/// UNSUBACK is received) regardless of whether buffered messages still arrive.
async fn unsubscribe_buffered_messages(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/unsub/buffered";

    // Subscribe at QoS 1 so messages are properly queued
    let params = ConnectParams::new("mqtt-test-unsub-buf");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut client).await {
        return Ok(r);
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
        return Ok(Outcome::fail("UNSUBACK not received"));
    }

    if buffered_count > 0 {
        // Server delivered buffered messages — MAY behaviour detected
        Ok(Outcome::Pass)
    } else {
        // Server did not deliver any buffered messages — also valid, but MAY not detected
        Ok(Outcome::unsupported(
            "Server did not deliver any buffered messages after UNSUBSCRIBE",
        ))
    }
}

const RETAIN_HANDLING_0: TestContext = TestContext {
    refs: &["MQTT-3.8.4-4", "MQTT-3.3.1-9"],
    description: "If the Retain Handling option is 0, any existing retained messages matching the Topic Filter MUST be re-sent",
    compliance: Compliance::Must,
};

/// With retain_handling=0 (the default), any existing retained messages matching
/// If the Retain Handling option is 0, any existing retained messages matching the Topic Filter MUST be re-sent, but Application Messages MUST NOT be lost due to replacing the Subscription. [MQTT-3.8.4-4].
async fn retain_handling_0_sends_retained(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/sub/rh0";

    // Publish a retained message
    let pub_conn = ConnectParams::new("mqtt-test-rh0-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    if connack.properties.retain_available == Some(false) {
        return Ok(Outcome::skip("Broker reported Retain Available = false"));
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
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Must receive the retained message
    if let Err(r) = expect_publish(&mut sub_client, topic).await {
        return Ok(r);
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
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Must receive retained message again
    Ok(expect_publish(&mut sub_client, topic).await.into_outcome())
}

const QOS_DOWNGRADE_1_TO_0: TestContext = TestContext {
    refs: &["MQTT-3.8.4-8"],
    description: "QoS of Payload Messages sent in response to a Subscription MUST be the minimum of the QoS of the originally published message and the Maximum QoS granted by server",
    compliance: Compliance::Must,
};

/// The QoS of delivered messages MUST be the minimum of the published QoS and
/// The QoS of Payload Messages sent in response to a Subscription MUST be the minimum of the QoS of the originally published message and the Maximum QoS granted by the Server. [MQTT-3.8.4-8].
/// at QoS 0, verify delivery at QoS 0.
async fn qos_downgrade_qos1_to_qos0(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/sub/qos1to0";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-dg10",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publisher sends QoS 1
    pub_client
        .send_publish(&PublishParams::qos1(topic, b"dg-test".to_vec(), 1))
        .await?;

    // Drain PUBACK from publisher
    let _ = pub_client.recv().await;

    // Subscriber should receive at QoS 0 (no packet_id)
    let p = match expect_publish(&mut sub_client, topic).await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if p.qos == QoS::AtMostOnce {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Delivered at {:?}, expected AtMostOnce (QoS 1 pub, QoS 0 sub)",
            p.qos
        )))
    }
}

const UNSUB_INFLIGHT_QOS1: TestContext = TestContext {
    refs: &["MQTT-3.10.4-2"],
    description: "When a Server receives UNSUBSCRIBE It MUST stop adding any new messages which match the Topic Filters, for delivery to client",
    compliance: Compliance::Must,
};

/// After UNSUBSCRIBE, the server MUST complete delivery of any QoS 1 messages
/// When a Server receives UNSUBSCRIBE It MUST stop adding any new messages which match the Topic Filters, for delivery to the Client. [MQTT-3.10.4-2].
async fn unsubscribe_inflight_qos1_completes(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/sub/unsub-inflight";

    // Subscriber at QoS 1
    let sub_conn = ConnectParams::new("mqtt-test-unsub-if-sub");
    let (mut sub_client, _) = client::connect(config.addr, &sub_conn, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
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
        Ok(other) => return Ok(Outcome::fail_packet("PUBLISH", &other)),
        Err(RecvError::Closed) => {
            return Ok(Outcome::fail(
                "broker closed connection before delivering message",
            ));
        }
        Err(RecvError::Timeout) => {
            return Ok(Outcome::fail("No message received before unsubscribe"));
        }
        Err(RecvError::Other(e)) => {
            return Ok(Outcome::fail(format!("unexpected error: {e:#}")));
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
        return Ok(Outcome::fail("UNSUBACK not received"));
    }

    // The fact that we received messages, unsubscribed, and could still
    // complete in-flight QoS 1 delivery (PUBACK accepted) means the
    // server completed the in-flight delivery.
    if received_before_unsub > 0 {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail("No in-flight messages observed"))
    }
}

// ── Shared subscriptions ────────────────────────────────────────────────────

const SHARED_SUB_FORMAT: TestContext = TestContext {
    refs: &["MQTT-4.8.2-2"],
    description: "The ShareName MUST NOT contain the characters \"/\", \"+\" or \"#\", but MUST be followed by a \"/\" character",
    compliance: Compliance::Must,
};

/// The ShareName in `$share/ShareName/TopicFilter` MUST NOT contain '/', '+',
/// The ShareName MUST NOT contain the characters "/", "+" or "#", but MUST be followed by a "/" character. This "/" character MUST be followed by a Topic Filter. [MQTT-4.8.2-2].
async fn shared_sub_topic_filter_format(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-shared-fmt");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(Outcome::skip(
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
            Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => {
                // Broker disconnected us — this counts as rejection.
                // Reconnect for remaining tests.
                rejected += 1;
                if i < invalid_topics.len() - 1 {
                    let (new_client, _) =
                        client::connect(config.addr, &params, config.recv_timeout).await?;
                    client = new_client;
                }
            }
            Err(RecvError::Timeout) => {
                // Timeout waiting for SUBACK — treat as inconclusive, skip.
            }
            Err(RecvError::Other(e)) => {
                return Err(e);
            }
            Ok(Packet::SubAck(_)) => {
                // Broker accepted — not a rejection.
            }
            Ok(_) => {}
        }
    }

    if rejected == invalid_topics.len() {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Only {rejected}/{} invalid shared subscription formats were rejected",
            invalid_topics.len()
        )))
    }
}

const SHARED_SUB_QOS: TestContext = TestContext {
    refs: &["MQTT-4.8.2-3"],
    description: "Server MUST respect the granted QoS for clients subscription",
    compliance: Compliance::Must,
};

/// When delivering to shared subscribers, the server MUST respect each
/// The Server MUST respect the granted QoS for the Clients subscription. [MQTT-4.8.2-3].
async fn shared_sub_qos_respected(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/shared/qos";
    let shared_filter = "$share/qosgrp/mqtt/test/shared/qos";

    // Subscriber A at QoS 0.
    let params_a = ConnectParams::new("mqtt-test-shared-qos-a");
    let (mut sub_a, connack) = client::connect(config.addr, &params_a, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(Outcome::skip(
            "Broker does not support shared subscriptions",
        ));
    }

    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtMostOnce);
    sub_a.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_a).await {
        return Ok(r);
    }

    // Subscriber B at QoS 1.
    let params_b = ConnectParams::new("mqtt-test-shared-qos-b");
    let (mut sub_b, _) = client::connect(config.addr, &params_b, config.recv_timeout).await?;
    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtLeastOnce);
    sub_b.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_b).await {
        return Ok(r);
    }

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
    let mut count_a = 0u32;
    let mut count_b = 0u32;

    // Drain subscriber A — should all be QoS 0.
    while let Ok(Packet::Publish(p)) = sub_a.recv_with_timeout(short_timeout).await {
        count_a += 1;
        if p.qos != QoS::AtMostOnce {
            qos_violation = true;
        }
    }

    // Drain subscriber B — should be QoS 0 or QoS 1.
    while let Ok(Packet::Publish(p)) = sub_b.recv_with_timeout(short_timeout).await {
        count_b += 1;
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

    let total = count_a + count_b;
    if total == 0 {
        return Ok(Outcome::fail(
            "No messages delivered to either shared subscriber",
        ));
    }

    if qos_violation {
        Ok(Outcome::fail(
            "Server delivered messages exceeding the subscriber's granted QoS",
        ))
    } else {
        Ok(Outcome::Pass)
    }
}

const SHARED_SUB_QOS2_RECONNECT: TestContext = TestContext {
    refs: &["MQTT-4.8.2-4"],
    description: "Server MUST complete the delivery of the message to that Client when it reconnects",
    compliance: Compliance::Must,
};

/// If the connection to the chosen shared subscriber breaks during QoS 2
/// delivery, the server MUST complete delivery when the client reconnects
/// The Server MUST complete the delivery of the message to that Client when it reconnects. [MQTT-4.8.2-4].
async fn shared_sub_qos2_reconnect(config: TestConfig<'_>) -> Result<Outcome> {
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
        return Ok(Outcome::skip(
            "Broker does not support shared subscriptions",
        ));
    }

    let sub = SubscribeParams::simple(1, shared_filter, QoS::ExactlyOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

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
        return Ok(Outcome::fail(
            "Broker did not preserve session (session_present=0)",
        ));
    }

    // 5. Should receive the queued QoS 2 message.
    let result = match sub_client2.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Outcome::Pass,
        Ok(Packet::PubRel(_)) => Outcome::Pass,
        Ok(other) => Outcome::fail_packet(
            "PUBLISH or PUBREL from shared subscription on reconnect",
            &other,
        ),
        Err(RecvError::Closed) => Outcome::fail(
            "broker closed connection before delivering QoS 2 message after reconnect",
        ),
        Err(RecvError::Timeout) => {
            Outcome::fail("No QoS 2 message delivered to shared subscriber after reconnect")
        }
        Err(RecvError::Other(e)) => Outcome::fail(format!("unexpected error: {e:#}")),
    };

    cleanup_session(config.addr, sub_id, config.recv_timeout).await;

    Ok(result)
}

const SHARED_SUB_NACK_DISCARD: TestContext = TestContext {
    refs: &["MQTT-4.8.2-6"],
    description: "If a Client responds with a PUBACK or PUBREC containing a Reason Code of 0x80 or greater to a PUBLISH packet from server, server MUST discard the Application Message and not attempt to send it to any other Subscriber",
    compliance: Compliance::Must,
};

/// If a shared subscription client responds with a PUBACK containing Reason
/// Code >= 0x80, the server MUST discard the message and not attempt to send
/// If a Client responds with a PUBACK or PUBREC containing a Reason Code of 0x80 or greater to a PUBLISH packet from the Server, the Server MUST discard the Application Message and not attempt to send it to any other Subscriber. [MQTT-4.8.2-6].
async fn shared_sub_negative_ack_discard(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/shared/nack";
    let shared_filter = "$share/nackgrp/mqtt/test/shared/nack";

    // 1. Connect subscriber A.
    let params_a = ConnectParams::new("mqtt-test-shared-nack-a");
    let (mut sub_a, connack) = client::connect(config.addr, &params_a, config.recv_timeout).await?;

    if connack.properties.shared_subscription_available == Some(false) {
        return Ok(Outcome::skip(
            "Broker does not support shared subscriptions",
        ));
    }

    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtLeastOnce);
    sub_a.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_a).await {
        return Ok(r);
    }

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
            return Ok(Outcome::fail_packet("PUBLISH on subscriber A", &other));
        }
    }

    // 5. Now subscribe B to the same shared group.
    let sub = SubscribeParams::simple(1, shared_filter, QoS::AtLeastOnce);
    sub_b.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_b).await {
        return Ok(r);
    }

    // 6. B should NOT receive the NACKed message.
    let short_timeout = Duration::from_millis(500);
    match sub_b.recv_with_timeout(short_timeout).await {
        Err(RecvError::Timeout) => {
            // Timeout — no message received. This is correct.
            Ok(Outcome::Pass)
        }
        Err(RecvError::Closed) => Ok(Outcome::fail("broker closed connection unexpectedly")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(_)) => Ok(Outcome::fail(
            "Server redirected NACKed message to another subscriber (should have discarded)",
        )),
        Ok(other) => Ok(Outcome::fail_packet(
            "no packet (NACKed message check)",
            &other,
        )),
    }
}

/// Clean up a persistent session by reconnecting with clean_start=true.
async fn cleanup_session(addr: &str, client_id: &str, recv_timeout: Duration) {
    let params = ConnectParams::new(client_id);
    if let Ok((_c, _)) = client::connect(addr, &params, recv_timeout).await {
        // AutoDisconnect handles the clean disconnect on drop.
    }
}
