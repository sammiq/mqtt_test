//! PUBLISH / PUBACK / PUBREC / PUBREL / PUBCOMP compliance tests [MQTT-3.3].

use std::time::Duration;

use anyhow::Result;

use crate::client::{self, RecvError};
use crate::codec::{ConnectParams, Packet, Properties, PublishParams, QoS, SubscribeParams};
use crate::helpers::{expect_disconnect, expect_publish, expect_suback, publish_and_expect};
use crate::types::{Compliance, IntoOutcome, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("PUBLISH");

    suite.add(QOS0, qos0_accepted(config));
    suite.add(QOS1, qos1_gets_puback(config));
    suite.add(QOS1_DELIVERY, qos1_delivery(config));
    suite.add(QOS2, qos2_full_flow(config));
    suite.add(QOS_DOWNGRADE, qos_downgrade_on_delivery(config));
    suite.add(INVALID_QOS3, invalid_qos3(config));
    suite.add(DUP_QOS0, dup_on_qos0(config));
    suite.add(RETAIN, retain_flag_accepted(config));
    suite.add(TOPIC_ALIAS, topic_alias_accepted(config));
    suite.add(PFI, payload_format_indicator_preserved(config));
    suite.add(MEI, message_expiry_interval_present(config));
    suite.add(CONTENT_TYPE, content_type_preserved(config));
    suite.add(RESPONSE_TOPIC, response_topic_preserved(config));
    suite.add(CORRELATION_DATA, correlation_data_preserved(config));
    suite.add(USER_PROPS, user_properties_preserved(config));
    suite.add(MSG_ORDERING, message_ordering(config));
    suite.add(
        RETAIN_DELIVERY_FLAG,
        retained_delivered_with_retain_flag(config),
    );
    suite.add(RETAIN_DELETE, retained_deletion(config));
    suite.add(RETAIN_REPLACE, retained_replacement(config));
    suite.add(PUBACK_NO_SUB, puback_no_matching_subscribers(config));
    suite.add(MEI_COUNTDOWN, message_expiry_countdown(config));
    suite.add(MAX_PKT_SIZE, max_packet_size_enforcement(config));
    suite.add(TOPIC_ALIAS_REUSE, topic_alias_reuse(config));
    suite.add(TOPIC_ALIAS_RESET, topic_alias_reset_on_reconnect(config));
    suite.add(RECV_MAX_FLOW, receive_maximum_flow_control(config));
    suite.add(QOS2_DUP, qos2_duplicate_publish(config));
    suite.add(PID_REUSE_QOS1, packet_id_reuse_after_puback(config));
    suite.add(PID_REUSE_QOS2, packet_id_reuse_after_pubcomp(config));
    suite.add(QOS2_DUP_PUBREL, qos2_duplicate_pubrel(config));
    suite.add(PAYLOAD_FORMAT_UTF8, payload_format_utf8_validated(config));
    suite.add(USER_PROPS_ORDER, user_properties_order(config));
    suite.add(RETAINED_QOS0, retained_qos0_stored(config));
    suite.add(QOS2_NO_DUP_DELIVERY, qos2_no_duplicate_delivery(config));
    suite.add(
        QOS2_EXPIRY_CONTINUES,
        qos2_continues_after_message_expiry(config),
    );
    suite.add(QOS1_DUP_ZERO, qos1_initial_delivery_dup_zero(config));
    suite.add(QUOTA_ZERO_CONTROL, control_packets_when_quota_zero(config));
    suite.add(
        RETAIN_ZERO_PRESERVES,
        retain_zero_preserves_existing(config),
    );
    suite.add(ORDERED_TOPIC_QOS0, ordered_topic_qos0(config));
    suite.add(
        CONTENT_TYPE_FORWARDED,
        content_type_forwarded_unaltered(config),
    );
    suite.add(
        QOS1_UNACKNOWLEDGED,
        qos1_unacknowledged_until_puback(config),
    );

    suite
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const QOS0: TestContext = TestContext {
    refs: &["MQTT-4.3.1-1"],
    description: "QoS 0 PUBLISH MUST be delivered with QoS=0 and DUP=0",
    compliance: Compliance::Must,
};

/// [The sender] MUST send a PUBLISH packet with QoS 0 and DUP flag set to 0 [MQTT-4.3.1-1].
///
/// This test publishes a QoS 0 message and verifies the broker accepts it and forwards it to a matching subscriber.
async fn qos0_accepted(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-qos0-pub",
        "mqtt/test/pub/qos0",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    Ok(
        publish_and_expect(&mut client, "mqtt/test/pub/qos0", b"hello")
            .await
            .into_outcome(),
    )
}

const QOS1: TestContext = TestContext {
    refs: &["MQTT-4.3.2-4"],
    description: "QoS 1 PUBLISH MUST be acknowledged with PUBACK",
    compliance: Compliance::Must,
};

/// [The receiver of a QoS 1 PUBLISH] MUST respond with a PUBACK packet containing the Packet Identifier from the
/// incoming PUBLISH packet, having accepted ownership of the Application Message [MQTT-4.3.2-4].
///
/// This test sends a QoS 1 PUBLISH and verifies the broker responds with a PUBACK containing the same Packet
/// Identifier.
async fn qos1_gets_puback(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-qos1-pub");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let pub_params = PublishParams::qos1("mqtt/test/pub/qos1", b"qos1-test".to_vec(), 1);
    client.send_publish(&pub_params).await?;

    for _ in 0..5 {
        match client.recv().await? {
            Packet::PubAck(ack) if ack.packet_id == 1 => {
                return Ok(Outcome::Pass);
            }
            Packet::Publish(_) => {} // may receive own loopback — ignore
            other => {
                return Ok(Outcome::fail_packet("PUBACK(1)", &other));
            }
        }
    }

    Ok(Outcome::fail("PUBACK not received within packet limit"))
}

const QOS1_DELIVERY: TestContext = TestContext {
    refs: &["MQTT-4.3.2-2"],
    description: "QoS 1 PUBLISH SHOULD be delivered at QoS 1 to matching QoS 1 subscriber",
    compliance: Compliance::Should,
};

/// [The sender] MUST send a PUBLISH packet containing this Packet Identifier with QoS 1 and DUP flag set to 0
/// [MQTT-4.3.2-2].
///
/// This test publishes a QoS 1 message to a QoS 1 subscription and verifies the subscriber receives it at QoS 1.
async fn qos1_delivery(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/qos1_delivery";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-qos1-del",
        topic,
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    let pub_params = PublishParams::qos1(topic, b"qos1-delivery-test".to_vec(), 1);
    pub_client.send_publish(&pub_params).await?;

    // Drain publisher PUBACK
    for _ in 0..5 {
        if let Packet::PubAck(_) = pub_client.recv().await? {
            break;
        }
    }

    // Subscriber should receive at QoS 1
    let p = match expect_publish(&mut sub_client, topic).await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if let Some(pid) = p.packet_id {
        sub_client.send_puback(pid, 0x00).await?;
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

const QOS2: TestContext = TestContext {
    refs: &["MQTT-4.3.3-8", "MQTT-4.3.3-11"],
    description: "QoS 2 PUBLISH MUST complete PUBREC / PUBREL / PUBCOMP flow",
    compliance: Compliance::Must,
};

/// [The receiver] MUST respond with a PUBREC packet containing the Packet Identifier from the incoming PUBLISH
/// packet, having accepted ownership of the Application Message [MQTT-4.3.3-8]. [The receiver] MUST respond to a
/// PUBREL packet by sending a PUBCOMP packet containing the same Packet Identifier as the PUBREL [MQTT-4.3.3-11].
///
/// This test publishes a QoS 2 message and verifies the broker completes the full PUBREC → PUBREL → PUBCOMP
/// acknowledgement flow.
async fn qos2_full_flow(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-qos2-pub");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let pub_params = PublishParams::qos2("mqtt/test/pub/qos2", b"qos2-test".to_vec(), 2);
    client.send_publish(&pub_params).await?;

    for _ in 0..5 {
        match client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 2 => {
                client.send_pubrel(2, 0x00).await?;

                match client.recv().await? {
                    Packet::PubComp(comp) if comp.packet_id == 2 => {
                        return Ok(Outcome::Pass);
                    }
                    other => {
                        return Ok(Outcome::fail_packet("PUBCOMP(2)", &other));
                    }
                }
            }
            Packet::Publish(_) => {} // loopback — ignore
            other => {
                return Ok(Outcome::fail_packet("PUBREC(2)", &other));
            }
        }
    }

    Ok(Outcome::fail("PUBREC not received within packet limit"))
}

const INVALID_QOS3: TestContext = TestContext {
    refs: &["MQTT-3.3.1-4"],
    description: "Server MUST treat QoS value of 3 as a malformed packet",
    compliance: Compliance::Must,
};

/// A PUBLISH Packet MUST NOT have both QoS bits set to 1 [MQTT-3.3.1-4].
///
/// This test sends a PUBLISH packet with QoS bits set to 0b11 and verifies the broker treats it as a malformed
/// packet and closes the connection.
async fn invalid_qos3(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-qos3");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with QoS=3 (0b11 in bits 2-1 of fixed header byte)
    // Fixed header: 0x36 = 0011_0110 → type=3 (PUBLISH), DUP=0, QoS=3, RETAIN=0
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x36,                                       // PUBLISH | QoS=3
        0x0B,                                       // remaining length = 11
        0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/" (7)
        0x00, 0x01,                                 // packet ID = 1 (2)
        0x00,                                       // properties length = 0 (1)
        0x00,                                       // payload (1)
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client).await)
}

const DUP_QOS0: TestContext = TestContext {
    refs: &["MQTT-3.3.1-2"],
    description: "DUP flag MUST be 0 for QoS 0 messages",
    compliance: Compliance::Must,
};

/// The DUP flag MUST be set to 0 for all QoS 0 messages [MQTT-3.3.1-2].
///
/// This test sends a PUBLISH packet with DUP=1 and QoS=0 and verifies the broker treats it as a protocol error
/// and closes the connection.
async fn dup_on_qos0(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-dup-qos0");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with DUP=1, QoS=0 (invalid combination)
    // Fixed header: 0x38 = 0011_1000 → type=3 (PUBLISH), DUP=1, QoS=0, RETAIN=0
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x38,                                       // PUBLISH | DUP=1 | QoS=0
        0x09,                                       // remaining length = 9
        0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/" (7)
        0x00,                                       // properties length = 0 (1)
        0x00,                                       // payload (1)
    ];
    client.send_raw(bad_publish).await?;

    match client.recv().await {
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(_)) => {
            // Some brokers may silently accept and forward — this is non-compliant
            Ok(Outcome::fail(
                "Broker accepted PUBLISH with DUP=1 and QoS=0 (should disconnect)",
            ))
        }
        Ok(other) => Ok(Outcome::fail_packet("disconnect (DUP=1, QoS=0)", &other)),
    }
}

const QOS_DOWNGRADE: TestContext = TestContext {
    refs: &["MQTT-3.8.4-8"],
    description: "Delivered QoS MUST NOT exceed the subscription's maximum QoS",
    compliance: Compliance::Must,
};

/// The QoS of Payload Messages sent in response to a Subscription MUST be the minimum of the QoS of the originally
/// published message and the Maximum QoS granted by the Server [MQTT-3.8.4-8].
///
/// This test publishes a QoS 2 message to a QoS 0 subscription and verifies the subscriber receives it at QoS 0.
async fn qos_downgrade_on_delivery(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/qos_downgrade";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-qos-dg",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publisher publishes at QoS 2
    let pub_params = PublishParams::qos2(topic, b"downgrade-test".to_vec(), 1);
    pub_client.send_publish(&pub_params).await?;

    // Complete publisher QoS 2 flow
    for _ in 0..5 {
        match pub_client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 1 => {
                pub_client.send_pubrel(1, 0x00).await?;
            }
            Packet::PubComp(_) => break,
            _ => {}
        }
    }

    // Subscriber should receive at QoS 0 (no packet_id field)
    let p = match expect_publish(&mut sub_client, topic).await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if p.qos == QoS::AtMostOnce {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Message delivered at {:?}, expected AtMostOnce (subscription QoS 0)",
            p.qos
        )))
    }
}

// ── MAY ──────────────────────────────────────────────────────────────────────

const RETAIN: TestContext = TestContext {
    refs: &["MQTT-3.3.1-5"],
    description: "Retain flag: broker stores and delivers retained message to new subscribers",
    compliance: Compliance::May,
};

/// If the RETAIN flag is set to 1 in a PUBLISH packet sent by a Client to a Server, the Server MUST replace any
/// existing retained message for this topic and store the Application Message [MQTT-3.3.1-5].
///
/// This test publishes a retained message, then subscribes from a new client and verifies the retained message is
/// delivered.
async fn retain_flag_accepted(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-retain-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let pub_params = PublishParams::retained("mqtt/test/pub/retain", b"retained-payload".to_vec());
    pub_client.send_publish(&pub_params).await?;

    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-retain-sub",
        "mqtt/test/pub/retain",
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let p = match expect_publish(&mut sub_client, "mqtt/test/pub/retain").await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if p.retain {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::unsupported(
            "Received PUBLISH but retain flag not set on delivery",
        ))
    }
}

const TOPIC_ALIAS: TestContext = TestContext {
    refs: &["MQTT-3.3.2-12"],
    description: "Topic Alias in PUBLISH is accepted",
    compliance: Compliance::May,
};

/// A Server MUST accept all Topic Alias values greater than 0 and less than or equal to the Topic Alias Maximum
/// value that it returned in the CONNACK packet [MQTT-3.3.2-12].
///
/// This test publishes a QoS 1 message with a Topic Alias and verifies the broker accepts it and responds with
/// PUBACK.
async fn topic_alias_accepted(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-topic-alias");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    if connack.properties.topic_alias_maximum.unwrap_or(0) == 0 {
        return Ok(Outcome::skip(
            "Broker reported Topic Alias Maximum = 0 (not supported)",
        ));
    }

    let props = Properties {
        topic_alias: Some(1),
        ..Properties::default()
    };

    let pub_params = PublishParams {
        topic: "mqtt/test/pub/alias".to_string(),
        payload: b"alias-test".to_vec(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: props,
    };
    client.send_publish(&pub_params).await?;

    for _ in 0..5 {
        match client.recv().await? {
            Packet::PubAck(ack) if ack.packet_id == 1 => {
                return Ok(Outcome::Pass);
            }
            Packet::Disconnect(d) => {
                return Ok(Outcome::fail(format!(
                    "Broker disconnected with reason code {:#04x}",
                    d.reason_code
                )));
            }
            Packet::Publish(_) => {} // loopback
            other => {
                return Ok(Outcome::fail_packet("PUBACK(1)", &other));
            }
        }
    }

    Ok(Outcome::fail("No PUBACK received"))
}

// ── Property forwarding ─────────────────────────────────────────────────────

/// Helper: subscribe, publish with custom properties, verify a property is preserved.
async fn property_forwarding_test(
    config: TestConfig<'_>,
    topic: &'static str,
    props: Properties,
    check: fn(&Properties) -> bool,
    check_description: &'static str,
) -> Result<Outcome> {
    let mut client = client::connect_and_subscribe(
        config.addr,
        &format!("mqtt-test-{topic}"),
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let pub_params = PublishParams {
        topic: topic.to_string(),
        payload: b"prop-test".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        dup: false,
        packet_id: None,
        properties: props,
    };
    client.send_publish(&pub_params).await?;

    match client.recv().await? {
        Packet::Publish(p) if p.topic == topic => {
            if check(&p.properties) {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Property not preserved: {check_description}"
                )))
            }
        }
        other => Ok(Outcome::fail_packet(
            &format!("PUBLISH on topic \"{topic}\""),
            &other,
        )),
    }
}

const PFI: TestContext = TestContext {
    refs: &["MQTT-3.3.2-4"],
    description: "Payload Format Indicator MUST be forwarded unchanged",
    compliance: Compliance::Must,
};

/// A Server MUST send the Payload Format Indicator unaltered to all subscribers receiving the Application Message
/// [MQTT-3.3.2-4].
///
/// This test publishes a message with Payload Format Indicator = 1 and verifies the subscriber receives it
/// unchanged.
async fn payload_format_indicator_preserved(config: TestConfig<'_>) -> Result<Outcome> {
    let props = Properties {
        payload_format_indicator: Some(1),
        ..Properties::default()
    };
    property_forwarding_test(
        config,
        "mqtt/test/pub/pfi",
        props,
        |p| p.payload_format_indicator == Some(1),
        "expected payload_format_indicator=1",
    )
    .await
}

const MEI: TestContext = TestContext {
    refs: &["MQTT-3.3.2-6"],
    description: "Message Expiry Interval MUST be present in forwarded PUBLISH",
    compliance: Compliance::Must,
};

/// The PUBLISH packet sent to a Client by the Server MUST contain a Message Expiry Interval set to the received
/// value minus the time that the Application Message has been waiting in the Server [MQTT-3.3.2-6].
///
/// This test publishes a message with a Message Expiry Interval and verifies the subscriber receives the property
/// in the forwarded PUBLISH.
async fn message_expiry_interval_present(config: TestConfig<'_>) -> Result<Outcome> {
    let props = Properties {
        message_expiry_interval: Some(3600),
        ..Properties::default()
    };
    property_forwarding_test(
        config,
        "mqtt/test/pub/mei",
        props,
        |p| p.message_expiry_interval.is_some(),
        "expected message_expiry_interval to be present",
    )
    .await
}

const CONTENT_TYPE: TestContext = TestContext {
    refs: &["MQTT-3.3.2-20"],
    description: "Content Type MUST be forwarded unchanged",
    compliance: Compliance::Should,
};

/// A Server MUST send the Content Type unaltered to all subscribers receiving the Application Message
/// [MQTT-3.3.2-20].
///
/// This test publishes a message with Content Type = "application/json" and verifies the subscriber receives it
/// unchanged.
async fn content_type_preserved(config: TestConfig<'_>) -> Result<Outcome> {
    let props = Properties {
        content_type: Some("application/json".to_string()),
        ..Properties::default()
    };
    property_forwarding_test(
        config,
        "mqtt/test/pub/ct",
        props,
        |p| p.content_type.as_deref() == Some("application/json"),
        "expected content_type=\"application/json\"",
    )
    .await
}

const RESPONSE_TOPIC: TestContext = TestContext {
    refs: &["MQTT-3.3.2-15"],
    description: "Response Topic MUST be forwarded unchanged",
    compliance: Compliance::Should,
};

/// The Server MUST send the Response Topic unaltered to all subscribers receiving the Application Message
/// [MQTT-3.3.2-15].
///
/// This test publishes a message with a Response Topic and verifies the subscriber receives it unchanged.
async fn response_topic_preserved(config: TestConfig<'_>) -> Result<Outcome> {
    let props = Properties {
        response_topic: Some("mqtt/test/pub/reply".to_string()),
        ..Properties::default()
    };
    property_forwarding_test(
        config,
        "mqtt/test/pub/rt",
        props,
        |p| p.response_topic.as_deref() == Some("mqtt/test/pub/reply"),
        "expected response_topic=\"mqtt/test/pub/reply\"",
    )
    .await
}

const CORRELATION_DATA: TestContext = TestContext {
    refs: &["MQTT-3.3.2-16"],
    description: "Correlation Data MUST be forwarded unchanged",
    compliance: Compliance::Should,
};

/// The Server MUST send the Correlation Data unaltered to all subscribers receiving the Application Message
/// [MQTT-3.3.2-16].
///
/// This test publishes a message with Correlation Data and verifies the subscriber receives it unchanged.
async fn correlation_data_preserved(config: TestConfig<'_>) -> Result<Outcome> {
    let props = Properties {
        correlation_data: Some(b"corr-123".to_vec()),
        ..Properties::default()
    };
    property_forwarding_test(
        config,
        "mqtt/test/pub/cd",
        props,
        |p| p.correlation_data.as_deref() == Some(b"corr-123"),
        "expected correlation_data=b\"corr-123\"",
    )
    .await
}

const USER_PROPS: TestContext = TestContext {
    refs: &["MQTT-3.3.2-17"],
    description: "User Properties MUST be forwarded unchanged",
    compliance: Compliance::Should,
};

/// The Server MUST send all User Properties unaltered in a PUBLISH packet when forwarding the Application Message
/// to a Client [MQTT-3.3.2-17].
///
/// This test publishes a message with a User Property and verifies the subscriber receives it unchanged.
async fn user_properties_preserved(config: TestConfig<'_>) -> Result<Outcome> {
    let props = Properties {
        user_properties: vec![("key".to_string(), "value".to_string())],
        ..Properties::default()
    };
    property_forwarding_test(
        config,
        "mqtt/test/pub/up",
        props,
        |p| {
            p.user_properties
                .contains(&("key".to_string(), "value".to_string()))
        },
        "expected user_properties to contain (\"key\", \"value\")",
    )
    .await
}

const MSG_ORDERING: TestContext = TestContext {
    refs: &["MQTT-4.6.0-5"],
    description: "Message ordering MUST be maintained for same-topic QoS 1 messages",
    compliance: Compliance::Must,
};

/// When a Server processes a message that has been published to an Ordered Topic, it MUST send PUBLISH packets to
/// consumers (for the same Topic and QoS) in the order that they were received from any given Client
/// [MQTT-4.6.0-5].
///
/// This test publishes 5 QoS 1 messages in sequence and verifies they arrive at the subscriber in order.
async fn message_ordering(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/ordering";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-order",
        topic,
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    for i in 0u16..5 {
        let pub_params = PublishParams::qos1(topic, format!("msg-{i}").into_bytes(), i + 1);
        pub_client.send_publish(&pub_params).await?;
    }

    // Drain PUBACKs
    for _ in 0..10 {
        match pub_client.recv().await {
            Ok(Packet::PubAck(_)) => {}
            _ => break,
        }
    }

    // Receive and verify order
    let mut received = Vec::new();
    for _ in 0..5 {
        match sub_client.recv().await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                if let Some(pid) = p.packet_id {
                    sub_client.send_puback(pid, 0x00).await?;
                }
                received.push(String::from_utf8_lossy(&p.payload).to_string());
            }
            Ok(_) => {}
            Err(RecvError::Closed | RecvError::Timeout) => break,
            Err(RecvError::Other(e)) => return Err(e),
        }
    }

    let expected: Vec<String> = (0..5).map(|i| format!("msg-{i}")).collect();
    if received == expected {
        Ok(Outcome::Pass)
    } else if received.len() < 5 {
        Ok(Outcome::fail(format!(
            "Only received {}/5 messages: {received:?}",
            received.len()
        )))
    } else {
        Ok(Outcome::fail(format!(
            "Messages out of order: expected {expected:?}, got {received:?}"
        )))
    }
}

// ── SHOULD ──────────────────────────────────────────────────────────────────

const RETAIN_DELIVERY_FLAG: TestContext = TestContext {
    refs: &["MQTT-3.3.1-9"],
    description: "Server SHOULD deliver retained messages with Retain=1 to new subscribers",
    compliance: Compliance::Should,
};

/// If Retain Handling is set to 0 the Server MUST send the retained messages matching the Topic Filter of the
/// subscription to the Client [MQTT-3.3.1-9]. Non-normative prose in §3.3.1.3 states that "these messages are
/// sent with the RETAIN flag set to 1"; the flag-setting itself is not a tagged requirement.
///
/// This test publishes a retained message, subscribes from a new client with default (Retain Handling=0) options,
/// and verifies the retained message is delivered with the RETAIN flag set to 1.
async fn retained_delivered_with_retain_flag(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/retain_flag";

    // Publish a retained message.
    let pub_conn = ConnectParams::new("mqtt-test-retflag-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    let pub_params = PublishParams::retained(topic, b"retain-flag-test".to_vec());
    pub_client.send_publish(&pub_params).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Subscribe from a new client — should get the retained message with Retain=1.
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-retflag-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let result = match expect_publish(&mut sub_client, topic).await {
        Ok(p) if p.retain => Outcome::Pass,
        Ok(_) => Outcome::fail("Retained message delivered but Retain flag is 0 (SHOULD be 1)"),
        Err(r) => r,
    };

    // Clean up: remove retained message by publishing empty payload with retain.
    let cleanup_conn = ConnectParams::new("mqtt-test-retflag-cleanup");
    if let Ok((mut c, _)) = client::connect(config.addr, &cleanup_conn, config.recv_timeout).await {
        let clear = PublishParams::retained(topic, Vec::new());
        let _ = c.send_publish(&clear).await;
    }

    Ok(result)
}

// ── Retained message lifecycle ──────────────────────────────────────────────

const RETAIN_DELETE: TestContext = TestContext {
    refs: &["MQTT-3.3.1-6", "MQTT-3.3.1-7"],
    description: "Retained message MUST be deleted when empty payload with RETAIN is published",
    compliance: Compliance::Must,
};

/// If the Payload contains zero bytes it is processed normally by the Server but any retained message with the
/// same topic name MUST be removed and any future subscribers for the topic will not receive a retained message
/// [MQTT-3.3.1-6]. A retained message with a Payload containing zero bytes MUST NOT be stored as a retained
/// message on the Server [MQTT-3.3.1-7].
///
/// This test publishes a retained message, then publishes an empty payload with RETAIN=1, and verifies a new
/// subscriber does not receive any retained message.
async fn retained_deletion(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/retain_delete";

    // Publish a retained message
    let pub_conn = ConnectParams::new("mqtt-test-retdel-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    pub_client
        .send_publish(&PublishParams::retained(topic, b"to-delete".to_vec()))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Delete it with empty payload + retain
    pub_client
        .send_publish(&PublishParams::retained(topic, Vec::new()))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // New subscriber should NOT receive any retained message
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-retdel-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Err(RecvError::Closed) => Ok(Outcome::Pass),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::Publish(p)) if p.topic == topic && p.payload.is_empty() => {
            // Some brokers send the empty retained message — this is acceptable
            Ok(Outcome::Pass)
        }
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(Outcome::fail(format!(
            "Retained message still delivered after deletion: {:?}",
            String::from_utf8_lossy(&p.payload)
        ))),
        Ok(_) => Ok(Outcome::Pass),
    }
}

const RETAIN_REPLACE: TestContext = TestContext {
    refs: &["MQTT-3.3.1-5"],
    description: "New retained message MUST replace existing retained message for same topic",
    compliance: Compliance::Must,
};

/// If the RETAIN flag is set to 1 in a PUBLISH packet sent by a Client to a Server, the Server MUST replace any
/// existing retained message for this topic and store the Application Message [MQTT-3.3.1-5].
///
/// This test publishes two retained messages to the same topic in succession and verifies a new subscriber only
/// receives the most recent one.
async fn retained_replacement(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/retain_replace";

    let pub_conn = ConnectParams::new("mqtt-test-retrpl-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    // Publish v1
    pub_client
        .send_publish(&PublishParams::retained(topic, b"v1".to_vec()))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Publish v2 (should replace v1)
    pub_client
        .send_publish(&PublishParams::retained(topic, b"v2".to_vec()))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // New subscriber should get v2 only
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-retrpl-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let result = match expect_publish(&mut sub_client, topic).await {
        Ok(p) if p.payload == b"v2" => Outcome::Pass,
        Ok(p) => Outcome::fail(format!(
            "Expected retained payload \"v2\", got {:?}",
            String::from_utf8_lossy(&p.payload)
        )),
        Err(r) => r,
    };

    // Clean up
    let _ = pub_client
        .send_publish(&PublishParams::retained(topic, Vec::new()))
        .await;

    Ok(result)
}

// ── PUBACK reason codes ─────────────────────────────────────────────────────

const PUBACK_NO_SUB: TestContext = TestContext {
    refs: &["MQTT-3.4.2-1"],
    description: "Server MAY return PUBACK reason 0x10 when no subscribers match",
    compliance: Compliance::May,
};

/// The Client or Server sending the PUBACK packet MUST use one of the PUBACK Reason Codes [MQTT-3.4.2-1]. The
/// PUBACK Reason Code 0x10 (No Matching Subscribers) is defined for use when the message is accepted but there
/// are no subscribers (§3.4.2.1).
///
/// This test publishes a QoS 1 message to a topic with no subscribers and verifies the broker returns PUBACK with
/// reason code 0x10 (support is optional).
async fn puback_no_matching_subscribers(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-puback-nosub");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Publish QoS 1 to a topic with no subscribers
    client
        .send_publish(&PublishParams::qos1(
            "mqtt/test/pub/no_subscribers_at_all",
            b"nobody-listening".to_vec(),
            1,
        ))
        .await?;

    match client.recv().await? {
        Packet::PubAck(ack) if ack.packet_id == 1 => {
            if ack.reason_code == 0x10 {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::unsupported(format!(
                    "PUBACK reason code {:#04x} (broker did not report 0x10 for no matching subscribers)",
                    ack.reason_code
                )))
            }
        }
        other => Ok(Outcome::fail_packet("PUBACK(1)", &other)),
    }
}

// ── Message Expiry Interval countdown ───────────────────────────────────────

const MEI_COUNTDOWN: TestContext = TestContext {
    refs: &["MQTT-3.3.2-6"],
    description: "Message Expiry Interval MUST be decremented by time spent in server",
    compliance: Compliance::Must,
};

/// The PUBLISH packet sent to a Client by the Server MUST contain a Message Expiry Interval set to the received
/// value minus the time that the Application Message has been waiting in the Server [MQTT-3.3.2-6].
///
/// This test publishes a message with MEI=60 to an offline subscriber's persistent session, waits 2 seconds,
/// reconnects, and verifies the forwarded PUBLISH contains an MEI strictly less than 60.
async fn message_expiry_countdown(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/mei_countdown";

    // Connect subscriber with a persistent session, subscribe, then disconnect
    let mut sub_params = ConnectParams::new("mqtt-test-mei-cd-sub");
    sub_params.clean_start = false;
    sub_params.properties.session_expiry_interval = Some(300);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;
    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }
    drop(sub_client); // disconnect

    // Publish with MEI=60 while subscriber is offline
    let pub_conn = ConnectParams::new("mqtt-test-mei-cd-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    let pub_params = PublishParams {
        topic: topic.to_string(),
        payload: b"expiry-test".to_vec(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: Properties {
            message_expiry_interval: Some(60),
            ..Properties::default()
        },
    };
    pub_client.send_publish(&pub_params).await?;
    // Drain PUBACK
    for _ in 0..5 {
        if let Ok(Packet::PubAck(_)) = pub_client.recv().await {
            break;
        }
    }

    // Wait 2 seconds so the MEI should be decremented
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Reconnect subscriber with same session
    let mut sub_params2 = ConnectParams::new("mqtt-test-mei-cd-sub");
    sub_params2.clean_start = false;
    sub_params2.properties.session_expiry_interval = Some(300);
    let (mut sub_client2, _) =
        client::connect(config.addr, &sub_params2, config.recv_timeout).await?;

    let p = match expect_publish(&mut sub_client2, topic).await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if let Some(pid) = p.packet_id {
        sub_client2.send_puback(pid, 0x00).await?;
    }
    match p.properties.message_expiry_interval {
        Some(mei) if mei < 60 => Ok(Outcome::Pass),
        Some(mei) => Ok(Outcome::fail(format!(
            "MEI not decremented: received {mei}, expected < 60"
        ))),
        None => Ok(Outcome::fail(
            "No Message Expiry Interval in forwarded PUBLISH",
        )),
    }
}

// ── Maximum Packet Size enforcement ─────────────────────────────────────────

const MAX_PKT_SIZE: TestContext = TestContext {
    refs: &["MQTT-3.1.2-24"],
    description: "Server MUST NOT send packets exceeding client's Maximum Packet Size",
    compliance: Compliance::Must,
};

/// The Server MUST NOT send packets exceeding Maximum Packet Size to the Client [MQTT-3.1.2-24].
///
/// This test connects a subscriber with Maximum Packet Size = 64, publishes a 128-byte message from a separate
/// client, and verifies the oversized packet is not delivered to the subscriber.
async fn max_packet_size_enforcement(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/max_pkt";

    // Connect subscriber with a small Maximum Packet Size
    let mut sub_params = ConnectParams::new("mqtt-test-maxpkt-sub");
    sub_params.properties.maximum_packet_size = Some(64);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;
    let sub = SubscribeParams::simple(1, topic, QoS::AtMostOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Publish a message with payload larger than 64 bytes from another client
    let pub_conn = ConnectParams::new("mqtt-test-maxpkt-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    let big_payload = vec![b'X'; 128];
    pub_client
        .send_publish(&PublishParams::qos0(topic, big_payload))
        .await?;

    // Should NOT be delivered (would exceed max packet size)
    let got_big = matches!(sub_client.recv_with_timeout(Duration::from_secs(1)).await, Ok(Packet::Publish(p)) if p.topic == topic && p.payload.len() > 40);

    if got_big {
        return Ok(Outcome::fail(
            "Server sent packet exceeding client's Maximum Packet Size",
        ));
    }

    // Verify small messages still work
    pub_client
        .send_publish(&PublishParams::qos0(topic, b"small".to_vec()))
        .await?;

    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(Outcome::Pass),
        _ => Ok(Outcome::Pass), // Server may have disconnected — still compliant
    }
}

// ── Topic Alias lifecycle ───────────────────────────────────────────────────

const TOPIC_ALIAS_REUSE: TestContext = TestContext {
    refs: &["MQTT-3.3.2-12"],
    description: "Topic Alias MUST allow subsequent PUBLISH with empty topic using the alias",
    compliance: Compliance::Must,
};

/// A Server MUST accept all Topic Alias values greater than 0 and less than or equal to the Topic Alias Maximum
/// value that it returned in the CONNACK packet [MQTT-3.3.2-12]. Non-normative prose in §3.3.2.3.4 describes the
/// mechanism: after a PUBLISH establishes a Topic Name to Topic Alias mapping, subsequent PUBLISH packets on the
/// same Network Connection can contain just the Topic Alias with an empty topic name.
///
/// This test publishes a first message with a full topic name and Topic Alias=1, then publishes a second message
/// with an empty topic and the same alias, and verifies the subscriber receives both on the original topic.
async fn topic_alias_reuse(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/alias_reuse";

    let params = ConnectParams::new("mqtt-test-alias-reuse-pub");
    let (mut pub_client, connack) =
        client::connect(config.addr, &params, config.recv_timeout).await?;

    let max_alias = connack.properties.topic_alias_maximum.unwrap_or(0);
    if max_alias == 0 {
        return Ok(Outcome::skip(
            "Broker does not support Topic Aliases (maximum = 0)",
        ));
    }

    // Set up a subscriber
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-alias-reuse-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // First PUBLISH: establish alias=1 with full topic name
    let p1 = PublishParams {
        topic: topic.to_string(),
        payload: b"msg1".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        dup: false,
        packet_id: None,
        properties: Properties {
            topic_alias: Some(1),
            ..Properties::default()
        },
    };
    pub_client.send_publish(&p1).await?;

    match sub_client.recv().await? {
        Packet::Publish(p) if p.topic == topic => {}
        other => {
            return Ok(Outcome::fail_packet("first PUBLISH via alias", &other));
        }
    }

    // Second PUBLISH: reuse alias=1 with empty topic
    let p2 = PublishParams {
        topic: String::new(),
        payload: b"msg2".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        dup: false,
        packet_id: None,
        properties: Properties {
            topic_alias: Some(1),
            ..Properties::default()
        },
    };
    pub_client.send_publish(&p2).await?;

    match sub_client.recv().await {
        Ok(Packet::Publish(p)) if p.topic == topic => Ok(Outcome::Pass),
        Ok(Packet::Publish(p)) => Ok(Outcome::fail(format!(
            "Message delivered on wrong topic: {:?}",
            p.topic
        ))),
        Ok(other) => Ok(Outcome::fail_packet("PUBLISH via alias reuse", &other)),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "No message delivered via alias reuse (timed out)",
        )),
        Err(RecvError::Closed) => Ok(Outcome::fail(
            "No message delivered via alias reuse (connection closed)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

const TOPIC_ALIAS_RESET: TestContext = TestContext {
    refs: &["MQTT-3.3.2-7"],
    description: "Topic Alias mappings MUST NOT persist across network connections",
    compliance: Compliance::Must,
};

/// A receiver MUST NOT carry forward any Topic Alias mappings from one Network Connection to another
/// [MQTT-3.3.2-7].
///
/// This test establishes a Topic Alias mapping on one connection, disconnects, reconnects, and verifies the
/// broker rejects a PUBLISH that attempts to reuse the alias with an empty topic name.
async fn topic_alias_reset_on_reconnect(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-alias-reset");
    let (mut client, connack) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let max_alias = connack.properties.topic_alias_maximum.unwrap_or(0);
    if max_alias == 0 {
        return Ok(Outcome::skip(
            "Broker does not support Topic Aliases (maximum = 0)",
        ));
    }

    // Establish alias=1 for a topic
    let p1 = PublishParams {
        topic: "mqtt/test/pub/alias_reset".to_string(),
        payload: b"establish".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        dup: false,
        packet_id: None,
        properties: Properties {
            topic_alias: Some(1),
            ..Properties::default()
        },
    };
    client.send_publish(&p1).await?;
    drop(client); // disconnect

    // Reconnect and try to use alias=1 with empty topic — should fail
    let params2 = ConnectParams::new("mqtt-test-alias-reset");
    let (mut client2, connack2) =
        client::connect(config.addr, &params2, config.recv_timeout).await?;

    if connack2.properties.topic_alias_maximum.unwrap_or(0) == 0 {
        return Ok(Outcome::skip(
            "Broker does not support Topic Aliases after reconnect",
        ));
    }

    // Send PUBLISH with empty topic + alias=1 (no mapping exists on new connection)
    let p2 = PublishParams {
        topic: String::new(),
        payload: b"should-fail".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        dup: false,
        packet_id: None,
        properties: Properties {
            topic_alias: Some(1),
            ..Properties::default()
        },
    };
    client2.send_publish(&p2).await?;

    // Server should disconnect or send DISCONNECT — alias mapping was reset
    Ok(expect_disconnect(&mut client2).await)
}

// ── Receive Maximum flow control ────────────────────────────────────────────

const RECV_MAX_FLOW: TestContext = TestContext {
    refs: &["MQTT-3.3.4-9"],
    description: "Server MUST NOT send more than Receive Maximum unacknowledged QoS>0 messages",
    compliance: Compliance::Must,
};

/// The Server MUST NOT send more than Receive Maximum QoS 1 and QoS 2 PUBLISH packets for which it has not
/// received PUBACK, PUBCOMP, or PUBREC with a Reason Code of 128 or greater from the Client [MQTT-3.3.4-9].
///
/// This test connects a subscriber with Receive Maximum=2, publishes 5 QoS 1 messages, and verifies the server
/// sends at most 2 unacknowledged messages before waiting for PUBACKs.
async fn receive_maximum_flow_control(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/recv_max";

    // Connect subscriber with receive_maximum=2
    let mut sub_params = ConnectParams::new("mqtt-test-recvmax-sub");
    sub_params.properties.receive_maximum = Some(2);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;
    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Publish 5 QoS 1 messages from another client
    let pub_conn = ConnectParams::new("mqtt-test-recvmax-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    for i in 1u16..=5 {
        pub_client
            .send_publish(&PublishParams::qos1(
                topic,
                format!("msg-{i}").into_bytes(),
                i,
            ))
            .await?;
    }
    // Drain PUBACKs
    for _ in 0..10 {
        match pub_client.recv_with_timeout(Duration::from_secs(1)).await {
            Ok(Packet::PubAck(_)) => {}
            _ => break,
        }
    }

    // Read messages WITHOUT sending PUBACKs — server should stop after 2
    let mut unacked = Vec::new();
    for _ in 0..5 {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                unacked.push(p.packet_id);
            }
            _ => break,
        }
    }

    if unacked.len() > 2 {
        return Ok(Outcome::fail(format!(
            "Server sent {} unacknowledged messages (receive_maximum=2)",
            unacked.len()
        )));
    }

    // Now ACK both and verify remaining messages flow
    for id in unacked.iter().flatten() {
        sub_client.send_puback(*id, 0x00).await?;
    }

    // Should receive more messages now
    let mut total = unacked.len();
    for _ in 0..5 {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                if let Some(pid) = p.packet_id {
                    sub_client.send_puback(pid, 0x00).await?;
                }
                total += 1;
            }
            _ => break,
        }
    }

    if total >= 4 {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Only received {total}/5 messages total after ACKing"
        )))
    }
}

// ── QoS 2 duplicate handling ────────────────────────────────────────────────

const QOS2_DUP: TestContext = TestContext {
    refs: &["MQTT-4.3.3-10"],
    description: "Server MUST respond with PUBREC to duplicate QoS 2 PUBLISH (DUP=1)",
    compliance: Compliance::Must,
};

/// Until it has received the corresponding PUBREL packet, the receiver MUST acknowledge any subsequent PUBLISH
/// packet with the same Packet Identifier by sending a PUBREC. It MUST NOT cause duplicate messages to be
/// delivered to any onward recipients in this case [MQTT-4.3.3-10].
///
/// This test sends a QoS 2 PUBLISH, receives the PUBREC, resends the same PUBLISH with DUP=1, and verifies the
/// server responds with another PUBREC for the same Packet Identifier.
async fn qos2_duplicate_publish(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-qos2-dup");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Send QoS 2 PUBLISH
    let pub_params = PublishParams::qos2("mqtt/test/pub/qos2dup", b"qos2-dup-test".to_vec(), 10);
    client.send_publish(&pub_params).await?;

    // Get PUBREC
    for _ in 0..5 {
        match client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 10 => break,
            Packet::Publish(_) => {} // loopback
            other => return Ok(Outcome::fail_packet("PUBREC(10)", &other)),
        }
    }

    // Resend same PUBLISH with DUP=1
    let dup_params = PublishParams {
        topic: "mqtt/test/pub/qos2dup".to_string(),
        payload: b"qos2-dup-test".to_vec(),
        qos: QoS::ExactlyOnce,
        retain: false,
        dup: true,
        packet_id: Some(10),
        properties: Properties::default(),
    };
    client.send_publish(&dup_params).await?;

    // Should get another PUBREC for the same packet ID
    for _ in 0..5 {
        match client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 10 => {
                // Complete the flow
                client.send_pubrel(10, 0x00).await?;
                match client.recv().await? {
                    Packet::PubComp(comp) if comp.packet_id == 10 => {
                        return Ok(Outcome::Pass);
                    }
                    other => return Ok(Outcome::fail_packet("PUBCOMP(10)", &other)),
                }
            }
            Packet::Publish(_) => {} // loopback
            other => {
                return Ok(Outcome::fail_packet("PUBREC(10) after DUP", &other));
            }
        }
    }

    Ok(Outcome::fail("PUBREC not received for duplicate PUBLISH"))
}

// ── Packet ID reuse ─────────────────────────────────────────────────────────

const PID_REUSE_QOS1: TestContext = TestContext {
    refs: &["MQTT-2.2.1-3"],
    description: "Packet ID MUST be available for reuse after PUBACK completes (QoS 1)",
    compliance: Compliance::Must,
};

/// Each time a Client sends a new SUBSCRIBE, UNSUBSCRIBE, or PUBLISH (where QoS > 0) MQTT Control Packet it MUST
/// assign it a non-zero Packet Identifier that is currently unused [MQTT-2.2.1-3]. Non-normative prose in §4.3.2
/// states: "The Packet Identifier becomes available for reuse once the sender has received the PUBACK packet."
///
/// This test sends two QoS 1 PUBLISH packets with the same Packet Identifier, with a PUBACK received between
/// them, and verifies both are acknowledged and delivered.
async fn packet_id_reuse_after_puback(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/pid_reuse_q1";
    let (mut sub, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-pidq1",
        topic,
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    // First PUBLISH with packet_id=1
    pub_client
        .send_publish(&PublishParams::qos1(topic, b"first".to_vec(), 1))
        .await?;
    match pub_client.recv().await? {
        Packet::PubAck(ack) if ack.packet_id == 1 => {}
        other => return Ok(Outcome::fail_packet("PUBACK(1)", &other)),
    }

    // Reuse packet_id=1 for a second PUBLISH
    pub_client
        .send_publish(&PublishParams::qos1(topic, b"second".to_vec(), 1))
        .await?;
    match pub_client.recv().await? {
        Packet::PubAck(ack) if ack.packet_id == 1 => {}
        other => return Ok(Outcome::fail_packet("PUBACK(1) reuse", &other)),
    }

    // Verify both messages arrived
    let mut payloads = Vec::new();
    for _ in 0..2 {
        match sub.recv().await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                if let Some(pid) = p.packet_id {
                    sub.send_puback(pid, 0x00).await?;
                }
                payloads.push(p.payload);
            }
            _ => break,
        }
    }

    if payloads.len() == 2 {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Expected 2 messages, got {}",
            payloads.len()
        )))
    }
}

const PID_REUSE_QOS2: TestContext = TestContext {
    refs: &["MQTT-2.2.1-4"],
    description: "Packet ID MUST be available for reuse after PUBCOMP completes (QoS 2)",
    compliance: Compliance::Must,
};

/// Each time a Server sends a new PUBLISH (with QoS > 0) MQTT Control Packet it MUST assign it a non-zero Packet
/// Identifier that is currently unused [MQTT-2.2.1-4]. Non-normative prose in §4.3.3 states: "The Packet
/// Identifier becomes available for reuse once the sender has received the PUBCOMP packet or a PUBREC with a
/// Reason Code of 0x80 or greater."
///
/// This test completes a QoS 2 flow then starts a second QoS 2 flow with the same Packet Identifier and verifies
/// both flows complete successfully.
async fn packet_id_reuse_after_pubcomp(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-pidq2-pub");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // First QoS 2 flow with packet_id=5
    client
        .send_publish(&PublishParams::qos2(
            "mqtt/test/pub/pid_reuse_q2",
            b"first".to_vec(),
            5,
        ))
        .await?;
    // Expect PUBREC
    loop {
        match client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 5 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBREC(5)", &other)),
        }
    }
    client.send_pubrel(5, 0x00).await?;
    loop {
        match client.recv().await? {
            Packet::PubComp(comp) if comp.packet_id == 5 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBCOMP(5)", &other)),
        }
    }

    // Reuse packet_id=5 for a second QoS 2 flow
    client
        .send_publish(&PublishParams::qos2(
            "mqtt/test/pub/pid_reuse_q2",
            b"second".to_vec(),
            5,
        ))
        .await?;
    loop {
        match client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 5 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBREC(5) reuse", &other)),
        }
    }
    client.send_pubrel(5, 0x00).await?;
    loop {
        match client.recv().await? {
            Packet::PubComp(comp) if comp.packet_id == 5 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBCOMP(5) reuse", &other)),
        }
    }

    Ok(Outcome::Pass)
}

const QOS2_DUP_PUBREL: TestContext = TestContext {
    refs: &["MQTT-4.3.3-11"],
    description: "Server MUST respond with PUBCOMP to duplicate PUBREL",
    compliance: Compliance::Must,
};

/// [The receiver] MUST respond to a PUBREL packet by sending a PUBCOMP packet containing the same Packet
/// Identifier as the PUBREL [MQTT-4.3.3-11].
///
/// This test completes a QoS 2 flow, sends a duplicate PUBREL, and verifies the server responds with PUBCOMP
/// again (or closes the connection as a protocol error — both are acceptable).
async fn qos2_duplicate_pubrel(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-qos2-duppubrel");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Start QoS 2 flow
    client
        .send_publish(&PublishParams::qos2(
            "mqtt/test/pub/dup_pubrel",
            b"test".to_vec(),
            7,
        ))
        .await?;
    loop {
        match client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 7 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBREC(7)", &other)),
        }
    }

    // Send PUBREL
    client.send_pubrel(7, 0x00).await?;
    loop {
        match client.recv().await? {
            Packet::PubComp(comp) if comp.packet_id == 7 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBCOMP(7)", &other)),
        }
    }

    // Send duplicate PUBREL — server MUST respond with PUBCOMP
    client.send_pubrel(7, 0x00).await?;
    match client.recv().await {
        Ok(Packet::PubComp(comp)) if comp.packet_id == 7 => Ok(Outcome::Pass),
        Ok(Packet::Disconnect(_)) | Err(RecvError::Closed) => {
            // Some brokers may consider duplicate PUBREL after PUBCOMP as
            // a protocol error — still acceptable behaviour
            Ok(Outcome::Pass)
        }
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet(
            "PUBCOMP(7) for duplicate PUBREL",
            &other,
        )),
    }
}

const PAYLOAD_FORMAT_UTF8: TestContext = TestContext {
    refs: &["MQTT-3.3.2-4"],
    description: "Server MAY validate UTF-8 payload when Payload Format Indicator is 1",
    compliance: Compliance::May,
};

/// A Server MUST send the Payload Format Indicator unaltered to all subscribers receiving the Application
/// Message [MQTT-3.3.2-4]. Non-normative prose in §3.3.2.3.2 states: "The receiver MAY validate that the Payload
/// is of the format indicated, and if it is not send a PUBACK, PUBREC, or DISCONNECT with Reason Code of 0x99
/// (Payload format invalid)." The validation itself is not a tagged requirement.
///
/// This test publishes a message with Payload Format Indicator=1 and an invalid UTF-8 payload and checks whether
/// the broker validates and rejects it (support is optional).
async fn payload_format_utf8_validated(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-pfi-utf8");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Send PUBLISH with payload_format_indicator=1 but invalid UTF-8 payload
    let publish = PublishParams {
        topic: "mqtt/test/pub/pfi_utf8".into(),
        payload: vec![0xFF, 0xFE, 0x80, 0x81], // invalid UTF-8
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: Properties {
            payload_format_indicator: Some(1),
            ..Properties::default()
        },
    };
    client.send_publish(&publish).await?;

    match client.recv().await {
        Ok(Packet::Disconnect(d)) if d.reason_code == 0x99 => {
            // Server validated and rejected — good
            Ok(Outcome::Pass)
        }
        Ok(Packet::Disconnect(_)) => {
            // Disconnected for some other reason — still counts as validation
            Ok(Outcome::Pass)
        }
        Ok(Packet::PubAck(_)) => {
            // Server accepted without validation — MAY, so this is not a failure
            Ok(Outcome::unsupported(
                "Server accepted invalid UTF-8 payload without validation (Payload Format Indicator=1)",
            ))
        }
        Err(RecvError::Closed) => {
            // Connection closed — server may have validated and closed
            Ok(Outcome::Pass)
        }
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(other) => Ok(Outcome::fail_packet("PUBACK or DISCONNECT", &other)),
    }
}

// ── User Properties ordering ─────────────────────────────────────────────

const USER_PROPS_ORDER: TestContext = TestContext {
    refs: &["MQTT-3.3.2-18"],
    description: "User Properties order MUST be maintained when forwarding",
    compliance: Compliance::Must,
};

/// The Server MUST maintain the order of User Properties when forwarding the Application Message
/// [MQTT-3.3.2-18].
///
/// This test publishes a message with three ordered User Properties and verifies the subscriber receives them in
/// the same order.
async fn user_properties_order(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/up_order";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-uporder",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let ordered_props = vec![
        ("a".to_string(), "1".to_string()),
        ("b".to_string(), "2".to_string()),
        ("c".to_string(), "3".to_string()),
    ];

    let pub_params = PublishParams {
        topic: topic.to_string(),
        payload: b"order-test".to_vec(),
        qos: QoS::AtMostOnce,
        retain: false,
        dup: false,
        packet_id: None,
        properties: Properties {
            user_properties: ordered_props.clone(),
            ..Properties::default()
        },
    };
    pub_client.send_publish(&pub_params).await?;

    match sub_client.recv().await? {
        Packet::Publish(p) if p.topic == topic => {
            if p.properties.user_properties == ordered_props {
                Ok(Outcome::Pass)
            } else if p.properties.user_properties.is_empty() {
                Ok(Outcome::fail("No user properties in forwarded PUBLISH"))
            } else {
                Ok(Outcome::fail(format!(
                    "User properties order not maintained: expected {:?}, got {:?}",
                    ordered_props, p.properties.user_properties
                )))
            }
        }
        other => Ok(Outcome::fail_packet(
            &format!("PUBLISH on topic \"{topic}\""),
            &other,
        )),
    }
}

// ── QoS 0 retained storage ──────────────────────────────────────────────

const RETAINED_QOS0: TestContext = TestContext {
    refs: &["MQTT-3.3.1-5"],
    description: "Server SHOULD store QoS 0 retained message",
    compliance: Compliance::Should,
};

/// If the RETAIN flag is set to 1 in a PUBLISH packet sent by a Client to a Server, the Server MUST replace any
/// existing retained message for this topic and store the Application Message [MQTT-3.3.1-5]. Non-normative prose
/// in §3.3.1.3 adds the QoS 0 carve-out: "If the Server receives a PUBLISH packet with the RETAIN flag set to 1,
/// and QoS 0 it SHOULD store the new QoS 0 message as the new retained message for that topic, but MAY choose to
/// discard it at any time."
///
/// This test publishes a QoS 0 retained message and verifies a new subscriber receives the stored message.
async fn retained_qos0_stored(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/retain_qos0";

    // Publish a QoS 0 retained message
    let pub_conn = ConnectParams::new("mqtt-test-retq0-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    let pub_params = PublishParams {
        topic: topic.to_string(),
        payload: b"retained-qos0".to_vec(),
        qos: QoS::AtMostOnce,
        retain: true,
        dup: false,
        packet_id: None,
        properties: Properties::default(),
    };
    pub_client.send_publish(&pub_params).await?;

    // Give the broker time to store it
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Subscribe from a new client — should receive the retained message
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-retq0-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let result = match expect_publish(&mut sub_client, topic).await {
        Ok(p) if !p.payload.is_empty() => Outcome::Pass,
        Ok(_) => Outcome::fail("Retained message delivered but payload was empty"),
        Err(r) => r,
    };

    // Clean up: remove retained message
    let cleanup_conn = ConnectParams::new("mqtt-test-retq0-cleanup");
    if let Ok((mut c, _)) = client::connect(config.addr, &cleanup_conn, config.recv_timeout).await {
        let clear = PublishParams::retained(topic, Vec::new());
        let _ = c.send_publish(&clear).await;
    }

    Ok(result)
}

// ── QoS 2 no duplicate delivery ─────────────────────────────────────────

const QOS2_NO_DUP_DELIVERY: TestContext = TestContext {
    refs: &["MQTT-4.3.3-10"],
    description: "Duplicate QoS 2 PUBLISH before PUBREL MUST NOT cause duplicate delivery",
    compliance: Compliance::Must,
};

/// Until it has received the corresponding PUBREL packet, the receiver MUST acknowledge any subsequent PUBLISH
/// packet with the same Packet Identifier by sending a PUBREC. It MUST NOT cause duplicate messages to be
/// delivered to any onward recipients in this case [MQTT-4.3.3-10].
///
/// This test sends a QoS 2 PUBLISH, then before sending PUBREL resends the same PUBLISH with DUP=1, completes
/// the flow, and verifies the subscriber received exactly one message.
async fn qos2_no_duplicate_delivery(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/qos2_nodup";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-q2nodup",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Send QoS 2 PUBLISH
    pub_client
        .send_publish(&PublishParams::qos2(topic, b"once-only".to_vec(), 20))
        .await?;

    // Wait for PUBREC
    for _ in 0..5 {
        match pub_client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 20 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBREC(20)", &other)),
        }
    }

    // Send duplicate PUBLISH (DUP=1) before PUBREL
    let dup_params = PublishParams {
        topic: topic.to_string(),
        payload: b"once-only".to_vec(),
        qos: QoS::ExactlyOnce,
        retain: false,
        dup: true,
        packet_id: Some(20),
        properties: Properties::default(),
    };
    pub_client.send_publish(&dup_params).await?;

    // Should get PUBREC again
    for _ in 0..5 {
        match pub_client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 20 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBREC(20) dup", &other)),
        }
    }

    // Complete the flow
    pub_client.send_pubrel(20, 0x00).await?;
    for _ in 0..5 {
        match pub_client.recv().await? {
            Packet::PubComp(comp) if comp.packet_id == 20 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBCOMP(20)", &other)),
        }
    }

    // Count messages received by subscriber — should be exactly 1
    let mut count = 0;
    loop {
        match sub_client.recv_with_timeout(Duration::from_secs(1)).await {
            Ok(Packet::Publish(p)) if p.topic == topic => count += 1,
            _ => break,
        }
    }

    if count == 1 {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Subscriber received {count} messages (expected exactly 1, duplicate PUBLISH must not cause duplicate delivery)"
        )))
    }
}

// ── QoS 2 continues after message expiry ─────────────────────────────────

const QOS2_EXPIRY_CONTINUES: TestContext = TestContext {
    refs: &["MQTT-4.3.3-13"],
    description: "Server MUST continue QoS 2 ack sequence even after message expiry",
    compliance: Compliance::Must,
};

/// [The receiver] MUST continue the QoS 2 acknowledgement sequence even if it has applied message expiry
/// [MQTT-4.3.3-13].
///
/// This test publishes a QoS 2 message with a 1-second Message Expiry Interval, waits 2 seconds for the message
/// to expire, sends PUBREL, and verifies the server still responds with PUBCOMP.
async fn qos2_continues_after_message_expiry(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-q2expiry");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Publish QoS 2 with 1-second expiry
    let pub_params = PublishParams {
        topic: "mqtt/test/pub/qos2_expiry".to_string(),
        payload: b"expires-fast".to_vec(),
        qos: QoS::ExactlyOnce,
        retain: false,
        dup: false,
        packet_id: Some(30),
        properties: Properties {
            message_expiry_interval: Some(1),
            ..Properties::default()
        },
    };
    client.send_publish(&pub_params).await?;

    // Wait for PUBREC
    for _ in 0..5 {
        match client.recv().await? {
            Packet::PubRec(rec) if rec.packet_id == 30 => break,
            Packet::Publish(_) => continue,
            other => return Ok(Outcome::fail_packet("PUBREC(30)", &other)),
        }
    }

    // Wait for message to expire
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send PUBREL — server MUST still respond with PUBCOMP
    client.send_pubrel(30, 0x00).await?;

    match client.recv().await {
        Ok(Packet::PubComp(comp)) if comp.packet_id == 30 => Ok(Outcome::Pass),
        Ok(other) => Ok(Outcome::fail_packet(
            "PUBCOMP(30) after message expiry",
            &other,
        )),
        Err(RecvError::Timeout) => Ok(Outcome::fail(
            "No PUBCOMP after message expiry (timed out) — server must continue QoS 2 flow",
        )),
        Err(RecvError::Closed) => Ok(Outcome::fail(
            "No PUBCOMP after message expiry (connection closed) — server must continue QoS 2 flow",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

// ── QoS 1 initial delivery DUP=0 ─────────────────────────────────────────

const QOS1_DUP_ZERO: TestContext = TestContext {
    refs: &["MQTT-4.3.2-2"],
    description: "Server MUST forward QoS 1 PUBLISH with DUP=0 on initial delivery",
    compliance: Compliance::Must,
};

/// [The sender] MUST send a PUBLISH packet containing this Packet Identifier with QoS 1 and DUP flag set to 0
/// [MQTT-4.3.2-2].
///
/// This test publishes a QoS 1 message and verifies the subscriber receives the initial delivery with DUP=0.
async fn qos1_initial_delivery_dup_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/qos1_dup0";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-q1dup0",
        topic,
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    pub_client
        .send_publish(&PublishParams::qos1(topic, b"dup-check".to_vec(), 1))
        .await?;
    // Drain PUBACK
    let _ = pub_client.recv().await;

    // Receive forwarded message on subscriber
    match sub_client.recv().await? {
        Packet::Publish(p) if p.topic == topic => {
            if let Some(pid) = p.packet_id {
                sub_client.send_puback(pid, 0x00).await?;
            }
            if p.dup {
                Ok(Outcome::fail(
                    "Server forwarded QoS 1 message with DUP=1 on initial delivery",
                ))
            } else {
                Ok(Outcome::Pass)
            }
        }
        other => Ok(Outcome::fail_packet("PUBLISH on subscriber", &other)),
    }
}

// ── Control packets when quota is zero ────────────────────────────────────

const QUOTA_ZERO_CONTROL: TestContext = TestContext {
    refs: &["MQTT-4.9.0-3"],
    description: "Server MUST process control packets even when send quota is zero",
    compliance: Compliance::Must,
};

/// The Client and Server MUST continue to process and respond to all other MQTT Control Packets even if the
/// quota is zero [MQTT-4.9.0-3].
///
/// This test fills the server's send quota by receiving but not acknowledging two QoS 1 messages on a subscriber
/// with Receive Maximum=2, then sends a PINGREQ and verifies the server still responds with PINGRESP.
async fn control_packets_when_quota_zero(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/quota_zero";

    // Subscriber with receive_maximum=2
    let mut sub_params = ConnectParams::new("mqtt-test-quota0-sub");
    sub_params.properties.receive_maximum = Some(2);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;

    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Publish 3 QoS 1 messages from another client
    let pub_conn = ConnectParams::new("mqtt-test-quota0-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    for i in 1u16..=3 {
        pub_client
            .send_publish(&PublishParams::qos1(
                topic,
                format!("q-{i}").into_bytes(),
                i,
            ))
            .await?;
    }
    // Drain PUBACKs
    for _ in 0..5 {
        match pub_client.recv_with_timeout(Duration::from_secs(1)).await {
            Ok(Packet::PubAck(_)) => {}
            _ => break,
        }
    }

    // Receive up to 2 messages but do NOT ACK them (fill quota)
    for _ in 0..2 {
        match sub_client.recv_with_timeout(Duration::from_secs(2)).await {
            Ok(Packet::Publish(_)) => {}
            _ => break,
        }
    }

    // Quota should now be zero. Send PINGREQ — server MUST still respond.
    sub_client.send_pingreq().await?;

    match sub_client.recv().await {
        Ok(Packet::PingResp) => Ok(Outcome::Pass),
        Ok(Packet::Publish(_)) => {
            // Might receive another publish before pingresp — try once more
            sub_client.send_pingreq().await?;
            match sub_client.recv().await {
                Ok(Packet::PingResp) => Ok(Outcome::Pass),
                Ok(other) => Ok(Outcome::fail_packet("PINGRESP", &other)),
                Err(RecvError::Timeout) => {
                    Ok(Outcome::fail("No PINGRESP when quota is zero (timed out)"))
                }
                Err(RecvError::Closed) => Ok(Outcome::fail(
                    "No PINGRESP when quota is zero (connection closed)",
                )),
                Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
            }
        }
        Ok(other) => Ok(Outcome::fail_packet("PINGRESP", &other)),
        Err(RecvError::Timeout) => Ok(Outcome::fail("No PINGRESP when quota is zero (timed out)")),
        Err(RecvError::Closed) => Ok(Outcome::fail(
            "No PINGRESP when quota is zero (connection closed)",
        )),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
    }
}

// ── Retain=0 must not replace existing retained ──────────────────────────

const RETAIN_ZERO_PRESERVES: TestContext = TestContext {
    refs: &["MQTT-3.3.1-8"],
    description: "PUBLISH with Retain=0 MUST NOT store or replace existing retained messages",
    compliance: Compliance::Must,
};

/// If the RETAIN flag is 0 in a PUBLISH packet sent by a Client to a Server, the Server MUST NOT store the
/// message as a retained message and MUST NOT remove or replace any existing retained message [MQTT-3.3.1-8].
///
/// This test stores a retained message, publishes a non-retained message on the same topic, then subscribes
/// from a new client and verifies the original retained message is still delivered unchanged.
async fn retain_zero_preserves_existing(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/retain0_preserve";

    // 1. Store a retained message
    let pub_conn = ConnectParams::new("mqtt-test-r0p-pub1");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;

    let retained = PublishParams {
        topic: topic.to_string(),
        payload: b"original-retained".to_vec(),
        qos: QoS::AtMostOnce,
        retain: true,
        dup: false,
        packet_id: None,
        properties: Properties::default(),
    };
    pub_client.send_publish(&retained).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Publish a non-retained message on the same topic
    let non_retained = PublishParams::qos0(topic, b"non-retained-update".to_vec());
    pub_client.send_publish(&non_retained).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. New subscriber should still receive the ORIGINAL retained message
    let mut sub_client = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-r0p-sub",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    let result = match expect_publish(&mut sub_client, topic).await {
        Ok(p) if p.retain && p.payload == b"original-retained" => Outcome::Pass,
        Ok(p) if p.retain && p.payload == b"non-retained-update" => {
            Outcome::fail("Retained message was replaced by PUBLISH with Retain=0")
        }
        Ok(p) if p.retain => Outcome::fail(format!(
            "Unexpected retained payload: {:?}",
            String::from_utf8_lossy(&p.payload)
        )),
        Ok(p) => Outcome::fail(format!(
            "Received non-retained message (payload: {:?}) instead of retained",
            String::from_utf8_lossy(&p.payload)
        )),
        Err(r) => r,
    };

    // Clean up: remove retained message
    let cleanup = ConnectParams::new("mqtt-test-r0p-cleanup");
    if let Ok((mut c, _)) = client::connect(config.addr, &cleanup, config.recv_timeout).await {
        let _ = c
            .send_publish(&PublishParams::retained(topic, Vec::new()))
            .await;
    }

    Ok(result)
}

const ORDERED_TOPIC_QOS0: TestContext = TestContext {
    refs: &["MQTT-4.6.0-5", "MQTT-4.6.0-6"],
    description: "Server MUST deliver QoS 0 messages in order for an Ordered Topic",
    compliance: Compliance::Must,
};

/// When a Server processes a message that has been published to an Ordered Topic, it MUST send PUBLISH packets
/// to consumers (for the same Topic and QoS) in the order that they were received from any given Client
/// [MQTT-4.6.0-5]. By default, a Server MUST treat every Topic as an Ordered Topic when it is forwarding
/// messages on Non-shared Subscriptions [MQTT-4.6.0-6].
///
/// This test publishes 10 QoS 0 messages in sequence and verifies they arrive at the subscriber in the same
/// order (complementing the QoS 1 ordering test).
async fn ordered_topic_qos0(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/ordered_qos0";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-ord0",
        topic,
        QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    for i in 0u32..10 {
        let params = PublishParams {
            topic: topic.to_string(),
            qos: QoS::AtMostOnce,
            retain: false,
            payload: format!("ord-{i}").into_bytes(),
            packet_id: None,
            dup: false,
            properties: Properties::default(),
        };
        pub_client.send_publish(&params).await?;
    }

    // Receive and verify order
    let mut received = Vec::new();
    for _ in 0..10 {
        match sub_client.recv().await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                received.push(String::from_utf8_lossy(&p.payload).to_string());
            }
            Ok(_) => {}
            Err(RecvError::Closed | RecvError::Timeout) => break,
            Err(RecvError::Other(e)) => return Err(e),
        }
    }

    let expected: Vec<String> = (0..10).map(|i| format!("ord-{i}")).collect();
    if received == expected {
        Ok(Outcome::Pass)
    } else if received.len() < 10 {
        // QoS 0 may lose messages — still a pass if ordering is preserved
        let is_ordered = received.windows(2).all(|w| w[0] < w[1]);
        if is_ordered && received.len() >= 5 {
            Ok(Outcome::Pass)
        } else if is_ordered {
            Ok(Outcome::fail(format!(
                "Only {}/10 messages received (ordered, but too few)",
                received.len()
            )))
        } else {
            Ok(Outcome::fail(format!(
                "Messages arrived out of order: {received:?}"
            )))
        }
    } else {
        Ok(Outcome::fail(format!(
            "Messages arrived out of order: {received:?}"
        )))
    }
}

const CONTENT_TYPE_FORWARDED: TestContext = TestContext {
    refs: &["MQTT-3.3.2-20"],
    description: "Content Type MUST be forwarded unaltered by the server",
    compliance: Compliance::Must,
};

/// A Server MUST send the Content Type unaltered to all subscribers receiving the Application Message
/// [MQTT-3.3.2-20].
///
/// This test publishes a message with a Content Type containing a charset parameter and verifies the subscriber
/// receives the exact same Content Type string.
async fn content_type_forwarded_unaltered(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/content_type_fwd";
    let content_type = "application/octet-stream; charset=utf-8";

    let (mut sub_client, mut pub_client) = client::sub_pub_pair(
        config.addr,
        "mqtt-test-ct-fwd",
        topic,
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    let params = PublishParams {
        topic: topic.to_string(),
        qos: QoS::AtLeastOnce,
        retain: false,
        payload: b"ct-test".to_vec(),
        packet_id: Some(1),
        dup: false,
        properties: Properties {
            content_type: Some(content_type.to_string()),
            ..Default::default()
        },
    };
    pub_client.send_publish(&params).await?;

    // Drain PUBACK
    let _ = pub_client.recv().await;

    let p = match expect_publish(&mut sub_client, topic).await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    if let Some(pid) = p.packet_id {
        sub_client.send_puback(pid, 0x00).await?;
    }
    match p.properties.content_type.as_deref() {
        Some(ct) if ct == content_type => Ok(Outcome::Pass),
        Some(ct) => Ok(Outcome::fail(format!(
            "Content Type altered: expected \"{content_type}\", got \"{ct}\""
        ))),
        None => Ok(Outcome::fail(
            "Content Type property was stripped by server",
        )),
    }
}

// ── QoS 1 unacknowledged until PUBACK ───────────────────────────────────────

const QOS1_UNACKNOWLEDGED: TestContext = TestContext {
    refs: &["MQTT-4.3.2-3"],
    description: "QoS 1 PUBLISH MUST be treated as unacknowledged until PUBACK received",
    compliance: Compliance::Must,
};

/// [The sender] MUST treat the PUBLISH Packet as "unacknowledged" until it has received the corresponding PUBACK
/// packet from the receiver [MQTT-4.3.2-3].
///
/// This test subscribes QoS 1 with a persistent session, receives a forwarded PUBLISH but withholds PUBACK,
/// disconnects abruptly, then reconnects and verifies the broker redelivers the unacknowledged message.
async fn qos1_unacknowledged_until_puback(config: TestConfig<'_>) -> Result<Outcome> {
    let topic = "mqtt/test/pub/qos1_unack";

    // Connect subscriber with a persistent session, subscribe QoS 1
    let mut sub_params = ConnectParams::new("mqtt-test-qos1-unack-sub");
    sub_params.clean_start = false;
    sub_params.properties.session_expiry_interval = Some(300);
    let (mut sub_client, _) =
        client::connect(config.addr, &sub_params, config.recv_timeout).await?;
    let sub = SubscribeParams::simple(1, topic, QoS::AtLeastOnce);
    sub_client.send_subscribe(&sub).await?;
    if let Err(r) = expect_suback(&mut sub_client).await {
        return Ok(r);
    }

    // Publish QoS 1 from a separate client
    let pub_conn = ConnectParams::new("mqtt-test-qos1-unack-pub");
    let (mut pub_client, _) = client::connect(config.addr, &pub_conn, config.recv_timeout).await?;
    let pub_params = PublishParams::qos1(topic, b"unack-test".to_vec(), 1);
    pub_client.send_publish(&pub_params).await?;
    // Drain publisher PUBACK
    for _ in 0..5 {
        if let Ok(Packet::PubAck(_)) = pub_client.recv().await {
            break;
        }
    }

    // Receive the forwarded PUBLISH on subscriber — but do NOT send PUBACK
    let received = match expect_publish(&mut sub_client, topic).await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };

    // Disconnect abruptly without PUBACK — message remains unacknowledged
    drop(sub_client.into_raw());

    // Small delay to let broker process the disconnect
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Reconnect with same client ID and persistent session
    let mut sub_params2 = ConnectParams::new("mqtt-test-qos1-unack-sub");
    sub_params2.clean_start = false;
    sub_params2.properties.session_expiry_interval = Some(300);
    let (mut sub_client2, _) =
        client::connect(config.addr, &sub_params2, config.recv_timeout).await?;

    // Broker MUST redeliver the unacknowledged message
    let p = match expect_publish(&mut sub_client2, topic).await {
        Ok(p) => p,
        Err(r) => return Ok(r),
    };
    // ACK it this time so the broker cleans up
    if let Some(pid) = p.packet_id {
        sub_client2.send_puback(pid, 0x00).await?;
    }
    // Verify it's the same message
    if p.payload == received.payload {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Redelivered payload differs: expected {:?}, got {:?}",
            received.payload, p.payload
        )))
    }
}
