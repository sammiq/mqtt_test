//! PUBLISH / PUBACK / PUBREC / PUBREL / PUBCOMP compliance tests [MQTT-3.3].

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client;
use crate::codec::{ConnectParams, Packet, Properties, PublishParams, QoS, SubscribeOptions,
                   SubscribeParams};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 14;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "PUBLISH",
        results: vec![
            qos0_accepted(addr, recv_timeout, pb).await,
            qos1_gets_puback(addr, recv_timeout, pb).await,
            qos2_full_flow(addr, recv_timeout, pb).await,
            qos_downgrade_on_delivery(addr, recv_timeout, pb).await,
            invalid_qos3(addr, recv_timeout, pb).await,
            dup_on_qos0(addr, recv_timeout, pb).await,
            retain_flag_accepted(addr, recv_timeout, pb).await,
            topic_alias_accepted(addr, recv_timeout, pb).await,
            payload_format_indicator_preserved(addr, recv_timeout, pb).await,
            message_expiry_interval_present(addr, recv_timeout, pb).await,
            content_type_preserved(addr, recv_timeout, pb).await,
            response_topic_preserved(addr, recv_timeout, pb).await,
            correlation_data_preserved(addr, recv_timeout, pb).await,
            user_properties_preserved(addr, recv_timeout, pb).await,
        ],
    }
}

// ── MUST ─────────────────────────────────────────────────────────────────────

const QOS0: TestContext = TestContext {
    id: "MQTT-3.3.1-1",
    description: "QoS 0 PUBLISH MUST be delivered without acknowledgement",
    compliance: Compliance::Must,
};

/// QoS 0 PUBLISH MUST be accepted without error.
async fn qos0_accepted(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = QOS0;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-qos0-pub");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                "mqtt/test/pub/qos0".to_string(),
                SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
            )],
            properties: Properties::default(),
        };
        client.send_subscribe(&sub).await?;
        client.recv(recv_timeout).await?; // SUBACK

        let pub_params = PublishParams::qos0("mqtt/test/pub/qos0", b"hello".to_vec());
        client.send_publish(&pub_params).await?;

        match client.recv(recv_timeout).await? {
            Packet::Publish(p) if p.topic == "mqtt/test/pub/qos0" => {
                let _ = client.send_disconnect(0x00).await;
                Ok(TestResult::pass(&ctx))
            }
            other => {
                let _ = client.send_disconnect(0x00).await;
                Ok(TestResult::fail_packet(&ctx, "PUBLISH on topic \"mqtt/test/pub/qos0\"", &other))
            }
        }
    })
    .await
}

const QOS1: TestContext = TestContext {
    id: "MQTT-4.3.2-1",
    description: "QoS 1 PUBLISH MUST be acknowledged with PUBACK",
    compliance: Compliance::Must,
};

/// QoS 1 PUBLISH MUST receive a PUBACK [MQTT-4.3.2-1].
async fn qos1_gets_puback(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = QOS1;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-qos1-pub");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let pub_params = PublishParams {
            topic:      "mqtt/test/pub/qos1".to_string(),
            payload:    b"qos1-test".to_vec(),
            qos:        QoS::AtLeastOnce,
            retain:     false,
            packet_id:  Some(1),
            properties: Properties::default(),
        };
        client.send_publish(&pub_params).await?;

        for _ in 0..5 {
            match client.recv(recv_timeout).await? {
                Packet::PubAck(ack) if ack.packet_id == 1 => {
                    let _ = client.send_disconnect(0x00).await;
                    return Ok(TestResult::pass(&ctx));
                }
                Packet::Publish(_) => {} // may receive own loopback — ignore
                other => {
                    let _ = client.send_disconnect(0x00).await;
                    return Ok(TestResult::fail_packet(&ctx, "PUBACK(1)", &other));
                }
            }
        }

        let _ = client.send_disconnect(0x00).await;
        Ok(TestResult::fail(&ctx, "PUBACK not received within packet limit"))
    })
    .await
}

const QOS2: TestContext = TestContext {
    id: "MQTT-4.3.3-1",
    description: "QoS 2 PUBLISH MUST complete PUBREC / PUBREL / PUBCOMP flow",
    compliance: Compliance::Must,
};

/// QoS 2 PUBLISH MUST go through full PUBREC → PUBREL → PUBCOMP flow [MQTT-4.3.3-1].
async fn qos2_full_flow(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = QOS2;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-qos2-pub");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let pub_params = PublishParams {
            topic:      "mqtt/test/pub/qos2".to_string(),
            payload:    b"qos2-test".to_vec(),
            qos:        QoS::ExactlyOnce,
            retain:     false,
            packet_id:  Some(2),
            properties: Properties::default(),
        };
        client.send_publish(&pub_params).await?;

        for _ in 0..5 {
            match client.recv(recv_timeout).await? {
                Packet::PubRec(rec) if rec.packet_id == 2 => {
                    client.send_pubrel(2, 0x00).await?;

                    match client.recv(recv_timeout).await? {
                        Packet::PubComp(comp) if comp.packet_id == 2 => {
                            let _ = client.send_disconnect(0x00).await;
                            return Ok(TestResult::pass(&ctx));
                        }
                        other => {
                            let _ = client.send_disconnect(0x00).await;
                            return Ok(TestResult::fail_packet(&ctx, "PUBCOMP(2)", &other));
                        }
                    }
                }
                Packet::Publish(_) => {} // loopback — ignore
                other => {
                    let _ = client.send_disconnect(0x00).await;
                    return Ok(TestResult::fail_packet(&ctx, "PUBREC(2)", &other));
                }
            }
        }

        let _ = client.send_disconnect(0x00).await;
        Ok(TestResult::fail(&ctx, "PUBREC not received within packet limit"))
    })
    .await
}

const INVALID_QOS3: TestContext = TestContext {
    id: "MQTT-3.3.1-4",
    description: "Server MUST treat QoS value of 3 as a malformed packet",
    compliance: Compliance::Must,
};

/// QoS value of 3 (0b11) is malformed — server MUST close the connection [MQTT-3.3.1-4].
async fn invalid_qos3(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = INVALID_QOS3;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-qos3");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        // PUBLISH with QoS=3 (0b11 in bits 2-1 of fixed header byte)
        // Fixed header: 0x36 = 0011_0110 → type=3 (PUBLISH), DUP=0, QoS=3, RETAIN=0
        #[rustfmt::skip]
        let bad_publish: &[u8] = &[
            0x36,                                       // PUBLISH | QoS=3
            0x0C,                                       // remaining length = 12
            0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/"
            0x00, 0x01,                                 // packet ID = 1
            0x00,                                       // properties length = 0
            0x00,                                       // payload (1 byte)
        ];
        client.send_raw(bad_publish).await?;

        match client.recv(recv_timeout).await {
            Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
            Ok(other) => Ok(TestResult::fail_packet(&ctx, "disconnect (malformed QoS=3)", &other)),
        }
    })
    .await
}

const DUP_QOS0: TestContext = TestContext {
    id: "MQTT-3.3.1-2",
    description: "DUP flag MUST be 0 for QoS 0 messages",
    compliance: Compliance::Must,
};

/// DUP=1 with QoS=0 is a protocol error — server MUST close the connection [MQTT-3.3.1-2].
async fn dup_on_qos0(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = DUP_QOS0;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-dup-qos0");
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        // PUBLISH with DUP=1, QoS=0 (invalid combination)
        // Fixed header: 0x38 = 0011_1000 → type=3 (PUBLISH), DUP=1, QoS=0, RETAIN=0
        #[rustfmt::skip]
        let bad_publish: &[u8] = &[
            0x38,                                       // PUBLISH | DUP=1 | QoS=0
            0x0A,                                       // remaining length = 10
            0x00, 0x05, b'm', b'q', b't', b't', b'/',  // topic "mqtt/"
            0x00,                                       // properties length = 0
            0x00,                                       // payload (1 byte)
        ];
        client.send_raw(bad_publish).await?;

        match client.recv(recv_timeout).await {
            Err(_) | Ok(Packet::Disconnect(_)) => Ok(TestResult::pass(&ctx)),
            Ok(Packet::Publish(_)) => {
                // Some brokers may silently accept and forward — this is non-compliant
                let _ = client.send_disconnect(0x00).await;
                Ok(TestResult::fail(
                    &ctx,
                    "Broker accepted PUBLISH with DUP=1 and QoS=0 (should disconnect)",
                ))
            }
            Ok(other) => Ok(TestResult::fail_packet(&ctx, "disconnect (DUP=1, QoS=0)", &other)),
        }
    })
    .await
}

const QOS_DOWNGRADE: TestContext = TestContext {
    id: "MQTT-4.3.1-1",
    description: "Delivered QoS MUST NOT exceed the subscription's maximum QoS",
    compliance: Compliance::Must,
};

/// Server MUST deliver at the lower of the publisher's QoS and the subscriber's
/// maximum QoS [MQTT-4.3.1-1]. Publishing QoS 2 to a QoS 0 subscription must
/// deliver at QoS 0.
async fn qos_downgrade_on_delivery(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = QOS_DOWNGRADE;
    run_test(ctx, pb, || async move {
        let topic = "mqtt/test/pub/qos_downgrade";

        // Subscriber subscribes at QoS 0
        let sub_conn = ConnectParams::new("mqtt-test-qos-dg-sub");
        let (mut sub_client, _) = client::connect(addr, &sub_conn, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                topic.to_string(),
                SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
            )],
            properties: Properties::default(),
        };
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        // Publisher publishes at QoS 2
        let pub_conn = ConnectParams::new("mqtt-test-qos-dg-pub");
        let (mut pub_client, _) = client::connect(addr, &pub_conn, recv_timeout).await?;

        let pub_params = PublishParams {
            topic:      topic.to_string(),
            payload:    b"downgrade-test".to_vec(),
            qos:        QoS::ExactlyOnce,
            retain:     false,
            packet_id:  Some(1),
            properties: Properties::default(),
        };
        pub_client.send_publish(&pub_params).await?;

        // Complete publisher QoS 2 flow
        for _ in 0..5 {
            match pub_client.recv(recv_timeout).await? {
                Packet::PubRec(rec) if rec.packet_id == 1 => {
                    pub_client.send_pubrel(1, 0x00).await?;
                }
                Packet::PubComp(_) => break,
                _ => {}
            }
        }
        let _ = pub_client.send_disconnect(0x00).await;

        // Subscriber should receive at QoS 0 (no packet_id field)
        match sub_client.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.topic == topic => {
                let _ = sub_client.send_disconnect(0x00).await;
                if p.qos == QoS::AtMostOnce {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!(
                            "Message delivered at {:?}, expected AtMostOnce (subscription QoS 0)",
                            p.qos
                        ),
                    ))
                }
            }
            Ok(other) => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::fail_packet(&ctx, &format!("PUBLISH on topic \"{topic}\""), &other))
            }
            Err(_) => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::fail(&ctx, "No message delivered to subscriber"))
            }
        }
    })
    .await
}

// ── MAY ──────────────────────────────────────────────────────────────────────

const RETAIN: TestContext = TestContext {
    id: "MQTT-3.3.1-5",
    description: "Retain flag: broker stores and delivers retained message to new subscribers",
    compliance: Compliance::May,
};

/// Retain flag is accepted and message is stored [MQTT-3.3.1-5].
async fn retain_flag_accepted(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = RETAIN;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-retain-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

        let pub_params = PublishParams {
            topic:      "mqtt/test/pub/retain".to_string(),
            payload:    b"retained-payload".to_vec(),
            qos:        QoS::AtMostOnce,
            retain:     true,
            packet_id:  None,
            properties: Properties::default(),
        };
        pub_client.send_publish(&pub_params).await?;
        let _ = pub_client.send_disconnect(0x00).await;

        let sub_params = ConnectParams::new("mqtt-test-retain-sub");
        let (mut sub_client, _) = client::connect(addr, &sub_params, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                "mqtt/test/pub/retain".to_string(),
                SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
            )],
            properties: Properties::default(),
        };
        sub_client.send_subscribe(&sub).await?;
        sub_client.recv(recv_timeout).await?; // SUBACK

        match sub_client.recv(recv_timeout).await {
            Ok(Packet::Publish(p)) if p.retain && p.topic == "mqtt/test/pub/retain" => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::pass(&ctx))
            }
            Ok(Packet::Publish(_)) => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::fail(&ctx, "Received PUBLISH but retain flag not set on delivery"))
            }
            Ok(other) => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::fail_packet(&ctx, "retained PUBLISH", &other))
            }
            Err(_) => {
                let _ = sub_client.send_disconnect(0x00).await;
                Ok(TestResult::fail(&ctx, "No retained message delivered to new subscriber"))
            }
        }
    })
    .await
}

const TOPIC_ALIAS: TestContext = TestContext {
    id: "MQTT-3.3.2-11",
    description: "Topic Alias in PUBLISH is accepted",
    compliance: Compliance::May,
};

/// Topic Alias is accepted in PUBLISH [MQTT-3.3.2-11].
async fn topic_alias_accepted(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = TOPIC_ALIAS;
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new("mqtt-test-topic-alias");
        let (mut client, connack) = client::connect(addr, &params, recv_timeout).await?;

        if connack.properties.topic_alias_maximum == Some(0) {
            let _ = client.send_disconnect(0x00).await;
            return Ok(TestResult::skip(&ctx, "Broker reported Topic Alias Maximum = 0 (not supported)"));
        }

        let props = Properties { topic_alias: Some(1), ..Properties::default() };

        let pub_params = PublishParams {
            topic:      "mqtt/test/pub/alias".to_string(),
            payload:    b"alias-test".to_vec(),
            qos:        QoS::AtLeastOnce,
            retain:     false,
            packet_id:  Some(1),
            properties: props,
        };
        client.send_publish(&pub_params).await?;

        for _ in 0..5 {
            match client.recv(recv_timeout).await? {
                Packet::PubAck(ack) if ack.packet_id == 1 => {
                    let _ = client.send_disconnect(0x00).await;
                    return Ok(TestResult::pass(&ctx));
                }
                Packet::Disconnect(d) => {
                    return Ok(TestResult::fail(
                        &ctx,
                        format!("Broker disconnected with reason code {:#04x}", d.reason_code),
                    ));
                }
                Packet::Publish(_) => {} // loopback
                other => {
                    let _ = client.send_disconnect(0x00).await;
                    return Ok(TestResult::fail_packet(&ctx, "PUBACK(1)", &other));
                }
            }
        }

        let _ = client.send_disconnect(0x00).await;
        Ok(TestResult::fail(&ctx, "No PUBACK received"))
    })
    .await
}

// ── Property forwarding ─────────────────────────────────────────────────────

/// Helper: subscribe, publish with custom properties, verify a property is preserved.
#[allow(clippy::too_many_arguments)]
async fn property_forwarding_test(
    addr: &str,
    recv_timeout: Duration,
    ctx: TestContext,
    pb: &ProgressBar,
    topic: &'static str,
    props: Properties,
    check: fn(&Properties) -> bool,
    check_description: &'static str,
) -> TestResult {
    run_test(ctx, pb, || async move {
        let params = ConnectParams::new(format!("mqtt-test-{topic}"));
        let (mut client, _) = client::connect(addr, &params, recv_timeout).await?;

        let sub = SubscribeParams {
            packet_id:  1,
            filters:    vec![(
                topic.to_string(),
                SubscribeOptions { qos: QoS::AtMostOnce, ..Default::default() },
            )],
            properties: Properties::default(),
        };
        client.send_subscribe(&sub).await?;
        client.recv(recv_timeout).await?; // SUBACK

        let pub_params = PublishParams {
            topic:      topic.to_string(),
            payload:    b"prop-test".to_vec(),
            qos:        QoS::AtMostOnce,
            retain:     false,
            packet_id:  None,
            properties: props,
        };
        client.send_publish(&pub_params).await?;

        match client.recv(recv_timeout).await? {
            Packet::Publish(p) if p.topic == topic => {
                let _ = client.send_disconnect(0x00).await;
                if check(&p.properties) {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!("Property not preserved: {check_description}"),
                    ))
                }
            }
            other => {
                let _ = client.send_disconnect(0x00).await;
                Ok(TestResult::fail_packet(&ctx, &format!("PUBLISH on topic \"{topic}\""), &other))
            }
        }
    })
    .await
}

const PFI: TestContext = TestContext {
    id: "MQTT-3.3.2-7",
    description: "Payload Format Indicator SHOULD be forwarded unchanged",
    compliance: Compliance::Should,
};

/// Payload Format Indicator SHOULD be forwarded unchanged [MQTT-3.3.2-7].
async fn payload_format_indicator_preserved(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let props = Properties { payload_format_indicator: Some(1), ..Properties::default() };
    property_forwarding_test(addr, recv_timeout, PFI, pb, "mqtt/test/pub/pfi", props,
        |p| p.payload_format_indicator == Some(1), "expected payload_format_indicator=1").await
}

const MEI: TestContext = TestContext {
    id: "MQTT-3.3.2-8",
    description: "Message Expiry Interval MUST be present in forwarded PUBLISH",
    compliance: Compliance::Must,
};

/// Message Expiry Interval MUST be present in forwarded PUBLISH [MQTT-3.3.2-8].
async fn message_expiry_interval_present(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let props = Properties { message_expiry_interval: Some(3600), ..Properties::default() };
    property_forwarding_test(addr, recv_timeout, MEI, pb, "mqtt/test/pub/mei", props,
        |p| p.message_expiry_interval.is_some(), "expected message_expiry_interval to be present").await
}

const CONTENT_TYPE: TestContext = TestContext {
    id: "MQTT-3.3.2-12",
    description: "Content Type SHOULD be forwarded unchanged",
    compliance: Compliance::Should,
};

/// Content Type SHOULD be forwarded unchanged [MQTT-3.3.2-12].
async fn content_type_preserved(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let props = Properties { content_type: Some("application/json".to_string()), ..Properties::default() };
    property_forwarding_test(addr, recv_timeout, CONTENT_TYPE, pb, "mqtt/test/pub/ct", props,
        |p| p.content_type.as_deref() == Some("application/json"), "expected content_type=\"application/json\"").await
}

const RESPONSE_TOPIC: TestContext = TestContext {
    id: "MQTT-3.3.2-13",
    description: "Response Topic SHOULD be forwarded unchanged",
    compliance: Compliance::Should,
};

/// Response Topic SHOULD be forwarded unchanged [MQTT-3.3.2-13].
async fn response_topic_preserved(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let props = Properties { response_topic: Some("mqtt/test/pub/reply".to_string()), ..Properties::default() };
    property_forwarding_test(addr, recv_timeout, RESPONSE_TOPIC, pb, "mqtt/test/pub/rt", props,
        |p| p.response_topic.as_deref() == Some("mqtt/test/pub/reply"), "expected response_topic=\"mqtt/test/pub/reply\"").await
}

const CORRELATION_DATA: TestContext = TestContext {
    id: "MQTT-3.3.2-14",
    description: "Correlation Data SHOULD be forwarded unchanged",
    compliance: Compliance::Should,
};

/// Correlation Data SHOULD be forwarded unchanged [MQTT-3.3.2-14].
async fn correlation_data_preserved(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let props = Properties { correlation_data: Some(b"corr-123".to_vec()), ..Properties::default() };
    property_forwarding_test(addr, recv_timeout, CORRELATION_DATA, pb, "mqtt/test/pub/cd", props,
        |p| p.correlation_data.as_deref() == Some(b"corr-123"), "expected correlation_data=b\"corr-123\"").await
}

const USER_PROPS: TestContext = TestContext {
    id: "MQTT-3.3.2-18",
    description: "User Properties SHOULD be forwarded unchanged",
    compliance: Compliance::Should,
};

/// User Properties SHOULD be forwarded unchanged [MQTT-3.3.2-18].
async fn user_properties_preserved(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let props = Properties { user_properties: vec![("key".to_string(), "value".to_string())], ..Properties::default() };
    property_forwarding_test(addr, recv_timeout, USER_PROPS, pb, "mqtt/test/pub/up", props,
        |p| p.user_properties.contains(&("key".to_string(), "value".to_string())),
        "expected user_properties to contain (\"key\", \"value\")").await
}
