//! Request / Response pattern compliance tests [MQTT-4.10].
//!
//! MQTT v5 introduced a request/response pattern using the Response Topic
//! and Correlation Data properties. These tests verify the broker correctly
//! forwards these properties.

use anyhow::Result;

use crate::client::{self, connect_and_subscribe};
use crate::codec::{ConnectParams, Packet, Properties, PublishParams, QoS};
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("REQUEST / RESPONSE");

    suite.add(RESPONSE_TOPIC, response_topic_forwarded(config));
    suite.add(CORRELATION_DATA, correlation_data_forwarded(config));
    suite.add(FULL_RR, full_request_response(config));
    suite.add(
        RESPONSE_TOPIC_WITH_CORR,
        response_topic_with_correlation(config),
    );
    suite.add(MULTI_CORRELATION, multiple_correlation_data(config));

    suite
}

// ── SHOULD ──────────────────────────────────────────────────────────────────

const RESPONSE_TOPIC: TestContext = TestContext {
    refs: &["MQTT-3.3.2-15"],
    description: "Response Topic property MUST be forwarded unchanged by the broker",
    compliance: Compliance::Must,
};

/// The Server MUST send the Response Topic unaltered to all subscribers receiving the Application
/// Message [MQTT-3.3.2-15].
///
/// This test publishes a message with a Response Topic and verifies the subscriber receives it unchanged.
async fn response_topic_forwarded(config: TestConfig<'_>) -> Result<Outcome> {
    let mut sub = connect_and_subscribe(
        config.addr,
        "mqtt-test-resp-topic-sub",
        "test/rr/topic",
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-resp-topic-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let publish = PublishParams {
        topic: "test/rr/topic".into(),
        payload: b"request".to_vec(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: Properties {
            response_topic: Some("reply/to/me".into()),
            ..Default::default()
        },
    };
    pub_client.send_publish(&publish).await?;
    pub_client.recv().await?; // PUBACK

    match sub.recv().await? {
        Packet::Publish(msg) => {
            if msg.properties.response_topic.as_deref() == Some("reply/to/me") {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Response Topic not preserved: got {:?}",
                    msg.properties.response_topic
                )))
            }
        }
        other => Ok(Outcome::fail_packet("PUBLISH with Response Topic", &other)),
    }
}

const CORRELATION_DATA: TestContext = TestContext {
    refs: &["MQTT-3.3.2-16"],
    description: "Correlation Data property MUST be forwarded unchanged by the broker",
    compliance: Compliance::Must,
};

/// The Server MUST send the Correlation Data unaltered to all subscribers receiving the Application
/// Message [MQTT-3.3.2-16].
///
/// This test publishes a message with Correlation Data and verifies the subscriber receives it unchanged.
async fn correlation_data_forwarded(config: TestConfig<'_>) -> Result<Outcome> {
    let mut sub = connect_and_subscribe(
        config.addr,
        "mqtt-test-corr-data-sub",
        "test/rr/corr",
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-corr-data-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let publish = PublishParams {
        topic: "test/rr/corr".into(),
        payload: b"request".to_vec(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: Properties {
            correlation_data: Some(b"\x01\x02\x03\xAB\xCD".to_vec()),
            ..Default::default()
        },
    };
    pub_client.send_publish(&publish).await?;
    pub_client.recv().await?; // PUBACK

    match sub.recv().await? {
        Packet::Publish(msg) => {
            if msg.properties.correlation_data.as_deref() == Some(b"\x01\x02\x03\xAB\xCD") {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Correlation Data not preserved: got {:?}",
                    msg.properties.correlation_data
                )))
            }
        }
        other => Ok(Outcome::fail_packet(
            "PUBLISH with Correlation Data",
            &other,
        )),
    }
}

// ── MUST ────────────────────────────────────────────────────────────────────

const FULL_RR: TestContext = TestContext {
    refs: &["MQTT-3.3.2-15", "MQTT-3.3.2-16"],
    description: "Full request/response: requester receives response on Response Topic",
    compliance: Compliance::Must,
};

/// The Server MUST send the Response Topic unaltered to all subscribers receiving the Application
/// Message [MQTT-3.3.2-15]. The Server MUST send the Correlation Data unaltered to all subscribers receiving the
/// Application Message [MQTT-3.3.2-16].
///
/// This test exercises the full request/response pattern: Client A publishes a request with Response Topic and
/// Correlation Data, Client B receives it and responds on the Response Topic, and Client A receives the response
/// with Correlation Data intact.
async fn full_request_response(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client_a = connect_and_subscribe(
        config.addr,
        "mqtt-test-rr-requester",
        "test/rr/reply",
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    let mut client_b = connect_and_subscribe(
        config.addr,
        "mqtt-test-rr-responder",
        "test/rr/request",
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    // Client A publishes a request with Response Topic
    let request = PublishParams {
        topic: "test/rr/request".into(),
        payload: b"what is 2+2?".to_vec(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: Properties {
            response_topic: Some("test/rr/reply".into()),
            correlation_data: Some(b"req-1".to_vec()),
            ..Default::default()
        },
    };
    client_a.send_publish(&request).await?;
    client_a.recv().await?; // PUBACK

    // Client B receives the request
    let req_msg = match client_b.recv().await? {
        Packet::Publish(msg) => msg,
        other => return Ok(Outcome::fail_packet("PUBLISH (request)", &other)),
    };

    // Client B sends a response to the Response Topic
    let resp_topic = req_msg.properties.response_topic.unwrap_or_default();
    let response = PublishParams {
        topic: resp_topic,
        payload: b"4".to_vec(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: Properties {
            correlation_data: req_msg.properties.correlation_data,
            ..Default::default()
        },
    };
    client_b.send_publish(&response).await?;
    client_b.recv().await?; // PUBACK

    // Client A receives the response
    match client_a.recv().await? {
        Packet::Publish(msg) => {
            let corr_ok = msg.properties.correlation_data.as_deref() == Some(b"req-1");
            let payload_ok = msg.payload == b"4";
            if corr_ok && payload_ok {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Response mismatch: correlation={:?} payload={:?}",
                    msg.properties.correlation_data,
                    String::from_utf8_lossy(&msg.payload)
                )))
            }
        }
        other => Ok(Outcome::fail_packet("PUBLISH (response)", &other)),
    }
}

const RESPONSE_TOPIC_WITH_CORR: TestContext = TestContext {
    refs: &["MQTT-3.3.2-15", "MQTT-3.3.2-16"],
    description: "Response Topic and Correlation Data MUST both be forwarded together",
    compliance: Compliance::Must,
};

/// The Server MUST send the Response Topic unaltered to all subscribers receiving the Application
/// Message [MQTT-3.3.2-15]. The Server MUST send the Correlation Data unaltered to all subscribers receiving the
/// Application Message [MQTT-3.3.2-16].
///
/// This test publishes a message with both Response Topic and Correlation Data and verifies the subscriber receives
/// both properties unchanged.
async fn response_topic_with_correlation(config: TestConfig<'_>) -> Result<Outcome> {
    let mut sub = connect_and_subscribe(
        config.addr,
        "mqtt-test-rr-both-sub",
        "test/rr/both",
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-rr-both-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let publish = PublishParams {
        topic: "test/rr/both".into(),
        payload: b"test".to_vec(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1),
        properties: Properties {
            response_topic: Some("test/rr/response".into()),
            correlation_data: Some(b"corr-42".to_vec()),
            ..Default::default()
        },
    };
    pub_client.send_publish(&publish).await?;
    pub_client.recv().await?; // PUBACK

    match sub.recv().await? {
        Packet::Publish(msg) => {
            let rt_ok = msg.properties.response_topic.as_deref() == Some("test/rr/response");
            let cd_ok = msg.properties.correlation_data.as_deref() == Some(b"corr-42");
            if rt_ok && cd_ok {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "Properties not forwarded: response_topic={:?}, correlation_data={:?}",
                    msg.properties.response_topic, msg.properties.correlation_data
                )))
            }
        }
        other => Ok(Outcome::fail_packet("PUBLISH with both properties", &other)),
    }
}

const MULTI_CORRELATION: TestContext = TestContext {
    refs: &["MQTT-3.3.2-16"],
    description: "Different Correlation Data values MUST be independently preserved",
    compliance: Compliance::Must,
};

/// The Server MUST send the Correlation Data unaltered to all subscribers receiving the Application
/// Message [MQTT-3.3.2-16].
///
/// This test sends multiple messages with different Correlation Data values and verifies each is preserved
/// independently by the broker.
async fn multiple_correlation_data(config: TestConfig<'_>) -> Result<Outcome> {
    let mut sub = connect_and_subscribe(
        config.addr,
        "mqtt-test-multi-corr-sub",
        "test/rr/multi",
        QoS::AtLeastOnce,
        config.recv_timeout,
    )
    .await?;

    let params = ConnectParams::new("mqtt-test-multi-corr-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // Send two messages with different correlation data
    for (id, corr) in [(1u16, b"AAA" as &[u8]), (2, b"BBB")] {
        let publish = PublishParams {
            topic: "test/rr/multi".into(),
            payload: format!("msg-{id}").into_bytes(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(id),
            properties: Properties {
                correlation_data: Some(corr.to_vec()),
                ..Default::default()
            },
        };
        pub_client.send_publish(&publish).await?;
        pub_client.recv().await?; // PUBACK
    }

    // Receive both messages
    let mut received_corrs = Vec::new();
    for _ in 0..2 {
        match sub.recv().await? {
            Packet::Publish(msg) => {
                received_corrs.push(msg.properties.correlation_data.unwrap_or_default());
            }
            other => return Ok(Outcome::fail_packet("PUBLISH", &other)),
        }
    }

    received_corrs.sort();
    if received_corrs == vec![b"AAA".to_vec(), b"BBB".to_vec()] {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::fail(format!(
            "Correlation data not preserved: got {:?}",
            received_corrs
        )))
    }
}
