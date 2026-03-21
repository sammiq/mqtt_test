//! Request / Response pattern compliance tests [MQTT-4.10].
//!
//! MQTT v5 introduced a request/response pattern using the Response Topic
//! and Correlation Data properties. These tests verify the broker correctly
//! forwards these properties.

use std::time::Duration;

use indicatif::ProgressBar;

use crate::client::{self, connect_and_subscribe};
use crate::codec::{ConnectParams, Packet, Properties, PublishParams, QoS};
use crate::report::run_test;
use crate::types::{Compliance, Suite, TestContext, TestResult};

pub const TEST_COUNT: usize = 5;

pub async fn run(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> Suite {
    Suite {
        name: "REQUEST / RESPONSE",
        results: vec![
            response_topic_forwarded(addr, recv_timeout, pb).await,
            correlation_data_forwarded(addr, recv_timeout, pb).await,
            full_request_response(addr, recv_timeout, pb).await,
            response_topic_with_correlation(addr, recv_timeout, pb).await,
            multiple_correlation_data(addr, recv_timeout, pb).await,
        ],
    }
}

// ── SHOULD ──────────────────────────────────────────────────────────────────

const RESPONSE_TOPIC: TestContext = TestContext {
    id: "MQTT-4.10.0-1",
    description: "Response Topic property SHOULD be forwarded unchanged by the broker",
    compliance: Compliance::Should,
};

/// The broker SHOULD forward the Response Topic property from PUBLISH to
/// subscribers without modification [MQTT-3.3.2-13].
async fn response_topic_forwarded(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = RESPONSE_TOPIC;
    run_test(ctx, pb, async {
        let mut sub = connect_and_subscribe(addr, "mqtt-test-resp-topic-sub", "test/rr/topic", QoS::AtLeastOnce, recv_timeout).await?;

        let params = ConnectParams::new("mqtt-test-resp-topic-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

        let publish = PublishParams {
            topic: "test/rr/topic".into(),
            payload: b"request".to_vec(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(1),
            properties: Properties { response_topic: Some("reply/to/me".into()), ..Default::default() },
        };
        pub_client.send_publish(&publish).await?;
        pub_client.recv(recv_timeout).await?; // PUBACK

        match sub.recv(recv_timeout).await? {
            Packet::Publish(msg) => {
                if msg.properties.response_topic.as_deref() == Some("reply/to/me") {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!("Response Topic not preserved: got {:?}", msg.properties.response_topic),
                    ))
                }
            }
            other => Ok(TestResult::fail_packet(&ctx, "PUBLISH with Response Topic", &other)),
        }
    })
    .await
}

const CORRELATION_DATA: TestContext = TestContext {
    id: "MQTT-4.10.0-2",
    description: "Correlation Data property SHOULD be forwarded unchanged by the broker",
    compliance: Compliance::Should,
};

/// The broker SHOULD forward the Correlation Data property from PUBLISH to
/// subscribers without modification [MQTT-3.3.2-14].
async fn correlation_data_forwarded(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = CORRELATION_DATA;
    run_test(ctx, pb, async {
        let mut sub = connect_and_subscribe(addr, "mqtt-test-corr-data-sub", "test/rr/corr", QoS::AtLeastOnce, recv_timeout).await?;

        let params = ConnectParams::new("mqtt-test-corr-data-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

        let publish = PublishParams {
            topic: "test/rr/corr".into(),
            payload: b"request".to_vec(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(1),
            properties: Properties { correlation_data: Some(b"\x01\x02\x03\xAB\xCD".to_vec()), ..Default::default() },
        };
        pub_client.send_publish(&publish).await?;
        pub_client.recv(recv_timeout).await?; // PUBACK

        match sub.recv(recv_timeout).await? {
            Packet::Publish(msg) => {
                if msg.properties.correlation_data.as_deref() == Some(b"\x01\x02\x03\xAB\xCD") {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!("Correlation Data not preserved: got {:?}", msg.properties.correlation_data),
                    ))
                }
            }
            other => Ok(TestResult::fail_packet(&ctx, "PUBLISH with Correlation Data", &other)),
        }
    })
    .await
}

// ── MUST ────────────────────────────────────────────────────────────────────

const FULL_RR: TestContext = TestContext {
    id: "MQTT-4.10.0-3",
    description: "Full request/response: requester receives response on Response Topic",
    compliance: Compliance::Must,
};

/// Complete request/response pattern:
/// 1. Client A subscribes to response topic
/// 2. Client B subscribes to request topic
/// 3. Client A publishes request with Response Topic
/// 4. Client B receives request, publishes response to Response Topic
/// 5. Client A receives response
async fn full_request_response(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = FULL_RR;
    run_test(ctx, pb, async {
        let mut client_a = connect_and_subscribe(
            addr, "mqtt-test-rr-requester", "test/rr/reply", QoS::AtLeastOnce, recv_timeout,
        ).await?;

        let mut client_b = connect_and_subscribe(
            addr, "mqtt-test-rr-responder", "test/rr/request", QoS::AtLeastOnce, recv_timeout,
        ).await?;

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
        client_a.recv(recv_timeout).await?; // PUBACK

        // Client B receives the request
        let req_msg = match client_b.recv(recv_timeout).await? {
            Packet::Publish(msg) => msg,
            other => return Ok(TestResult::fail_packet(&ctx, "PUBLISH (request)", &other)),
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
        client_b.recv(recv_timeout).await?; // PUBACK

        // Client A receives the response
        match client_a.recv(recv_timeout).await? {
            Packet::Publish(msg) => {
                let corr_ok = msg.properties.correlation_data.as_deref() == Some(b"req-1");
                let payload_ok = msg.payload == b"4";
                if corr_ok && payload_ok {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!(
                            "Response mismatch: correlation={:?} payload={:?}",
                            msg.properties.correlation_data,
                            String::from_utf8_lossy(&msg.payload)
                        ),
                    ))
                }
            }
            other => Ok(TestResult::fail_packet(&ctx, "PUBLISH (response)", &other)),
        }
    })
    .await
}

const RESPONSE_TOPIC_WITH_CORR: TestContext = TestContext {
    id: "MQTT-3.3.2-9",
    description: "Response Topic and Correlation Data MUST both be forwarded together",
    compliance: Compliance::Must,
};

/// Both Response Topic and Correlation Data MUST be forwarded together
/// when present in a PUBLISH [MQTT-3.3.2-13/14].
async fn response_topic_with_correlation(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = RESPONSE_TOPIC_WITH_CORR;
    run_test(ctx, pb, async {
        let mut sub = connect_and_subscribe(addr, "mqtt-test-rr-both-sub", "test/rr/both", QoS::AtLeastOnce, recv_timeout).await?;

        let params = ConnectParams::new("mqtt-test-rr-both-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

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
        pub_client.recv(recv_timeout).await?; // PUBACK

        match sub.recv(recv_timeout).await? {
            Packet::Publish(msg) => {
                let rt_ok = msg.properties.response_topic.as_deref() == Some("test/rr/response");
                let cd_ok = msg.properties.correlation_data.as_deref() == Some(b"corr-42");
                if rt_ok && cd_ok {
                    Ok(TestResult::pass(&ctx))
                } else {
                    Ok(TestResult::fail(
                        &ctx,
                        format!(
                            "Properties not forwarded: response_topic={:?}, correlation_data={:?}",
                            msg.properties.response_topic, msg.properties.correlation_data
                        ),
                    ))
                }
            }
            other => Ok(TestResult::fail_packet(&ctx, "PUBLISH with both properties", &other)),
        }
    })
    .await
}

const MULTI_CORRELATION: TestContext = TestContext {
    id: "MQTT-4.10.0-4",
    description: "Different Correlation Data values MUST be independently preserved",
    compliance: Compliance::Must,
};

/// Multiple messages with different Correlation Data values must each have
/// their data preserved independently.
async fn multiple_correlation_data(addr: &str, recv_timeout: Duration, pb: &ProgressBar) -> TestResult {
    let ctx = MULTI_CORRELATION;
    run_test(ctx, pb, async {
        let mut sub = connect_and_subscribe(addr, "mqtt-test-multi-corr-sub", "test/rr/multi", QoS::AtLeastOnce, recv_timeout).await?;

        let params = ConnectParams::new("mqtt-test-multi-corr-pub");
        let (mut pub_client, _) = client::connect(addr, &params, recv_timeout).await?;

        // Send two messages with different correlation data
        for (id, corr) in [(1u16, b"AAA" as &[u8]), (2, b"BBB")] {
            let publish = PublishParams {
                topic: "test/rr/multi".into(),
                payload: format!("msg-{id}").into_bytes(),
                qos: QoS::AtLeastOnce,
                retain: false,
                dup: false,
                packet_id: Some(id),
                properties: Properties { correlation_data: Some(corr.to_vec()), ..Default::default() },
            };
            pub_client.send_publish(&publish).await?;
            pub_client.recv(recv_timeout).await?; // PUBACK
        }

        // Receive both messages
        let mut received_corrs = Vec::new();
        for _ in 0..2 {
            match sub.recv(recv_timeout).await? {
                Packet::Publish(msg) => {
                    received_corrs.push(msg.properties.correlation_data.unwrap_or_default());
                }
                other => return Ok(TestResult::fail_packet(&ctx, "PUBLISH", &other)),
            }
        }

        received_corrs.sort();
        if received_corrs == vec![b"AAA".to_vec(), b"BBB".to_vec()] {
            Ok(TestResult::pass(&ctx))
        } else {
            Ok(TestResult::fail(
                &ctx,
                format!("Correlation data not preserved: got {:?}", received_corrs),
            ))
        }
    })
    .await
}
