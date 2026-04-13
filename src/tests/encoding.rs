//! Data encoding compliance tests (MQTT v5 section 1.5).
//!
//! Tests UTF-8 string validation, Variable Byte Integer encoding,
//! and String Pair compliance across multiple packet types and fields.

use anyhow::Result;

use crate::client::{self, RawClient, RecvError};
use crate::codec::{ConnectParams, Packet};
use crate::helpers::{expect_connect_reject, expect_disconnect};
use crate::types::{Compliance, Outcome, SuiteRunner, TestConfig, TestContext};

pub fn tests<'a>(config: TestConfig<'a>) -> SuiteRunner<'a> {
    let mut suite = SuiteRunner::new("ENCODING");

    // MQTT-1.5.4-1 — UTF-8 well-formedness
    suite.add(
        UTF8_HIGH_SURROGATE_TOPIC,
        utf8_high_surrogate_in_publish_topic(config),
    );
    suite.add(
        UTF8_LOW_SURROGATE_TOPIC,
        utf8_low_surrogate_in_publish_topic(config),
    );
    suite.add(UTF8_OVERLONG_TOPIC, utf8_overlong_in_publish_topic(config));
    suite.add(
        UTF8_TRUNCATED_TOPIC,
        utf8_truncated_in_publish_topic(config),
    );
    suite.add(
        UTF8_ORPHAN_CONTINUATION_TOPIC,
        utf8_orphan_continuation_in_publish_topic(config),
    );
    suite.add(
        UTF8_FIVE_BYTE_TOPIC,
        utf8_five_byte_in_publish_topic(config),
    );
    suite.add(
        UTF8_SURROGATE_CLIENT_ID,
        utf8_surrogate_in_client_id(config),
    );
    suite.add(UTF8_OVERLONG_CLIENT_ID, utf8_overlong_in_client_id(config));
    suite.add(
        UTF8_SURROGATE_SUBSCRIBE,
        utf8_surrogate_in_subscribe_filter(config),
    );

    // MQTT-1.5.4-2 — null character prohibition
    suite.add(NULL_IN_TOPIC, null_char_in_publish_topic(config));
    suite.add(NULL_IN_CLIENT_ID, null_char_in_client_id(config));
    suite.add(
        NULL_IN_SUBSCRIBE_FILTER,
        null_char_in_subscribe_filter(config),
    );

    // MQTT-1.5.4-3 — BOM preservation
    suite.add(BOM_PRESERVED, bom_not_stripped_from_topic(config));

    // MQTT-1.5.5-1 — Variable Byte Integer encoding
    suite.add(BAD_REMAINING_LEN, malformed_remaining_length(config));
    suite.add(
        VBI_NON_MINIMAL_CONNECT_PROPS,
        vbi_non_minimal_connect_properties(config),
    );
    suite.add(
        VBI_NON_MINIMAL_PUBLISH_PROPS,
        vbi_non_minimal_publish_properties(config),
    );
    suite.add(
        VBI_NON_MINIMAL_SUB_ID,
        vbi_non_minimal_subscription_id(config),
    );

    // MQTT-1.5.7-1 — String Pair UTF-8 compliance
    suite.add(
        USER_PROP_BAD_KEY_CONNECT,
        user_property_bad_key_in_connect(config),
    );
    suite.add(
        USER_PROP_BAD_VALUE_CONNECT,
        user_property_bad_value_in_connect(config),
    );
    suite.add(
        USER_PROP_BAD_KEY_PUBLISH,
        user_property_bad_key_in_publish(config),
    );
    suite.add(
        USER_PROP_BAD_KEY_SUBSCRIBE,
        user_property_bad_key_in_subscribe(config),
    );

    suite
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build and send a PUBLISH with invalid bytes in the topic, then expect disconnect.
///
/// Constructs a QoS 0 PUBLISH whose topic is `"mqtt/"` followed by `bad_bytes`,
/// with a 2-byte payload `"HI"`. The packet is built dynamically so callers only
/// need to supply the bad byte sequence.
async fn publish_bad_utf8_topic(
    config: TestConfig<'_>,
    client_id: &str,
    bad_bytes: &[u8],
) -> Result<Outcome> {
    let params = ConnectParams::new(client_id);
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let topic_prefix = b"mqtt/";
    let topic_len = topic_prefix.len() + bad_bytes.len();
    let payload = b"HI";
    // remaining = topic_len_field(2) + topic + props_len(1) + payload
    let remaining = 2 + topic_len + 1 + payload.len();

    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x30); // PUBLISH | QoS=0
    packet.push(remaining as u8);
    packet.push((topic_len >> 8) as u8);
    packet.push((topic_len & 0xFF) as u8);
    packet.extend_from_slice(topic_prefix);
    packet.extend_from_slice(bad_bytes);
    packet.push(0x00); // properties length = 0
    packet.extend_from_slice(payload);

    client.send_raw(&packet).await?;
    Ok(expect_disconnect(&mut client).await)
}

/// Build and send a CONNECT with invalid bytes in the Client ID, then expect rejection.
///
/// Constructs a CONNECT whose Client ID is `"t"` followed by `bad_bytes`.
/// The packet is built dynamically so callers only need to supply the bad byte sequence.
async fn connect_bad_utf8_client_id(config: TestConfig<'_>, bad_bytes: &[u8]) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    let client_id_prefix = b"t";
    let client_id_len = client_id_prefix.len() + bad_bytes.len();
    // variable header: protocol_name(6) + version(1) + flags(1) + keep_alive(2) + props_len(1) = 11
    // payload: client_id_len_field(2) + client_id
    let remaining = 11 + 2 + client_id_len;

    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x10); // CONNECT fixed header
    packet.push(remaining as u8);
    packet.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']); // protocol name
    packet.push(0x05); // protocol version 5
    packet.push(0x02); // flags: clean_start=1
    packet.extend_from_slice(&[0x00, 0x3C]); // keep alive = 60
    packet.push(0x00); // properties length = 0
    packet.push((client_id_len >> 8) as u8);
    packet.push((client_id_len & 0xFF) as u8);
    packet.extend_from_slice(client_id_prefix);
    packet.extend_from_slice(bad_bytes);

    client.send_raw(&packet).await?;
    Ok(expect_connect_reject(&mut client).await)
}

/// Build and send a SUBSCRIBE with invalid bytes in the topic filter, then expect rejection.
///
/// Constructs a SUBSCRIBE whose topic filter is `"mqtt/"` followed by `bad_bytes`.
/// Accepts either DISCONNECT/connection close or SUBACK with all error reason codes,
/// since some brokers respond with SUBACK errors for filter-level violations.
async fn subscribe_bad_utf8_filter(
    config: TestConfig<'_>,
    client_id: &str,
    bad_bytes: &[u8],
    reject_description: &str,
) -> Result<Outcome> {
    let params = ConnectParams::new(client_id);
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let filter_prefix = b"mqtt/";
    let filter_len = filter_prefix.len() + bad_bytes.len();
    // remaining = packet_id(2) + props_len(1) + filter_len_field(2) + filter + options(1)
    let remaining = 2 + 1 + 2 + filter_len + 1;

    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x82); // SUBSCRIBE fixed header
    packet.push(remaining as u8);
    packet.extend_from_slice(&[0x00, 0x01]); // packet ID = 1
    packet.push(0x00); // properties length = 0
    packet.push((filter_len >> 8) as u8);
    packet.push((filter_len & 0xFF) as u8);
    packet.extend_from_slice(filter_prefix);
    packet.extend_from_slice(bad_bytes);
    packet.push(0x00); // subscription options: QoS 0

    client.send_raw(&packet).await?;

    match client.recv().await {
        Err(RecvError::Closed) | Ok(Packet::Disconnect(_)) => Ok(Outcome::Pass),
        Err(RecvError::Timeout) => Ok(Outcome::fail("broker did not disconnect (timed out)")),
        Err(RecvError::Other(e)) => Ok(Outcome::fail(format!("unexpected error: {e:#}"))),
        Ok(Packet::SubAck(ack)) => {
            if ack.reason_codes.iter().all(|&c| c >= 0x80) {
                Ok(Outcome::Pass)
            } else {
                Ok(Outcome::fail(format!(
                    "SUBACK accepted filter with {reject_description}: reason codes {:?}",
                    ack.reason_codes
                )))
            }
        }
        Ok(other) => Ok(Outcome::fail_packet("disconnect or error SUBACK", &other)),
    }
}

/// Build and send a CONNECT with a User Property containing invalid bytes, then expect rejection.
///
/// Constructs a CONNECT with a single User Property (0x26) using the given `key` and `value`.
/// The caller places the bad bytes in either the key or value to test each half of the
/// String Pair independently.
async fn connect_bad_user_property(
    config: TestConfig<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // User Property: 0x26 + key_len(2) + key + value_len(2) + value
    let prop_len = 1 + 2 + key.len() + 2 + value.len();
    let client_id = b"test";
    // variable header: protocol_name(6) + version(1) + flags(1) + keep_alive(2) + props_len(1)
    // + properties + client_id_len(2) + client_id
    let remaining = 11 + prop_len + 2 + client_id.len();

    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x10); // CONNECT fixed header
    packet.push(remaining as u8);
    packet.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']); // protocol name
    packet.push(0x05); // protocol version 5
    packet.push(0x02); // flags: clean_start=1
    packet.extend_from_slice(&[0x00, 0x3C]); // keep alive = 60
    packet.push(prop_len as u8); // properties length
    packet.push(0x26); // User Property ID
    packet.push((key.len() >> 8) as u8);
    packet.push((key.len() & 0xFF) as u8);
    packet.extend_from_slice(key);
    packet.push((value.len() >> 8) as u8);
    packet.push((value.len() & 0xFF) as u8);
    packet.extend_from_slice(value);
    packet.extend_from_slice(&[0x00, 0x04]); // client ID length
    packet.extend_from_slice(client_id);

    client.send_raw(&packet).await?;
    Ok(expect_connect_reject(&mut client).await)
}

/// Build and send a PUBLISH with a User Property containing invalid bytes, then expect disconnect.
///
/// Constructs a QoS 0 PUBLISH to topic `"mqtt/"` with a single User Property (0x26) using
/// the given `key` and `value`.
async fn publish_bad_user_property(
    config: TestConfig<'_>,
    client_id: &str,
    key: &[u8],
    value: &[u8],
) -> Result<Outcome> {
    let params = ConnectParams::new(client_id);
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let topic = b"mqtt/";
    // User Property: 0x26 + key_len(2) + key + value_len(2) + value
    let prop_len = 1 + 2 + key.len() + 2 + value.len();
    let payload = b"HI";
    // remaining = topic_len(2) + topic + props_len(1) + props + payload
    let remaining = 2 + topic.len() + 1 + prop_len + payload.len();

    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x30); // PUBLISH | QoS=0
    packet.push(remaining as u8);
    packet.push((topic.len() >> 8) as u8);
    packet.push((topic.len() & 0xFF) as u8);
    packet.extend_from_slice(topic);
    packet.push(prop_len as u8); // properties length
    packet.push(0x26); // User Property ID
    packet.push((key.len() >> 8) as u8);
    packet.push((key.len() & 0xFF) as u8);
    packet.extend_from_slice(key);
    packet.push((value.len() >> 8) as u8);
    packet.push((value.len() & 0xFF) as u8);
    packet.extend_from_slice(value);
    packet.extend_from_slice(payload);

    client.send_raw(&packet).await?;
    Ok(expect_disconnect(&mut client).await)
}

/// Build and send a SUBSCRIBE with a User Property containing invalid bytes, then expect disconnect.
///
/// Constructs a SUBSCRIBE for topic filter `"mqtt/"` with a single User Property (0x26) using
/// the given `key` and `value`.
async fn subscribe_bad_user_property(
    config: TestConfig<'_>,
    client_id: &str,
    key: &[u8],
    value: &[u8],
) -> Result<Outcome> {
    let params = ConnectParams::new(client_id);
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let filter = b"mqtt/";
    // User Property: 0x26 + key_len(2) + key + value_len(2) + value
    let prop_len = 1 + 2 + key.len() + 2 + value.len();
    // remaining = packet_id(2) + props_len(1) + props + filter_len(2) + filter + options(1)
    let remaining = 2 + 1 + prop_len + 2 + filter.len() + 1;

    let mut packet = Vec::with_capacity(2 + remaining);
    packet.push(0x82); // SUBSCRIBE fixed header
    packet.push(remaining as u8);
    packet.extend_from_slice(&[0x00, 0x01]); // packet ID = 1
    packet.push(prop_len as u8); // properties length
    packet.push(0x26); // User Property ID
    packet.push((key.len() >> 8) as u8);
    packet.push((key.len() & 0xFF) as u8);
    packet.extend_from_slice(key);
    packet.push((value.len() >> 8) as u8);
    packet.push((value.len() & 0xFF) as u8);
    packet.extend_from_slice(value);
    packet.push((filter.len() >> 8) as u8);
    packet.push((filter.len() & 0xFF) as u8);
    packet.extend_from_slice(filter);
    packet.push(0x00); // subscription options: QoS 0

    client.send_raw(&packet).await?;
    Ok(expect_disconnect(&mut client).await)
}

// ── MQTT-1.5.4-1: UTF-8 well-formedness ─────────────────────────────────────

const UTF8_HIGH_SURROGATE_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject ill-formed UTF-8 (high surrogate U+D800) in PUBLISH topic",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// This test sends a PUBLISH with a topic containing the ill-formed byte sequence 0xED 0xA0 0x80
/// (high surrogate U+D800) and expects the server to disconnect.
async fn utf8_high_surrogate_in_publish_topic(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_utf8_topic(config, "mqtt-test-utf8-hi-surr", &[0xED, 0xA0, 0x80]).await
}

const UTF8_LOW_SURROGATE_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject ill-formed UTF-8 (low surrogate U+DC00) in PUBLISH topic",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// This test sends a PUBLISH with a topic containing the ill-formed byte sequence 0xED 0xB0 0x80
/// (low surrogate U+DC00), the other end of the surrogate range from U+D800.
async fn utf8_low_surrogate_in_publish_topic(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_utf8_topic(config, "mqtt-test-utf8-lo-surr", &[0xED, 0xB0, 0x80]).await
}

const UTF8_OVERLONG_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1", "MQTT-1.5.4-2"],
    description: "Server MUST reject overlong UTF-8 encoding (0xC0 0x80) in PUBLISH topic",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// A UTF-8 Encoded String MUST NOT include an encoding of the null character U+0000. [MQTT-1.5.4-2]
///
/// This test sends a PUBLISH with a topic containing the overlong encoding 0xC0 0x80 (a non-shortest
/// form for U+0000). This violates both requirements: it is ill-formed UTF-8 (overlong, MQTT-1.5.4-1)
/// and encodes the null character (MQTT-1.5.4-2). This is a classic compliance gap — Java's Modified
/// UTF-8 historically accepts this form.
async fn utf8_overlong_in_publish_topic(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_utf8_topic(config, "mqtt-test-utf8-overlong", &[0xC0, 0x80]).await
}

const UTF8_TRUNCATED_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject truncated multi-byte UTF-8 sequence in PUBLISH topic",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// This test sends a PUBLISH with a topic ending in 0xC2 — a two-byte sequence start byte with the
/// required continuation byte missing. This is ill-formed UTF-8 per RFC 3629.
async fn utf8_truncated_in_publish_topic(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_utf8_topic(config, "mqtt-test-utf8-trunc", &[0xC2]).await
}

const UTF8_ORPHAN_CONTINUATION_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject orphan continuation byte (0x80) in PUBLISH topic",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// This test sends a PUBLISH with a topic containing a lone continuation byte 0x80 without a preceding
/// start byte. Continuation bytes (0x80-0xBF) are only valid following a multi-byte start byte.
async fn utf8_orphan_continuation_in_publish_topic(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_utf8_topic(config, "mqtt-test-utf8-orphan", &[0x80]).await
}

const UTF8_FIVE_BYTE_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject 5-byte UTF-8 sequence (forbidden by RFC 3629) in PUBLISH topic",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// This test sends a PUBLISH with a topic containing the 5-byte sequence 0xF8 0x80 0x80 0x80 0x80.
/// RFC 3629 restricts UTF-8 to a maximum of 4 bytes per character; 5-byte and 6-byte sequences
/// (start bytes 0xF8-0xFD) are explicitly forbidden.
async fn utf8_five_byte_in_publish_topic(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_utf8_topic(
        config,
        "mqtt-test-utf8-5byte",
        &[0xF8, 0x80, 0x80, 0x80, 0x80],
    )
    .await
}

const UTF8_SURROGATE_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject ill-formed UTF-8 (surrogate) in CONNECT Client ID",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// This test sends a CONNECT with a Client ID containing the surrogate U+D800 (0xED 0xA0 0x80),
/// exercising CONNECT-time UTF-8 validation on the Client ID field — a different code path from
/// PUBLISH topic validation.
async fn utf8_surrogate_in_client_id(config: TestConfig<'_>) -> Result<Outcome> {
    connect_bad_utf8_client_id(config, &[0xED, 0xA0, 0x80]).await
}

const UTF8_OVERLONG_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1", "MQTT-1.5.4-2"],
    description: "Server MUST reject overlong UTF-8 encoding (0xC0 0x80) in CONNECT Client ID",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// A UTF-8 Encoded String MUST NOT include an encoding of the null character U+0000. [MQTT-1.5.4-2]
///
/// This test sends a CONNECT with a Client ID containing the overlong encoding 0xC0 0x80 (non-shortest
/// form for U+0000). This violates both requirements: ill-formed UTF-8 (MQTT-1.5.4-1) and encodes the
/// null character (MQTT-1.5.4-2). Exercises CONNECT-time validation on a different code path from
/// PUBLISH topic validation.
async fn utf8_overlong_in_client_id(config: TestConfig<'_>) -> Result<Outcome> {
    connect_bad_utf8_client_id(config, &[0xC0, 0x80]).await
}

const UTF8_SURROGATE_SUBSCRIBE: TestContext = TestContext {
    refs: &["MQTT-1.5.4-1"],
    description: "Server MUST reject ill-formed UTF-8 (surrogate) in SUBSCRIBE topic filter",
    compliance: Compliance::Must,
};

/// The character data in a UTF-8 Encoded String MUST be well-formed UTF-8 as defined by the Unicode
/// specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular, the character data MUST NOT
/// include encodings of code points between U+D800 and U+DFFF. [MQTT-1.5.4-1]
///
/// This test sends a SUBSCRIBE with a topic filter containing the surrogate U+D800, exercising
/// UTF-8 validation on the SUBSCRIBE path — a different code path from PUBLISH topic and CONNECT
/// Client ID validation.
async fn utf8_surrogate_in_subscribe_filter(config: TestConfig<'_>) -> Result<Outcome> {
    subscribe_bad_utf8_filter(
        config,
        "mqtt-test-utf8-sub-surr",
        &[0xED, 0xA0, 0x80],
        "surrogate",
    )
    .await
}

// ── MQTT-1.5.4-2: null character prohibition ─────────────────────────────────

const NULL_IN_TOPIC: TestContext = TestContext {
    refs: &["MQTT-1.5.4-2"],
    description: "PUBLISH with null character in topic name MUST be rejected",
    compliance: Compliance::Must,
};

/// A UTF-8 Encoded String MUST NOT include an encoding of the null character U+0000. [MQTT-1.5.4-2]
///
/// This test sends a PUBLISH with topic "mqtt/\0test" containing a null character embedded
/// in the middle of a longer topic name.
async fn null_char_in_publish_topic(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_utf8_topic(
        config,
        "mqtt-test-null-topic",
        &[0x00, b't', b'e', b's', b't'],
    )
    .await
}

const NULL_IN_CLIENT_ID: TestContext = TestContext {
    refs: &["MQTT-1.5.4-2"],
    description: "CONNECT with null character in Client ID MUST be rejected",
    compliance: Compliance::Must,
};

/// A UTF-8 Encoded String MUST NOT include an encoding of the null character U+0000. [MQTT-1.5.4-2]
///
/// This test sends a CONNECT with a Client ID containing a direct null byte (0x00), exercising
/// CONNECT-time null character validation — a different code path from PUBLISH topic validation.
async fn null_char_in_client_id(config: TestConfig<'_>) -> Result<Outcome> {
    connect_bad_utf8_client_id(config, &[0x00]).await
}

const NULL_IN_SUBSCRIBE_FILTER: TestContext = TestContext {
    refs: &["MQTT-1.5.4-2"],
    description: "SUBSCRIBE with null character in topic filter MUST be rejected",
    compliance: Compliance::Must,
};

/// A UTF-8 Encoded String MUST NOT include an encoding of the null character U+0000. [MQTT-1.5.4-2]
///
/// This test sends a SUBSCRIBE with a topic filter containing a direct null byte (0x00), exercising
/// SUBSCRIBE-time null character validation — a different code path from PUBLISH topic and CONNECT
/// Client ID validation.
async fn null_char_in_subscribe_filter(config: TestConfig<'_>) -> Result<Outcome> {
    subscribe_bad_utf8_filter(config, "mqtt-test-null-sub", &[0x00], "null character").await
}

// ── MQTT-1.5.4-3: BOM preservation ───────────────────────────────────────────

const BOM_PRESERVED: TestContext = TestContext {
    refs: &["MQTT-1.5.4-3"],
    description: "Server MUST NOT strip BOM (U+FEFF) from UTF-8 strings",
    compliance: Compliance::Must,
};

/// A UTF-8 encoded sequence 0xEF 0xBB 0xBF is always interpreted as U+FEFF ("ZERO WIDTH NO-BREAK
/// SPACE") wherever it appears in a string and MUST NOT be skipped over or stripped off by a packet
/// receiver. [MQTT-1.5.4-3]
///
/// This test subscribes to a topic prefixed with U+FEFF (BOM), publishes to that exact topic, and
/// verifies the message is delivered with the BOM intact in the topic name. It then publishes to the
/// same topic without the BOM and verifies no delivery occurs, confirming the broker treats BOM as a
/// significant character rather than stripping it during subscription matching.
async fn bom_not_stripped_from_topic(config: TestConfig<'_>) -> Result<Outcome> {
    let bom_topic = "\u{FEFF}mqtt/test/bom";
    let plain_topic = "mqtt/test/bom";

    let mut sub = client::connect_and_subscribe(
        config.addr,
        "mqtt-test-bom-sub",
        bom_topic,
        crate::codec::QoS::AtMostOnce,
        config.recv_timeout,
    )
    .await?;

    // Publish to the BOM-prefixed topic — should be delivered.
    let params = ConnectParams::new("mqtt-test-bom-pub");
    let (mut pub_client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    let publish = crate::codec::PublishParams::qos0(bom_topic, b"with-bom".to_vec());
    pub_client.send_publish(&publish).await?;

    // Expect delivery on the BOM topic with the BOM intact.
    let msg = match sub.recv().await {
        Ok(Packet::Publish(p)) => p,
        Ok(other) => return Ok(Outcome::fail_packet("PUBLISH", &other)),
        Err(RecvError::Timeout) => {
            return Ok(Outcome::fail(
                "no message received on BOM topic (timed out)",
            ));
        }
        Err(RecvError::Closed) => {
            return Ok(Outcome::fail(
                "connection closed before receiving BOM message",
            ));
        }
        Err(RecvError::Other(e)) => return Err(e),
    };

    // Verify the topic in the delivered PUBLISH still has the BOM prefix.
    if msg.topic != bom_topic {
        return Ok(Outcome::fail(format!(
            "delivered topic {:?} does not match subscribed topic {:?} — BOM may have been stripped",
            msg.topic, bom_topic
        )));
    }

    // Publish to the plain topic (without BOM) — should NOT be delivered to the BOM subscription.
    let publish_plain = crate::codec::PublishParams::qos0(plain_topic, b"no-bom".to_vec());
    pub_client.send_publish(&publish_plain).await?;

    match sub
        .recv_with_timeout(std::time::Duration::from_secs(1))
        .await
    {
        Err(RecvError::Timeout) => Ok(Outcome::Pass),
        Ok(Packet::Publish(p)) => Ok(Outcome::fail(format!(
            "received message on plain topic {:?} via BOM subscription — broker stripped BOM during matching",
            p.topic
        ))),
        Ok(other) => Ok(Outcome::fail_packet("no message (timeout)", &other)),
        Err(RecvError::Closed) => Ok(Outcome::fail("connection closed unexpectedly")),
        Err(RecvError::Other(e)) => Err(e),
    }
}

// ── MQTT-1.5.5-1: Variable Byte Integer encoding ────────────────────────────

const BAD_REMAINING_LEN: TestContext = TestContext {
    refs: &["MQTT-1.5.5-1"],
    description: "Server MUST close connection on malformed remaining length",
    compliance: Compliance::Must,
};

/// The encoded value MUST use the minimum number of bytes necessary to represent the
/// value. [MQTT-1.5.5-1]
///
/// This test sends a CONNECT with a 5-byte remaining length (all continuation bits set), violating
/// the VBI limit of 4 bytes.
async fn malformed_remaining_length(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // Send a CONNECT-like packet with a 5-byte remaining length (all continuation bits set).
    // This violates the VBI encoding limit of 4 bytes.
    #[rustfmt::skip]
    let bad_packet: &[u8] = &[
        0x10,                               // CONNECT fixed header
        0x80, 0x80, 0x80, 0x80, 0x01,       // malformed VBI: 5 continuation bytes
    ];
    client.send_raw(bad_packet).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const VBI_NON_MINIMAL_CONNECT_PROPS: TestContext = TestContext {
    refs: &["MQTT-1.5.5-1"],
    description: "Server MUST reject non-minimal VBI in CONNECT Properties Length",
    compliance: Compliance::Must,
};

/// The encoded value MUST use the minimum number of bytes necessary to represent the
/// value. [MQTT-1.5.5-1]
///
/// This test sends a CONNECT with Properties Length encoded as 0x80 0x00 (two bytes for value 0,
/// which should be a single byte 0x00). This is the canonical non-minimal VBI encoding and the
/// form most brokers fail to reject.
async fn vbi_non_minimal_connect_properties(config: TestConfig<'_>) -> Result<Outcome> {
    let mut client = RawClient::connect_tcp(config.addr, config.recv_timeout).await?;

    // CONNECT with Properties Length = 0 encoded as 0x80 0x00 (non-minimal).
    // The extra byte increases remaining length by 1 vs the minimal encoding.
    #[rustfmt::skip]
    let bad_connect: &[u8] = &[
        0x10,                                           // CONNECT fixed header
        0x12,                                           // remaining length = 18
        0x00, 0x04, b'M', b'Q', b'T', b'T',            // protocol name
        0x05,                                           // protocol version 5
        0x02,                                           // flags: clean_start=1
        0x00, 0x3C,                                     // keep alive = 60
        0x80, 0x00,                                     // properties length = 0 (non-minimal!)
        0x00, 0x04, b't', b'e', b's', b't',            // client ID "test"
    ];
    client.send_raw(bad_connect).await?;

    Ok(expect_connect_reject(&mut client).await)
}

const VBI_NON_MINIMAL_PUBLISH_PROPS: TestContext = TestContext {
    refs: &["MQTT-1.5.5-1"],
    description: "Server MUST reject non-minimal VBI in PUBLISH Properties Length",
    compliance: Compliance::Must,
};

/// The encoded value MUST use the minimum number of bytes necessary to represent the
/// value. [MQTT-1.5.5-1]
///
/// This test sends a PUBLISH with Properties Length encoded as 0x80 0x00 (two bytes for value 0).
/// This exercises VBI validation on the PUBLISH path — a different code path from CONNECT.
async fn vbi_non_minimal_publish_properties(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-vbi-pub");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // PUBLISH with Properties Length = 0 encoded as 0x80 0x00 (non-minimal).
    #[rustfmt::skip]
    let bad_publish: &[u8] = &[
        0x30,                                               // PUBLISH | QoS=0
        0x0B,                                               // remaining length = 11
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic "mqtt/" (7)
        0x80, 0x00,                                         // properties length = 0 (non-minimal!)
        0x48, 0x49,                                         // payload "HI"
    ];
    client.send_raw(bad_publish).await?;

    Ok(expect_disconnect(&mut client).await)
}

const VBI_NON_MINIMAL_SUB_ID: TestContext = TestContext {
    refs: &["MQTT-1.5.5-1"],
    description: "Server MUST reject non-minimal VBI in Subscription Identifier property",
    compliance: Compliance::Must,
};

/// The encoded value MUST use the minimum number of bytes necessary to represent the
/// value. [MQTT-1.5.5-1]
///
/// This test sends a SUBSCRIBE with a Subscription Identifier property whose value 1 is encoded
/// as 0x81 0x00 (two bytes) instead of the minimal 0x01 (one byte). This exercises VBI validation
/// inside property values, not just length fields.
async fn vbi_non_minimal_subscription_id(config: TestConfig<'_>) -> Result<Outcome> {
    let params = ConnectParams::new("mqtt-test-vbi-subid");
    let (mut client, _) = client::connect(config.addr, &params, config.recv_timeout).await?;

    // SUBSCRIBE with Subscription Identifier = 1 encoded as 0x81 0x00 (non-minimal).
    // Properties: 0x0B (Sub ID prop), 0x81 0x00 (value 1, non-minimal) = 3 bytes.
    #[rustfmt::skip]
    let bad_subscribe: &[u8] = &[
        0x82,                                               // SUBSCRIBE fixed header
        0x0E,                                               // remaining length = 14
        0x00, 0x01,                                         // packet ID = 1
        0x03,                                               // properties length = 3
        0x0B,                                               // Subscription Identifier property ID
        0x81, 0x00,                                         // value = 1 (non-minimal!)
        0x00, 0x05, b'm', b'q', b't', b't', b'/',          // topic filter "mqtt/" (7)
        0x00,                                               // subscription options: QoS 0
    ];
    client.send_raw(bad_subscribe).await?;

    Ok(expect_disconnect(&mut client).await)
}

// ── MQTT-1.5.7-1: String Pair UTF-8 compliance ──────────────────────────────

const USER_PROP_BAD_KEY_CONNECT: TestContext = TestContext {
    refs: &["MQTT-1.5.7-1"],
    description: "User Property with ill-formed UTF-8 key in CONNECT MUST be rejected",
    compliance: Compliance::Must,
};

/// Both strings MUST comply with the requirements for UTF-8 Encoded Strings. [MQTT-1.5.7-1]
///
/// This test sends a CONNECT with a User Property whose key contains the surrogate U+D800
/// (0xED 0xA0 0x80), with a valid value. Exercises key validation.
async fn user_property_bad_key_in_connect(config: TestConfig<'_>) -> Result<Outcome> {
    connect_bad_user_property(config, &[0xED, 0xA0, 0x80], b"v").await
}

const USER_PROP_BAD_VALUE_CONNECT: TestContext = TestContext {
    refs: &["MQTT-1.5.7-1"],
    description: "User Property with ill-formed UTF-8 value in CONNECT MUST be rejected",
    compliance: Compliance::Must,
};

/// Both strings MUST comply with the requirements for UTF-8 Encoded Strings. [MQTT-1.5.7-1]
///
/// This test sends a CONNECT with a User Property whose value contains the surrogate U+D800
/// (0xED 0xA0 0x80), with a valid key. Exercises value validation — the existing key test alone
/// does not prove both halves of the String Pair are checked.
async fn user_property_bad_value_in_connect(config: TestConfig<'_>) -> Result<Outcome> {
    connect_bad_user_property(config, b"k", &[0xED, 0xA0, 0x80]).await
}

const USER_PROP_BAD_KEY_PUBLISH: TestContext = TestContext {
    refs: &["MQTT-1.5.7-1"],
    description: "User Property with ill-formed UTF-8 key in PUBLISH MUST be rejected",
    compliance: Compliance::Must,
};

/// Both strings MUST comply with the requirements for UTF-8 Encoded Strings. [MQTT-1.5.7-1]
///
/// This test sends a PUBLISH with a User Property whose key contains the surrogate U+D800.
/// Exercises a different code path from CONNECT — servers often forward PUBLISH properties
/// rather than deeply validating them, so this catches implementations that skip UTF-8 checks
/// on the publish path.
async fn user_property_bad_key_in_publish(config: TestConfig<'_>) -> Result<Outcome> {
    publish_bad_user_property(config, "mqtt-test-up-pub", &[0xED, 0xA0, 0x80], b"v").await
}

const USER_PROP_BAD_KEY_SUBSCRIBE: TestContext = TestContext {
    refs: &["MQTT-1.5.7-1"],
    description: "User Property with ill-formed UTF-8 key in SUBSCRIBE MUST be rejected",
    compliance: Compliance::Must,
};

/// Both strings MUST comply with the requirements for UTF-8 Encoded Strings. [MQTT-1.5.7-1]
///
/// This test sends a SUBSCRIBE with a User Property whose key contains the surrogate U+D800.
/// Exercises the SUBSCRIBE code path for User Property UTF-8 validation.
async fn user_property_bad_key_in_subscribe(config: TestConfig<'_>) -> Result<Outcome> {
    subscribe_bad_user_property(config, "mqtt-test-up-sub", &[0xED, 0xA0, 0x80], b"v").await
}
