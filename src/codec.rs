//! MQTT v5 packet encoding and decoding.
//!
//! We implement the codec directly rather than depending on an external MQTT
//! library so that compliance tests have byte-level control — including the
//! ability to send intentionally malformed packets in negative test cases.
//!
//! Spec references are noted as [MQTT-x.y.z-n] throughout.

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("insufficient data")]
    InsufficientData,
    #[error("malformed variable-byte integer")]
    MalformedVbi,
    #[error("invalid UTF-8 in string field")]
    InvalidUtf8,
    #[error("unknown packet type: {0:#04x}")]
    UnknownPacketType(u8),
    #[error("protocol error: {0}")]
    Protocol(String),
}

// ─── Variable-byte integer ────────────────────────────────────────────────────

fn encode_vbi(n: u32, buf: &mut Vec<u8>) {
    let mut x = n;
    loop {
        let mut byte = (x % 128) as u8;
        x /= 128;
        if x > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if x == 0 {
            break;
        }
    }
}

fn decode_vbi(data: &[u8], pos: &mut usize) -> Result<u32, DecodeError> {
    let mut multiplier: u32 = 1;
    let mut value: u32 = 0;
    loop {
        if *pos >= data.len() {
            return Err(DecodeError::InsufficientData);
        }
        let byte = data[*pos];
        *pos += 1;
        value += (byte & 0x7F) as u32 * multiplier;
        if multiplier > 128 * 128 * 128 {
            return Err(DecodeError::MalformedVbi);
        }
        multiplier *= 128;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(value)
}

// ─── String / bytes primitives ────────────────────────────────────────────────

fn push_u16(v: u16, buf: &mut Vec<u8>) {
    buf.push((v >> 8) as u8);
    buf.push((v & 0xFF) as u8);
}

fn push_u32(v: u32, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn push_str(s: &str, buf: &mut Vec<u8>) {
    push_u16(s.len() as u16, buf);
    buf.extend_from_slice(s.as_bytes());
}

fn push_bytes(b: &[u8], buf: &mut Vec<u8>) {
    push_u16(b.len() as u16, buf);
    buf.extend_from_slice(b);
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, DecodeError> {
    if *pos + 2 > data.len() {
        return Err(DecodeError::InsufficientData);
    }
    let v = ((data[*pos] as u16) << 8) | data[*pos + 1] as u16;
    *pos += 2;
    Ok(v)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, DecodeError> {
    if *pos + 4 > data.len() {
        return Err(DecodeError::InsufficientData);
    }
    let v = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

fn read_str(data: &[u8], pos: &mut usize) -> Result<String, DecodeError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(DecodeError::InsufficientData);
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| DecodeError::InvalidUtf8)?
        .to_string();
    *pos += len;
    Ok(s)
}

fn read_bytes(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, DecodeError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(DecodeError::InsufficientData);
    }
    let b = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(b)
}

// ─── Properties ──────────────────────────────────────────────────────────────
//
// All MQTT v5 properties live here. Encoding and decoding use a single shared
// type so every packet can expose whatever subset it supports.

/// Property identifiers [MQTT-2.2.2].
mod prop {
    pub const PAYLOAD_FORMAT_INDICATOR: u8 = 0x01;
    pub const MESSAGE_EXPIRY_INTERVAL: u8 = 0x02;
    pub const CONTENT_TYPE: u8 = 0x03;
    pub const RESPONSE_TOPIC: u8 = 0x08;
    pub const CORRELATION_DATA: u8 = 0x09;
    pub const SUBSCRIPTION_IDENTIFIER: u8 = 0x0B;
    pub const SESSION_EXPIRY_INTERVAL: u8 = 0x11;
    pub const ASSIGNED_CLIENT_ID: u8 = 0x12;
    pub const SERVER_KEEP_ALIVE: u8 = 0x13;
    pub const AUTHENTICATION_METHOD: u8 = 0x15;
    pub const AUTHENTICATION_DATA: u8 = 0x16;
    pub const REQUEST_PROBLEM_INFORMATION: u8 = 0x17;
    pub const WILL_DELAY_INTERVAL: u8 = 0x18;
    pub const REQUEST_RESPONSE_INFORMATION: u8 = 0x19;
    pub const RESPONSE_INFORMATION: u8 = 0x1A;
    pub const SERVER_REFERENCE: u8 = 0x1C;
    pub const REASON_STRING: u8 = 0x1F;
    pub const RECEIVE_MAXIMUM: u8 = 0x21;
    pub const TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
    pub const TOPIC_ALIAS: u8 = 0x23;
    pub const MAXIMUM_QOS: u8 = 0x24;
    pub const RETAIN_AVAILABLE: u8 = 0x25;
    pub const USER_PROPERTY: u8 = 0x26;
    pub const MAXIMUM_PACKET_SIZE: u8 = 0x27;
    pub const WILDCARD_SUBSCRIPTION_AVAILABLE: u8 = 0x28;
    pub const SUBSCRIPTION_IDS_AVAILABLE: u8 = 0x29;
    pub const SHARED_SUBSCRIPTION_AVAILABLE: u8 = 0x2A;
}

/// All MQTT v5 properties in one flat struct. Each packet type uses a subset.
#[derive(Debug, Default, Clone)]
pub struct Properties {
    pub payload_format_indicator: Option<u8>,
    pub message_expiry_interval: Option<u32>,
    pub content_type: Option<String>,
    pub response_topic: Option<String>,
    pub correlation_data: Option<Vec<u8>>,
    pub subscription_identifier: Option<u32>,
    pub session_expiry_interval: Option<u32>,
    pub assigned_client_id: Option<String>,
    pub server_keep_alive: Option<u16>,
    pub authentication_method: Option<String>,
    pub authentication_data: Option<Vec<u8>>,
    pub request_problem_information: Option<bool>,
    pub will_delay_interval: Option<u32>,
    pub request_response_information: Option<bool>,
    pub response_information: Option<String>,
    pub server_reference: Option<String>,
    pub reason_string: Option<String>,
    pub receive_maximum: Option<u16>,
    pub topic_alias_maximum: Option<u16>,
    pub topic_alias: Option<u16>,
    pub maximum_qos: Option<u8>,
    pub retain_available: Option<bool>,
    pub user_properties: Vec<(String, String)>,
    pub maximum_packet_size: Option<u32>,
    pub wildcard_subscription_available: Option<bool>,
    pub subscription_ids_available: Option<bool>,
    pub shared_subscription_available: Option<bool>,
}

impl Properties {
    /// Encode all set properties into `buf`, prefixed with their VBI length.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut props: Vec<u8> = Vec::new();

        macro_rules! one_byte {
            ($id:expr, $val:expr) => {
                if let Some(v) = $val {
                    props.push($id);
                    props.push(v as u8);
                }
            };
        }
        macro_rules! two_byte {
            ($id:expr, $val:expr) => {
                if let Some(v) = $val {
                    props.push($id);
                    push_u16(v, &mut props);
                }
            };
        }
        macro_rules! four_byte {
            ($id:expr, $val:expr) => {
                if let Some(v) = $val {
                    props.push($id);
                    push_u32(v, &mut props);
                }
            };
        }
        macro_rules! utf8 {
            ($id:expr, $val:expr) => {
                if let Some(v) = &$val {
                    props.push($id);
                    push_str(v, &mut props);
                }
            };
        }
        macro_rules! binary {
            ($id:expr, $val:expr) => {
                if let Some(v) = &$val {
                    props.push($id);
                    push_bytes(v, &mut props);
                }
            };
        }

        one_byte!(
            prop::PAYLOAD_FORMAT_INDICATOR,
            self.payload_format_indicator
        );
        four_byte!(prop::MESSAGE_EXPIRY_INTERVAL, self.message_expiry_interval);
        utf8!(prop::CONTENT_TYPE, self.content_type);
        utf8!(prop::RESPONSE_TOPIC, self.response_topic);
        binary!(prop::CORRELATION_DATA, self.correlation_data);
        if let Some(v) = self.subscription_identifier {
            props.push(prop::SUBSCRIPTION_IDENTIFIER);
            encode_vbi(v, &mut props);
        }
        four_byte!(prop::SESSION_EXPIRY_INTERVAL, self.session_expiry_interval);
        utf8!(prop::ASSIGNED_CLIENT_ID, self.assigned_client_id);
        two_byte!(prop::SERVER_KEEP_ALIVE, self.server_keep_alive);
        utf8!(prop::AUTHENTICATION_METHOD, self.authentication_method);
        binary!(prop::AUTHENTICATION_DATA, self.authentication_data);
        one_byte!(
            prop::REQUEST_PROBLEM_INFORMATION,
            self.request_problem_information.map(|b| b as u8)
        );
        four_byte!(prop::WILL_DELAY_INTERVAL, self.will_delay_interval);
        one_byte!(
            prop::REQUEST_RESPONSE_INFORMATION,
            self.request_response_information.map(|b| b as u8)
        );
        utf8!(prop::RESPONSE_INFORMATION, self.response_information);
        utf8!(prop::SERVER_REFERENCE, self.server_reference);
        utf8!(prop::REASON_STRING, self.reason_string);
        two_byte!(prop::RECEIVE_MAXIMUM, self.receive_maximum);
        two_byte!(prop::TOPIC_ALIAS_MAXIMUM, self.topic_alias_maximum);
        two_byte!(prop::TOPIC_ALIAS, self.topic_alias);
        one_byte!(prop::MAXIMUM_QOS, self.maximum_qos);
        one_byte!(
            prop::RETAIN_AVAILABLE,
            self.retain_available.map(|b| b as u8)
        );
        for (k, v) in &self.user_properties {
            props.push(prop::USER_PROPERTY);
            push_str(k, &mut props);
            push_str(v, &mut props);
        }
        four_byte!(prop::MAXIMUM_PACKET_SIZE, self.maximum_packet_size);
        one_byte!(
            prop::WILDCARD_SUBSCRIPTION_AVAILABLE,
            self.wildcard_subscription_available.map(|b| b as u8)
        );
        one_byte!(
            prop::SUBSCRIPTION_IDS_AVAILABLE,
            self.subscription_ids_available.map(|b| b as u8)
        );
        one_byte!(
            prop::SHARED_SUBSCRIPTION_AVAILABLE,
            self.shared_subscription_available.map(|b| b as u8)
        );

        encode_vbi(props.len() as u32, buf);
        buf.extend_from_slice(&props);
    }

    /// Decode properties from `data[pos..]`. On entry `pos` points at the VBI
    /// length prefix; on return `pos` is just past the last property byte.
    pub fn decode(data: &[u8], pos: &mut usize) -> Result<Self, DecodeError> {
        let props_len = decode_vbi(data, pos)? as usize;
        let end = *pos + props_len;
        if end > data.len() {
            return Err(DecodeError::InsufficientData);
        }

        let mut p = Properties::default();

        while *pos < end {
            let id = data[*pos];
            *pos += 1;
            match id {
                prop::PAYLOAD_FORMAT_INDICATOR => {
                    p.payload_format_indicator = Some(data[*pos]);
                    *pos += 1;
                }
                prop::MESSAGE_EXPIRY_INTERVAL => {
                    p.message_expiry_interval = Some(read_u32(data, pos)?);
                }
                prop::CONTENT_TYPE => {
                    p.content_type = Some(read_str(data, pos)?);
                }
                prop::RESPONSE_TOPIC => {
                    p.response_topic = Some(read_str(data, pos)?);
                }
                prop::CORRELATION_DATA => {
                    p.correlation_data = Some(read_bytes(data, pos)?);
                }
                prop::SUBSCRIPTION_IDENTIFIER => {
                    p.subscription_identifier = Some(decode_vbi(data, pos)?);
                }
                prop::SESSION_EXPIRY_INTERVAL => {
                    p.session_expiry_interval = Some(read_u32(data, pos)?);
                }
                prop::ASSIGNED_CLIENT_ID => {
                    p.assigned_client_id = Some(read_str(data, pos)?);
                }
                prop::SERVER_KEEP_ALIVE => {
                    p.server_keep_alive = Some(read_u16(data, pos)?);
                }
                prop::AUTHENTICATION_METHOD => {
                    p.authentication_method = Some(read_str(data, pos)?);
                }
                prop::AUTHENTICATION_DATA => {
                    p.authentication_data = Some(read_bytes(data, pos)?);
                }
                prop::REQUEST_PROBLEM_INFORMATION => {
                    p.request_problem_information = Some(data[*pos] != 0);
                    *pos += 1;
                }
                prop::WILL_DELAY_INTERVAL => {
                    p.will_delay_interval = Some(read_u32(data, pos)?);
                }
                prop::REQUEST_RESPONSE_INFORMATION => {
                    p.request_response_information = Some(data[*pos] != 0);
                    *pos += 1;
                }
                prop::RESPONSE_INFORMATION => {
                    p.response_information = Some(read_str(data, pos)?);
                }
                prop::SERVER_REFERENCE => {
                    p.server_reference = Some(read_str(data, pos)?);
                }
                prop::REASON_STRING => {
                    p.reason_string = Some(read_str(data, pos)?);
                }
                prop::RECEIVE_MAXIMUM => {
                    p.receive_maximum = Some(read_u16(data, pos)?);
                }
                prop::TOPIC_ALIAS_MAXIMUM => {
                    p.topic_alias_maximum = Some(read_u16(data, pos)?);
                }
                prop::TOPIC_ALIAS => {
                    p.topic_alias = Some(read_u16(data, pos)?);
                }
                prop::MAXIMUM_QOS => {
                    p.maximum_qos = Some(data[*pos]);
                    *pos += 1;
                }
                prop::RETAIN_AVAILABLE => {
                    p.retain_available = Some(data[*pos] != 0);
                    *pos += 1;
                }
                prop::USER_PROPERTY => {
                    let k = read_str(data, pos)?;
                    let v = read_str(data, pos)?;
                    p.user_properties.push((k, v));
                }
                prop::MAXIMUM_PACKET_SIZE => {
                    p.maximum_packet_size = Some(read_u32(data, pos)?);
                }
                prop::WILDCARD_SUBSCRIPTION_AVAILABLE => {
                    p.wildcard_subscription_available = Some(data[*pos] != 0);
                    *pos += 1;
                }
                prop::SUBSCRIPTION_IDS_AVAILABLE => {
                    p.subscription_ids_available = Some(data[*pos] != 0);
                    *pos += 1;
                }
                prop::SHARED_SUBSCRIPTION_AVAILABLE => {
                    p.shared_subscription_available = Some(data[*pos] != 0);
                    *pos += 1;
                }
                unknown => {
                    return Err(DecodeError::Protocol(format!(
                        "unknown property id: {unknown:#04x}"
                    )));
                }
            }
        }

        Ok(p)
    }
}

// ─── Packet types ─────────────────────────────────────────────────────────────

/// QoS levels [MQTT-4.3].
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum QoS {
    #[default]
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl std::fmt::Display for QoS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QoS::AtMostOnce => write!(f, "QoS0"),
            QoS::AtLeastOnce => write!(f, "QoS1"),
            QoS::ExactlyOnce => write!(f, "QoS2"),
        }
    }
}

impl TryFrom<u8> for QoS {
    type Error = DecodeError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(QoS::AtMostOnce),
            1 => Ok(QoS::AtLeastOnce),
            2 => Ok(QoS::ExactlyOnce),
            _ => Err(DecodeError::Protocol(format!("invalid QoS: {v}"))),
        }
    }
}

/// Parameters for building a CONNECT packet.
#[derive(Debug, Clone)]
pub struct ConnectParams {
    pub client_id: String,
    pub keep_alive: u16,
    pub clean_start: bool,
    pub properties: Properties,
    /// Optional will message [MQTT-3.1.2-7].
    pub will: Option<WillParams>,
    /// Optional username [MQTT-3.1.3-4].
    pub username: Option<String>,
    /// Optional password [MQTT-3.1.3-5].
    pub password: Option<Vec<u8>>,
}

/// Will message parameters sent inside CONNECT [MQTT-3.1.2-8..13].
#[derive(Debug, Clone)]
pub struct WillParams {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: QoS,
    pub retain: bool,
    pub properties: Properties,
}

impl WillParams {
    pub fn new(topic: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            topic: topic.into(),
            payload: payload.into(),
            qos: QoS::AtMostOnce,
            retain: false,
            properties: Properties::default(),
        }
    }
}

impl ConnectParams {
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            keep_alive: 60,
            clean_start: true,
            properties: Properties::default(),
            will: None,
            username: None,
            password: None,
        }
    }
}

/// A received CONNACK packet [MQTT-3.2].
#[derive(Debug, Clone)]
pub struct ConnAck {
    /// True when the broker restored a previous session [MQTT-3.2.2-1].
    pub session_present: bool,
    /// 0x00 = Success [MQTT-3.2.2-2].
    pub reason_code: u8,
    pub properties: Properties,
}

/// A received PUBLISH packet [MQTT-3.3].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Publish {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    pub topic: String,
    pub packet_id: Option<u16>,
    pub properties: Properties,
    pub payload: Vec<u8>,
}

/// Parameters for building a PUBLISH packet.
#[derive(Debug, Clone)]
pub struct PublishParams {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: QoS,
    pub retain: bool,
    pub dup: bool,
    pub packet_id: Option<u16>,
    pub properties: Properties,
}

impl PublishParams {
    pub fn qos0(topic: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            topic: topic.into(),
            payload: payload.into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            properties: Properties::default(),
        }
    }

    pub fn qos1(topic: impl Into<String>, payload: impl Into<Vec<u8>>, packet_id: u16) -> Self {
        Self {
            topic: topic.into(),
            payload: payload.into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(packet_id),
            properties: Properties::default(),
        }
    }

    pub fn qos2(topic: impl Into<String>, payload: impl Into<Vec<u8>>, packet_id: u16) -> Self {
        Self {
            topic: topic.into(),
            payload: payload.into(),
            qos: QoS::ExactlyOnce,
            retain: false,
            dup: false,
            packet_id: Some(packet_id),
            properties: Properties::default(),
        }
    }

    pub fn retained(topic: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            topic: topic.into(),
            payload: payload.into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            properties: Properties::default(),
        }
    }
}

/// A received acknowledgement (PUBACK / PUBREC / PUBREL / PUBCOMP).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PubAck {
    pub packet_id: u16,
    pub reason_code: u8,
    pub properties: Properties,
}

/// Parameters for a SUBSCRIBE packet.
#[derive(Debug, Clone)]
pub struct SubscribeParams {
    pub packet_id: u16,
    pub filters: Vec<(String, SubscribeOptions)>,
    pub properties: Properties,
}

#[derive(Debug, Clone, Default)]
pub struct SubscribeOptions {
    pub qos: QoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    /// 0 = send retained on subscribe, 1 = only if new sub, 2 = never send
    pub retain_handling: u8,
}

impl SubscribeParams {
    /// Convenience: single-topic subscription with default options.
    pub fn simple(packet_id: u16, topic: impl Into<String>, qos: QoS) -> Self {
        Self {
            packet_id,
            filters: vec![(
                topic.into(),
                SubscribeOptions {
                    qos,
                    ..Default::default()
                },
            )],
            properties: Properties::default(),
        }
    }
}

/// A received SUBACK packet [MQTT-3.9].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SubAck {
    pub packet_id: u16,
    pub reason_codes: Vec<u8>,
    pub properties: Properties,
}

/// Parameters for an UNSUBSCRIBE packet.
#[derive(Debug, Clone)]
pub struct UnsubscribeParams {
    pub packet_id: u16,
    pub filters: Vec<String>,
    pub properties: Properties,
}

impl UnsubscribeParams {
    pub fn simple(packet_id: u16, filter: impl Into<String>) -> Self {
        Self {
            packet_id,
            filters: vec![filter.into()],
            properties: Properties::default(),
        }
    }
}

/// A received UNSUBACK packet [MQTT-3.11].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UnsubAck {
    pub packet_id: u16,
    pub reason_codes: Vec<u8>,
    pub properties: Properties,
}

/// A received DISCONNECT packet [MQTT-3.14].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Disconnect {
    pub reason_code: u8,
    pub properties: Properties,
}

/// All packets that can be received from a broker.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Packet {
    ConnAck(ConnAck),
    Publish(Publish),
    PubAck(PubAck),
    PubRec(PubAck),
    PubRel(PubAck),
    PubComp(PubAck),
    SubAck(SubAck),
    UnsubAck(UnsubAck),
    PingResp,
    Disconnect(Disconnect),
    Auth {
        reason_code: u8,
        properties: Properties,
    },
}

// ─── Display (concise human-readable output) ─────────────────────────────────

impl std::fmt::Display for ConnAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CONNACK(reason={:#04x}, session_present={})",
            self.reason_code, self.session_present
        )
    }
}

impl std::fmt::Display for Publish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PUBLISH(topic=\"{}\", qos={}, retain={}, payload={} bytes)",
            self.topic,
            self.qos,
            self.retain,
            self.payload.len()
        )
    }
}

impl std::fmt::Display for PubAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "id={}, reason={:#04x}", self.packet_id, self.reason_code)
    }
}

impl std::fmt::Display for SubAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SUBACK(id={}, reasons={:?})",
            self.packet_id, self.reason_codes
        )
    }
}

impl std::fmt::Display for UnsubAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UNSUBACK(id={}, reasons={:?})",
            self.packet_id, self.reason_codes
        )
    }
}

impl std::fmt::Display for Disconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DISCONNECT(reason={:#04x})", self.reason_code)
    }
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Packet::ConnAck(c) => write!(f, "{c}"),
            Packet::Publish(p) => write!(f, "{p}"),
            Packet::PubAck(a) => write!(f, "PUBACK({a})"),
            Packet::PubRec(a) => write!(f, "PUBREC({a})"),
            Packet::PubRel(a) => write!(f, "PUBREL({a})"),
            Packet::PubComp(a) => write!(f, "PUBCOMP({a})"),
            Packet::SubAck(s) => write!(f, "{s}"),
            Packet::UnsubAck(s) => write!(f, "{s}"),
            Packet::PingResp => write!(f, "PINGRESP"),
            Packet::Disconnect(d) => write!(f, "{d}"),
            Packet::Auth { reason_code, .. } => write!(f, "AUTH(reason={reason_code:#04x})"),
        }
    }
}

// ─── Encoding ─────────────────────────────────────────────────────────────────

fn prepend_fixed_header(packet_type_and_flags: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(packet_type_and_flags);
    encode_vbi(body.len() as u32, &mut out);
    out.extend_from_slice(&body);
    out
}

/// Encode a CONNECT packet [MQTT-3.1].
pub fn encode_connect(p: &ConnectParams) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();

    // Protocol name [MQTT-3.1.2-1]
    push_str("MQTT", &mut body);
    // Protocol version = 5 [MQTT-3.1.2-2]
    body.push(5);

    // Connect flags [MQTT-3.1.2-3]
    let mut flags: u8 = if p.clean_start { 0x02 } else { 0x00 };
    if let Some(ref will) = p.will {
        flags |= 0x04; // Will Flag [MQTT-3.1.2-7]
        flags |= (will.qos as u8) << 3; // Will QoS [MQTT-3.1.2-11]
        if will.retain {
            flags |= 0x20; // Will Retain [MQTT-3.1.2-13]
        }
    }
    if p.username.is_some() {
        flags |= 0x80; // Username Flag [MQTT-3.1.2-15]
    }
    if p.password.is_some() {
        flags |= 0x40; // Password Flag [MQTT-3.1.2-17]
    }
    body.push(flags);

    // Keep alive [MQTT-3.1.2-21]
    push_u16(p.keep_alive, &mut body);

    // Connect properties [MQTT-3.1.2-11]
    p.properties.encode(&mut body);

    // Payload: client identifier [MQTT-3.1.3-3]
    push_str(&p.client_id, &mut body);

    // Will properties, topic, payload [MQTT-3.1.3-9..10]
    if let Some(ref will) = p.will {
        will.properties.encode(&mut body);
        push_str(&will.topic, &mut body);
        push_bytes(&will.payload, &mut body);
    }

    // Username [MQTT-3.1.3-4]
    if let Some(ref username) = p.username {
        push_str(username, &mut body);
    }

    // Password [MQTT-3.1.3-5]
    if let Some(ref password) = p.password {
        push_bytes(password, &mut body);
    }

    prepend_fixed_header(0x10, body)
}

/// Encode a PUBLISH packet [MQTT-3.3].
pub fn encode_publish(p: &PublishParams) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();

    // Topic name [MQTT-3.3.2-1]
    push_str(&p.topic, &mut body);

    // Packet identifier — only present for QoS > 0 [MQTT-3.3.2-2]
    if let Some(id) = p.packet_id {
        push_u16(id, &mut body);
    }

    p.properties.encode(&mut body);
    body.extend_from_slice(&p.payload);

    let flags: u8 = (p.retain as u8) | ((p.qos as u8) << 1) | ((p.dup as u8) << 3);
    prepend_fixed_header(0x30 | flags, body)
}

/// Encode a PUBACK / PUBREC / PUBREL / PUBCOMP packet.
/// `packet_type_nibble`: 4 for PUBACK, 5 for PUBREC, 6 for PUBREL, 7 for PUBCOMP.
/// PUBREL has a fixed flag of 0x02 [MQTT-3.6.1-1].
pub fn encode_pub_response(packet_type_nibble: u8, packet_id: u16, reason_code: u8) -> Vec<u8> {
    // Per [MQTT-3.4.2-1]: reason code + props may be omitted when code == 0.
    let type_flags: u8 = if packet_type_nibble == 6 {
        0x62 // PUBREL fixed flags
    } else {
        packet_type_nibble << 4
    };

    if reason_code == 0x00 {
        // Short form: just packet ID, remaining length = 2
        let mut out = Vec::with_capacity(4);
        out.push(type_flags);
        out.push(2);
        push_u16(packet_id, &mut out);
        out
    } else {
        let mut body: Vec<u8> = Vec::new();
        push_u16(packet_id, &mut body);
        body.push(reason_code);
        Properties::default().encode(&mut body);
        prepend_fixed_header(type_flags, body)
    }
}

/// Encode a SUBSCRIBE packet [MQTT-3.8].
pub fn encode_subscribe(p: &SubscribeParams) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();

    push_u16(p.packet_id, &mut body);
    p.properties.encode(&mut body);

    for (filter, opts) in &p.filters {
        push_str(filter, &mut body);
        // Subscription options byte [MQTT-3.8.3-1]
        let opt_byte: u8 = (opts.qos as u8)
            | ((opts.no_local as u8) << 2)
            | ((opts.retain_as_published as u8) << 3)
            | ((opts.retain_handling & 0x03) << 4);
        body.push(opt_byte);
    }

    prepend_fixed_header(0x82, body) // SUBSCRIBE has fixed flags 0x02 [MQTT-3.8.1-1]
}

/// Encode an UNSUBSCRIBE packet [MQTT-3.10].
pub fn encode_unsubscribe(p: &UnsubscribeParams) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();

    push_u16(p.packet_id, &mut body);
    p.properties.encode(&mut body);

    for filter in &p.filters {
        push_str(filter, &mut body);
    }

    prepend_fixed_header(0xA2, body) // UNSUBSCRIBE has fixed flags 0x02 [MQTT-3.10.1-1]
}

/// Encode a PINGREQ packet [MQTT-3.12].
pub fn encode_pingreq() -> Vec<u8> {
    vec![0xC0, 0x00]
}

/// Encode a DISCONNECT packet [MQTT-3.14].
/// When `reason_code` is 0x00 (Normal) the short form is used [MQTT-3.14.2-1].
pub fn encode_disconnect(reason_code: u8) -> Vec<u8> {
    if reason_code == 0x00 {
        vec![0xE0, 0x00]
    } else {
        let mut body: Vec<u8> = Vec::new();
        body.push(reason_code);
        Properties::default().encode(&mut body);
        prepend_fixed_header(0xE0, body)
    }
}

/// Encode a DISCONNECT packet with properties [MQTT-3.14].
pub fn encode_disconnect_with_properties(reason_code: u8, properties: &Properties) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(reason_code);
    properties.encode(&mut body);
    prepend_fixed_header(0xE0, body)
}

/// Encode an AUTH packet [MQTT-3.15].
pub fn encode_auth(reason_code: u8, properties: &Properties) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(reason_code);
    properties.encode(&mut body);
    prepend_fixed_header(0xF0, body)
}

// ─── Decoding ─────────────────────────────────────────────────────────────────

/// Try to decode one packet from `buf`.
///
/// Returns `Ok(Some((packet, bytes_consumed)))` when a complete packet is
/// available, `Ok(None)` when more data is needed, or `Err` on a protocol
/// error.
pub fn decode_packet(buf: &[u8]) -> Result<Option<(Packet, usize)>, DecodeError> {
    if buf.is_empty() {
        return Ok(None);
    }

    // Parse fixed header to find remaining_length.
    let mut pos = 1usize; // skip first byte (type + flags)
    let remaining = match decode_vbi(buf, &mut pos) {
        Ok(v) => v as usize,
        Err(DecodeError::InsufficientData) => return Ok(None),
        Err(e) => return Err(e),
    };

    let total = pos + remaining;
    if buf.len() < total {
        return Ok(None);
    }

    let packet_type = buf[0] >> 4;
    let flags = buf[0] & 0x0F;
    let body = &buf[pos..total];

    let packet = match packet_type {
        // CONNACK
        2 => decode_connack(body, flags)?,
        // PUBLISH
        3 => decode_publish(body, flags)?,
        // PUBACK
        4 => Packet::PubAck(decode_pub_ack(body)?),
        // PUBREC
        5 => Packet::PubRec(decode_pub_ack(body)?),
        // PUBREL
        6 => Packet::PubRel(decode_pub_ack(body)?),
        // PUBCOMP
        7 => Packet::PubComp(decode_pub_ack(body)?),
        // SUBACK
        9 => Packet::SubAck(decode_suback(body)?),
        // UNSUBACK
        11 => Packet::UnsubAck(decode_unsuback(body)?),
        // PINGRESP
        13 => Packet::PingResp,
        // DISCONNECT
        14 => Packet::Disconnect(decode_disconnect(body)?),
        // AUTH
        15 => decode_auth(body)?,
        t => return Err(DecodeError::UnknownPacketType(t)),
    };

    Ok(Some((packet, total)))
}

fn decode_connack(body: &[u8], _flags: u8) -> Result<Packet, DecodeError> {
    if body.len() < 2 {
        return Err(DecodeError::InsufficientData);
    }
    let session_present = body[0] & 0x01 != 0;
    let reason_code = body[1];
    let mut pos = 2;
    let properties = if pos < body.len() {
        Properties::decode(body, &mut pos)?
    } else {
        Properties::default()
    };
    Ok(Packet::ConnAck(ConnAck {
        session_present,
        reason_code,
        properties,
    }))
}

fn decode_publish(body: &[u8], flags: u8) -> Result<Packet, DecodeError> {
    let dup = flags & 0x08 != 0;
    let qos = QoS::try_from((flags >> 1) & 0x03)?;
    let retain = flags & 0x01 != 0;

    let mut pos = 0;
    let topic = read_str(body, &mut pos)?;

    let packet_id = if qos != QoS::AtMostOnce {
        Some(read_u16(body, &mut pos)?)
    } else {
        None
    };

    let properties = Properties::decode(body, &mut pos)?;
    let payload = body[pos..].to_vec();

    Ok(Packet::Publish(Publish {
        dup,
        qos,
        retain,
        topic,
        packet_id,
        properties,
        payload,
    }))
}

fn decode_pub_ack(body: &[u8]) -> Result<PubAck, DecodeError> {
    if body.len() < 2 {
        return Err(DecodeError::InsufficientData);
    }
    let mut pos = 0;
    let packet_id = read_u16(body, &mut pos)?;
    // Reason code may be absent when remaining_length == 2 (success assumed).
    let reason_code = if body.len() > 2 { body[pos] } else { 0x00 };
    if body.len() > 2 {
        pos += 1;
    }
    let properties = if pos < body.len() {
        Properties::decode(body, &mut pos)?
    } else {
        Properties::default()
    };
    Ok(PubAck {
        packet_id,
        reason_code,
        properties,
    })
}

fn decode_suback(body: &[u8]) -> Result<SubAck, DecodeError> {
    let mut pos = 0;
    let packet_id = read_u16(body, &mut pos)?;
    let properties = Properties::decode(body, &mut pos)?;
    let reason_codes = body[pos..].to_vec();
    Ok(SubAck {
        packet_id,
        reason_codes,
        properties,
    })
}

fn decode_unsuback(body: &[u8]) -> Result<UnsubAck, DecodeError> {
    let mut pos = 0;
    let packet_id = read_u16(body, &mut pos)?;
    let properties = Properties::decode(body, &mut pos)?;
    let reason_codes = body[pos..].to_vec();
    Ok(UnsubAck {
        packet_id,
        reason_codes,
        properties,
    })
}

fn decode_disconnect(body: &[u8]) -> Result<Disconnect, DecodeError> {
    if body.is_empty() {
        return Ok(Disconnect {
            reason_code: 0x00,
            properties: Properties::default(),
        });
    }
    let reason_code = body[0];
    let mut pos = 1;
    let properties = if pos < body.len() {
        Properties::decode(body, &mut pos)?
    } else {
        Properties::default()
    };
    Ok(Disconnect {
        reason_code,
        properties,
    })
}

fn decode_auth(body: &[u8]) -> Result<Packet, DecodeError> {
    if body.is_empty() {
        return Ok(Packet::Auth {
            reason_code: 0x00,
            properties: Properties::default(),
        });
    }
    let reason_code = body[0];
    let mut pos = 1;
    let properties = if pos < body.len() {
        Properties::decode(body, &mut pos)?
    } else {
        Properties::default()
    };
    Ok(Packet::Auth {
        reason_code,
        properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_props() -> Properties {
        Properties::default()
    }

    #[test]
    fn display_qos() {
        assert_eq!(QoS::AtMostOnce.to_string(), "QoS0");
        assert_eq!(QoS::AtLeastOnce.to_string(), "QoS1");
        assert_eq!(QoS::ExactlyOnce.to_string(), "QoS2");
    }

    #[test]
    fn display_connack() {
        let c = ConnAck {
            session_present: false,
            reason_code: 0x00,
            properties: default_props(),
        };
        assert_eq!(c.to_string(), "CONNACK(reason=0x00, session_present=false)");

        let c = ConnAck {
            session_present: true,
            reason_code: 0x85,
            properties: default_props(),
        };
        assert_eq!(c.to_string(), "CONNACK(reason=0x85, session_present=true)");
    }

    #[test]
    fn display_publish() {
        let p = Publish {
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: true,
            topic: "a/b".into(),
            packet_id: Some(1),
            properties: default_props(),
            payload: vec![0; 42],
        };
        assert_eq!(
            p.to_string(),
            "PUBLISH(topic=\"a/b\", qos=QoS1, retain=true, payload=42 bytes)"
        );
    }

    #[test]
    fn display_puback_variants() {
        let a = PubAck {
            packet_id: 3,
            reason_code: 0x00,
            properties: default_props(),
        };
        assert_eq!(
            Packet::PubAck(a.clone()).to_string(),
            "PUBACK(id=3, reason=0x00)"
        );
        assert_eq!(
            Packet::PubRec(a.clone()).to_string(),
            "PUBREC(id=3, reason=0x00)"
        );
        assert_eq!(
            Packet::PubRel(a.clone()).to_string(),
            "PUBREL(id=3, reason=0x00)"
        );
        assert_eq!(Packet::PubComp(a).to_string(), "PUBCOMP(id=3, reason=0x00)");
    }

    #[test]
    fn display_suback() {
        let s = SubAck {
            packet_id: 1,
            reason_codes: vec![0, 1],
            properties: default_props(),
        };
        assert_eq!(s.to_string(), "SUBACK(id=1, reasons=[0, 1])");
    }

    #[test]
    fn display_unsuback() {
        let u = UnsubAck {
            packet_id: 2,
            reason_codes: vec![0],
            properties: default_props(),
        };
        assert_eq!(u.to_string(), "UNSUBACK(id=2, reasons=[0])");
    }

    #[test]
    fn display_disconnect() {
        let d = Disconnect {
            reason_code: 0x8e,
            properties: default_props(),
        };
        assert_eq!(d.to_string(), "DISCONNECT(reason=0x8e)");
    }

    #[test]
    fn display_pingresp() {
        assert_eq!(Packet::PingResp.to_string(), "PINGRESP");
    }

    #[test]
    fn display_auth() {
        let p = Packet::Auth {
            reason_code: 0x18,
            properties: default_props(),
        };
        assert_eq!(p.to_string(), "AUTH(reason=0x18)");
    }

    // ── VBI roundtrip tests ──────────────────────────────────────────────────

    #[test]
    fn vbi_roundtrip_zero() {
        let mut buf = Vec::new();
        encode_vbi(0, &mut buf);
        let mut pos = 0;
        assert_eq!(decode_vbi(&buf, &mut pos).unwrap(), 0);
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn vbi_roundtrip_one_byte_max() {
        let mut buf = Vec::new();
        encode_vbi(127, &mut buf);
        assert_eq!(buf.len(), 1);
        let mut pos = 0;
        assert_eq!(decode_vbi(&buf, &mut pos).unwrap(), 127);
    }

    #[test]
    fn vbi_roundtrip_two_bytes() {
        let mut buf = Vec::new();
        encode_vbi(128, &mut buf);
        assert_eq!(buf.len(), 2);
        let mut pos = 0;
        assert_eq!(decode_vbi(&buf, &mut pos).unwrap(), 128);
    }

    #[test]
    fn vbi_roundtrip_max() {
        // Maximum VBI value: 268_435_455
        let mut buf = Vec::new();
        encode_vbi(268_435_455, &mut buf);
        assert_eq!(buf.len(), 4);
        let mut pos = 0;
        assert_eq!(decode_vbi(&buf, &mut pos).unwrap(), 268_435_455);
    }

    #[test]
    fn vbi_roundtrip_various() {
        for val in [
            1,
            42,
            127,
            128,
            16383,
            16384,
            2_097_151,
            2_097_152,
            268_435_455,
        ] {
            let mut buf = Vec::new();
            encode_vbi(val, &mut buf);
            let mut pos = 0;
            assert_eq!(
                decode_vbi(&buf, &mut pos).unwrap(),
                val,
                "roundtrip failed for {val}"
            );
        }
    }

    // ── Properties roundtrip tests ───────────────────────────────────────────

    #[test]
    fn properties_roundtrip_empty() {
        let props = Properties::default();
        let mut buf = Vec::new();
        props.encode(&mut buf);
        let mut pos = 0;
        let decoded = Properties::decode(&buf, &mut pos).unwrap();
        assert!(decoded.payload_format_indicator.is_none());
        assert!(decoded.user_properties.is_empty());
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn properties_roundtrip_all_types() {
        let props = Properties {
            payload_format_indicator: Some(1),
            message_expiry_interval: Some(3600),
            content_type: Some("application/json".to_string()),
            response_topic: Some("reply/topic".to_string()),
            correlation_data: Some(b"corr-id".to_vec()),
            subscription_identifier: Some(42),
            session_expiry_interval: Some(300),
            server_keep_alive: Some(120),
            receive_maximum: Some(50),
            topic_alias_maximum: Some(10),
            topic_alias: Some(5),
            maximum_qos: Some(1),
            retain_available: Some(true),
            user_properties: vec![
                ("key1".to_string(), "val1".to_string()),
                ("key2".to_string(), "val2".to_string()),
            ],
            maximum_packet_size: Some(1_048_576),
            wildcard_subscription_available: Some(true),
            subscription_ids_available: Some(false),
            shared_subscription_available: Some(true),
            reason_string: Some("test reason".to_string()),
            request_response_information: Some(true),
            request_problem_information: Some(false),
            will_delay_interval: Some(10),
            ..Properties::default()
        };

        let mut buf = Vec::new();
        props.encode(&mut buf);

        let mut pos = 0;
        let decoded = Properties::decode(&buf, &mut pos).unwrap();
        assert_eq!(pos, buf.len());

        assert_eq!(decoded.payload_format_indicator, Some(1));
        assert_eq!(decoded.message_expiry_interval, Some(3600));
        assert_eq!(decoded.content_type.as_deref(), Some("application/json"));
        assert_eq!(decoded.response_topic.as_deref(), Some("reply/topic"));
        assert_eq!(
            decoded.correlation_data.as_deref(),
            Some(b"corr-id".as_slice())
        );
        assert_eq!(decoded.subscription_identifier, Some(42));
        assert_eq!(decoded.session_expiry_interval, Some(300));
        assert_eq!(decoded.server_keep_alive, Some(120));
        assert_eq!(decoded.receive_maximum, Some(50));
        assert_eq!(decoded.topic_alias_maximum, Some(10));
        assert_eq!(decoded.topic_alias, Some(5));
        assert_eq!(decoded.maximum_qos, Some(1));
        assert_eq!(decoded.retain_available, Some(true));
        assert_eq!(decoded.user_properties.len(), 2);
        assert_eq!(
            decoded.user_properties[0],
            ("key1".to_string(), "val1".to_string())
        );
        assert_eq!(
            decoded.user_properties[1],
            ("key2".to_string(), "val2".to_string())
        );
        assert_eq!(decoded.maximum_packet_size, Some(1_048_576));
        assert_eq!(decoded.wildcard_subscription_available, Some(true));
        assert_eq!(decoded.subscription_ids_available, Some(false));
        assert_eq!(decoded.shared_subscription_available, Some(true));
        assert_eq!(decoded.reason_string.as_deref(), Some("test reason"));
        assert_eq!(decoded.request_response_information, Some(true));
        assert_eq!(decoded.request_problem_information, Some(false));
        assert_eq!(decoded.will_delay_interval, Some(10));
    }

    // ── Packet encode/decode roundtrip tests ─────────────────────────────────

    /// Helper: encode a packet, then decode it via decode_packet, return the result.
    fn roundtrip_decode(encoded: &[u8]) -> Packet {
        let (packet, consumed) = decode_packet(encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        packet
    }

    #[test]
    fn connect_encodes_valid_packet() {
        let params = ConnectParams::new("test-client");
        let encoded = encode_connect(&params);
        // Verify the fixed header: type=1 (CONNECT), flags=0
        assert_eq!(encoded[0], 0x10);
        // Verify protocol name is present
        assert_eq!(&encoded[2..8], b"\x00\x04MQTT");
        // Verify protocol version
        assert_eq!(encoded[8], 5);
    }

    #[test]
    fn connect_with_will_encodes() {
        let mut params = ConnectParams::new("will-client");
        params.will = Some(WillParams {
            topic: "will/topic".to_string(),
            payload: b"will-payload".to_vec(),
            qos: QoS::AtLeastOnce,
            retain: true,
            properties: Properties::default(),
        });
        let encoded = encode_connect(&params);
        assert_eq!(encoded[0], 0x10);
        // Will flag (0x04), Will QoS 1 (0x08), Will Retain (0x20), Clean Start (0x02)
        let flags = encoded[9];
        assert!(flags & 0x04 != 0, "will flag should be set");
        assert!(flags & 0x08 != 0, "will QoS bit should be set");
        assert!(flags & 0x20 != 0, "will retain should be set");
    }

    #[test]
    fn publish_qos0_roundtrip() {
        let params = PublishParams::qos0("test/topic", b"hello".to_vec());
        let encoded = encode_publish(&params);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::Publish(p) => {
                assert_eq!(p.topic, "test/topic");
                assert_eq!(p.payload, b"hello");
                assert_eq!(p.qos, QoS::AtMostOnce);
                assert!(!p.retain);
                assert!(p.packet_id.is_none());
            }
            other => panic!("expected Publish, got {other}"),
        }
    }

    #[test]
    fn publish_qos1_roundtrip() {
        let mut params = PublishParams::qos1("qos1/topic", b"qos1-data".to_vec(), 42);
        params.retain = true;
        let encoded = encode_publish(&params);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::Publish(p) => {
                assert_eq!(p.topic, "qos1/topic");
                assert_eq!(p.payload, b"qos1-data");
                assert_eq!(p.qos, QoS::AtLeastOnce);
                assert!(p.retain);
                assert_eq!(p.packet_id, Some(42));
            }
            other => panic!("expected Publish, got {other}"),
        }
    }

    #[test]
    fn publish_qos2_roundtrip() {
        let mut params = PublishParams::qos2("qos2/topic", Vec::new(), 1000);
        params.properties.content_type = Some("text/plain".to_string());
        let encoded = encode_publish(&params);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::Publish(p) => {
                assert_eq!(p.topic, "qos2/topic");
                assert!(p.payload.is_empty());
                assert_eq!(p.qos, QoS::ExactlyOnce);
                assert_eq!(p.packet_id, Some(1000));
                assert_eq!(p.properties.content_type.as_deref(), Some("text/plain"));
            }
            other => panic!("expected Publish, got {other}"),
        }
    }

    #[test]
    fn publish_with_properties_roundtrip() {
        let props = Properties {
            payload_format_indicator: Some(1),
            message_expiry_interval: Some(60),
            response_topic: Some("reply/here".to_string()),
            correlation_data: Some(b"abc".to_vec()),
            user_properties: vec![("k".to_string(), "v".to_string())],
            ..Properties::default()
        };
        let mut params = PublishParams::qos0("prop/topic", b"with-props".to_vec());
        params.properties = props;
        let encoded = encode_publish(&params);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::Publish(p) => {
                assert_eq!(p.properties.payload_format_indicator, Some(1));
                assert_eq!(p.properties.message_expiry_interval, Some(60));
                assert_eq!(p.properties.response_topic.as_deref(), Some("reply/here"));
                assert_eq!(
                    p.properties.correlation_data.as_deref(),
                    Some(b"abc".as_slice())
                );
                assert_eq!(
                    p.properties.user_properties,
                    vec![("k".to_string(), "v".to_string())]
                );
            }
            other => panic!("expected Publish, got {other}"),
        }
    }

    #[test]
    fn subscribe_encode_decode_structure() {
        // We can't decode SUBSCRIBE (it's a client→server packet), but we can
        // verify it encodes to the expected byte structure.
        let params = SubscribeParams::simple(1, "test/topic", QoS::AtLeastOnce);
        let encoded = encode_subscribe(&params);
        assert_eq!(encoded[0], 0x82); // SUBSCRIBE fixed header
        // After fixed header + remaining length: packet_id (2 bytes)
    }

    #[test]
    fn unsubscribe_encode_structure() {
        let params = UnsubscribeParams::simple(5, "a/b");
        let encoded = encode_unsubscribe(&params);
        assert_eq!(encoded[0], 0xA2); // UNSUBSCRIBE fixed header
    }

    #[test]
    fn pingreq_encoding() {
        let encoded = encode_pingreq();
        assert_eq!(encoded, vec![0xC0, 0x00]);
    }

    #[test]
    fn disconnect_normal_encoding() {
        let encoded = encode_disconnect(0x00);
        assert_eq!(encoded, vec![0xE0, 0x00]);
    }

    #[test]
    fn disconnect_with_reason_encoding() {
        let encoded = encode_disconnect(0x81);
        assert_eq!(encoded[0], 0xE0);
        // Should have reason code in body
        assert!(encoded.len() > 2);
    }

    #[test]
    fn pub_response_roundtrip_puback() {
        let encoded = encode_pub_response(4, 100, 0x00);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::PubAck(a) => {
                assert_eq!(a.packet_id, 100);
                assert_eq!(a.reason_code, 0x00);
            }
            other => panic!("expected PubAck, got {other}"),
        }
    }

    #[test]
    fn pub_response_roundtrip_pubrec() {
        let encoded = encode_pub_response(5, 200, 0x10);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::PubRec(a) => {
                assert_eq!(a.packet_id, 200);
                assert_eq!(a.reason_code, 0x10);
            }
            other => panic!("expected PubRec, got {other}"),
        }
    }

    #[test]
    fn pub_response_roundtrip_pubrel() {
        let encoded = encode_pub_response(6, 300, 0x00);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::PubRel(a) => {
                assert_eq!(a.packet_id, 300);
                assert_eq!(a.reason_code, 0x00);
            }
            other => panic!("expected PubRel, got {other}"),
        }
    }

    #[test]
    fn pub_response_roundtrip_pubcomp() {
        let encoded = encode_pub_response(7, 400, 0x00);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::PubComp(a) => {
                assert_eq!(a.packet_id, 400);
                assert_eq!(a.reason_code, 0x00);
            }
            other => panic!("expected PubComp, got {other}"),
        }
    }

    #[test]
    fn decode_packet_insufficient_data() {
        // Empty buffer
        assert!(decode_packet(&[]).unwrap().is_none());
        // Just the fixed header byte, no remaining length
        assert!(decode_packet(&[0x20]).unwrap().is_none());
        // Fixed header + remaining length says 10, but only 2 bytes of body
        assert!(decode_packet(&[0x20, 0x0A, 0x00, 0x00]).unwrap().is_none());
    }

    #[test]
    fn qos_try_from() {
        assert_eq!(QoS::try_from(0).unwrap(), QoS::AtMostOnce);
        assert_eq!(QoS::try_from(1).unwrap(), QoS::AtLeastOnce);
        assert_eq!(QoS::try_from(2).unwrap(), QoS::ExactlyOnce);
        assert!(QoS::try_from(3).is_err());
    }

    #[test]
    fn subscribe_params_simple() {
        let params = SubscribeParams::simple(5, "a/b/c", QoS::ExactlyOnce);
        assert_eq!(params.packet_id, 5);
        assert_eq!(params.filters.len(), 1);
        assert_eq!(params.filters[0].0, "a/b/c");
        assert_eq!(params.filters[0].1.qos, QoS::ExactlyOnce);
        assert!(!params.filters[0].1.no_local);
        assert!(!params.filters[0].1.retain_as_published);
        assert_eq!(params.filters[0].1.retain_handling, 0);
    }

    #[test]
    fn unsubscribe_params_simple() {
        let params = UnsubscribeParams::simple(3, "x/y");
        assert_eq!(params.packet_id, 3);
        assert_eq!(params.filters, vec!["x/y".to_string()]);
    }

    #[test]
    fn publish_params_qos1() {
        let params = PublishParams::qos1("t/1", b"payload".to_vec(), 7);
        assert_eq!(params.topic, "t/1");
        assert_eq!(params.payload, b"payload");
        assert_eq!(params.qos, QoS::AtLeastOnce);
        assert!(!params.retain);
        assert_eq!(params.packet_id, Some(7));
    }

    #[test]
    fn publish_params_qos2() {
        let params = PublishParams::qos2("t/2", b"data".to_vec(), 99);
        assert_eq!(params.topic, "t/2");
        assert_eq!(params.qos, QoS::ExactlyOnce);
        assert_eq!(params.packet_id, Some(99));
    }

    #[test]
    fn publish_params_retained() {
        let params = PublishParams::retained("t/r", b"kept".to_vec());
        assert_eq!(params.qos, QoS::AtMostOnce);
        assert!(params.retain);
        assert!(params.packet_id.is_none());
    }

    #[test]
    fn will_params_new() {
        let params = WillParams::new("will/t", b"bye".to_vec());
        assert_eq!(params.topic, "will/t");
        assert_eq!(params.payload, b"bye");
        assert_eq!(params.qos, QoS::AtMostOnce);
        assert!(!params.retain);
    }

    // ── Disconnect roundtrip tests ──────────────────────────────────────────

    #[test]
    fn disconnect_normal_roundtrip() {
        // Normal disconnect (0x00) uses short form: [0xE0, 0x00]
        // decode_disconnect with empty body returns reason_code=0x00
        let encoded = encode_disconnect(0x00);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::Disconnect(d) => {
                assert_eq!(d.reason_code, 0x00);
            }
            other => panic!("expected Disconnect, got {other}"),
        }
    }

    #[test]
    fn disconnect_with_reason_roundtrip() {
        let encoded = encode_disconnect(0x81);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::Disconnect(d) => {
                assert_eq!(d.reason_code, 0x81);
            }
            other => panic!("expected Disconnect, got {other}"),
        }
    }

    #[test]
    fn disconnect_with_properties_roundtrip() {
        let props = Properties {
            reason_string: Some("shutting down".to_string()),
            session_expiry_interval: Some(0),
            ..Properties::default()
        };
        let encoded = encode_disconnect_with_properties(0x04, &props);
        let packet = roundtrip_decode(&encoded);
        match packet {
            Packet::Disconnect(d) => {
                assert_eq!(d.reason_code, 0x04);
                assert_eq!(d.properties.reason_string.as_deref(), Some("shutting down"));
                assert_eq!(d.properties.session_expiry_interval, Some(0));
            }
            other => panic!("expected Disconnect, got {other}"),
        }
    }

    // ── CONNACK decode tests ────────────────────────────────────────────────

    #[test]
    fn connack_decode_minimal() {
        // CONNACK: type=2, flags=0 → 0x20, remaining=2, session_present=0, reason=0x00
        let buf = [0x20, 0x02, 0x00, 0x00];
        let packet = roundtrip_decode(&buf);
        match packet {
            Packet::ConnAck(c) => {
                assert!(!c.session_present);
                assert_eq!(c.reason_code, 0x00);
            }
            other => panic!("expected ConnAck, got {other}"),
        }
    }

    #[test]
    fn connack_decode_session_present() {
        // session_present=1, reason=0x00, no properties
        let buf = [0x20, 0x02, 0x01, 0x00];
        let packet = roundtrip_decode(&buf);
        match packet {
            Packet::ConnAck(c) => {
                assert!(c.session_present);
                assert_eq!(c.reason_code, 0x00);
            }
            other => panic!("expected ConnAck, got {other}"),
        }
    }

    #[test]
    fn connack_decode_failure_reason() {
        // session_present=0, reason=0x85 (Client Identifier not valid)
        let buf = [0x20, 0x02, 0x00, 0x85];
        let packet = roundtrip_decode(&buf);
        match packet {
            Packet::ConnAck(c) => {
                assert!(!c.session_present);
                assert_eq!(c.reason_code, 0x85);
            }
            other => panic!("expected ConnAck, got {other}"),
        }
    }

    // ── SUBACK / UNSUBACK decode tests ──────────────────────────────────────

    #[test]
    fn suback_decode() {
        // SUBACK: type=9 → 0x90, packet_id=1, empty properties (VBI=0), reason_codes=[0x00, 0x01]
        let buf = [0x90, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01];
        let packet = roundtrip_decode(&buf);
        match packet {
            Packet::SubAck(s) => {
                assert_eq!(s.packet_id, 1);
                assert_eq!(s.reason_codes, vec![0x00, 0x01]);
            }
            other => panic!("expected SubAck, got {other}"),
        }
    }

    #[test]
    fn unsuback_decode() {
        // UNSUBACK: type=11 → 0xB0, packet_id=5, empty properties (VBI=0), reason_code=[0x00]
        let buf = [0xB0, 0x04, 0x00, 0x05, 0x00, 0x00];
        let packet = roundtrip_decode(&buf);
        match packet {
            Packet::UnsubAck(u) => {
                assert_eq!(u.packet_id, 5);
                assert_eq!(u.reason_codes, vec![0x00]);
            }
            other => panic!("expected UnsubAck, got {other}"),
        }
    }

    // ── AUTH decode tests ───────────────────────────────────────────────────

    #[test]
    fn auth_decode_empty_body() {
        // AUTH with empty body: reason_code defaults to 0x00
        let buf = [0xF0, 0x00];
        let packet = roundtrip_decode(&buf);
        match packet {
            Packet::Auth { reason_code, .. } => {
                assert_eq!(reason_code, 0x00);
            }
            other => panic!("expected Auth, got {other}"),
        }
    }

    #[test]
    fn auth_decode_with_reason() {
        // AUTH with reason_code=0x18 (Continue Authentication), no properties
        let buf = [0xF0, 0x01, 0x18];
        let packet = roundtrip_decode(&buf);
        match packet {
            Packet::Auth { reason_code, .. } => {
                assert_eq!(reason_code, 0x18);
            }
            other => panic!("expected Auth, got {other}"),
        }
    }

    // ── Subscribe encoding structure tests ──────────────────────────────────

    #[test]
    fn subscribe_encode_with_options() {
        let params = SubscribeParams {
            packet_id: 1,
            filters: vec![(
                "test/topic".to_string(),
                SubscribeOptions {
                    qos: QoS::ExactlyOnce,
                    no_local: true,
                    retain_as_published: true,
                    retain_handling: 2,
                },
            )],
            properties: Properties::default(),
        };
        let encoded = encode_subscribe(&params);
        assert_eq!(encoded[0], 0x82);
        // Find the options byte (last byte in the encoded packet)
        let opt_byte = *encoded.last().unwrap();
        // QoS2=0x02, no_local=0x04, retain_as_published=0x08, retain_handling=2<<4=0x20
        assert_eq!(opt_byte, 0x02 | 0x04 | 0x08 | 0x20);
    }

    #[test]
    fn subscribe_encode_multiple_filters() {
        let params = SubscribeParams {
            packet_id: 10,
            filters: vec![
                (
                    "a/b".to_string(),
                    SubscribeOptions {
                        qos: QoS::AtMostOnce,
                        ..Default::default()
                    },
                ),
                (
                    "c/d".to_string(),
                    SubscribeOptions {
                        qos: QoS::AtLeastOnce,
                        ..Default::default()
                    },
                ),
            ],
            properties: Properties::default(),
        };
        let encoded = encode_subscribe(&params);
        assert_eq!(encoded[0], 0x82);
        // Both topic strings should appear in the encoded bytes
        let as_str = String::from_utf8_lossy(&encoded);
        assert!(as_str.contains("a/b"));
        assert!(as_str.contains("c/d"));
    }

    #[test]
    fn unsubscribe_encode_multiple_filters() {
        let params = UnsubscribeParams {
            packet_id: 5,
            filters: vec!["a/b".to_string(), "c/d".to_string()],
            properties: Properties::default(),
        };
        let encoded = encode_unsubscribe(&params);
        assert_eq!(encoded[0], 0xA2);
        let as_str = String::from_utf8_lossy(&encoded);
        assert!(as_str.contains("a/b"));
        assert!(as_str.contains("c/d"));
    }

    // ── Decode error tests ──────────────────────────────────────────────────

    #[test]
    fn decode_unknown_packet_type() {
        // Packet type 0 is reserved
        let buf = [0x00, 0x00];
        assert!(decode_packet(&buf).is_err());
    }

    #[test]
    fn decode_connack_too_short() {
        // CONNACK body needs at least 2 bytes
        let buf = [0x20, 0x01, 0x00];
        assert!(decode_packet(&buf).is_err());
    }

    #[test]
    fn decode_puback_too_short() {
        // PUBACK body needs at least 2 bytes (packet_id)
        let buf = [0x40, 0x01, 0x00];
        assert!(decode_packet(&buf).is_err());
    }
}
