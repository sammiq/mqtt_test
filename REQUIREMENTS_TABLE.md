# MQTT v5.0 Normative Requirements — Test Coverage

Generated: 2026-03-24

## Summary

| Category | Count |
|----------|-------|
| Total normative requirements | 256 |
| Implemented (tested, passing) | 171 |
| Structural (codec/format, implicitly covered) | 37 |
| Client (client-side obligation, not server-testable) | 25 |
| Not tested (with explanation) | 19 |
| WebSocket (out of scope — TCP/TLS only) | 4 |

Test results against Mosquitto: 118/118 MUST pass, 15/15 SHOULD pass, 13/25 MAY detected.

---

## Section 1 — MQTT Control Packet Format

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-1.5.4-1 | MUST | Implemented | UTF-8 strings must not include surrogates U+D800..U+DFFF |
| MQTT-1.5.4-2 | MUST | Implemented | UTF-8 strings must not include null character U+0000 |
| MQTT-1.5.4-3 | MUST | Structural | BOM U+FEFF must not be stripped by receiver. Implicitly handled by codec passing bytes through unchanged. |
| MQTT-1.5.5-1 | MUST | Implemented | Variable Byte Integer must use minimum bytes |
| MQTT-1.5.7-1 | MUST | Structural | String Pair both strings must be valid UTF-8. Enforced by codec encoding. |

## Section 2 — MQTT Control Packet Format (Headers)

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-2.1.3-1 | MUST | Implemented | Reserved flag bits must be set to specified values |
| MQTT-2.2.1-2 | MUST | Structural | QoS 0 PUBLISH must not contain Packet Identifier. Enforced by codec. |
| MQTT-2.2.1-3 | MUST | Implemented | Client must assign non-zero unused Packet Identifier for QoS>0 |
| MQTT-2.2.1-4 | MUST | Implemented | Server must assign non-zero unused Packet Identifier for QoS>0 |
| MQTT-2.2.1-5 | MUST | Structural | PUBACK/PUBREC/PUBREL/PUBCOMP must echo Packet Identifier. Verified implicitly by all QoS 1/2 tests. |
| MQTT-2.2.1-6 | MUST | Structural | SUBACK/UNSUBACK must echo Packet Identifier. Verified implicitly by subscribe/unsubscribe tests. |
| MQTT-2.2.2-1 | MUST | Structural | Zero Property Length when no properties. Enforced by codec encoding. |

## Section 3.1 — CONNECT

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.1.0-1 | MUST | Implemented | First packet from Client must be CONNECT |
| MQTT-3.1.0-2 | MUST | Implemented | Server must treat second CONNECT as Protocol Error |
| MQTT-3.1.2-1 | MUST | Implemented | Server may send CONNACK 0x84 for unsupported protocol, must close connection |
| MQTT-3.1.2-2 | MUST | Implemented | Wrong protocol version: may send CONNACK 0x84, must close connection |
| MQTT-3.1.2-3 | MUST | Implemented | Server must validate reserved flag in CONNECT is 0 |
| MQTT-3.1.2-4 | MUST | Implemented | Clean Start=1: discard existing Session, start new |
| MQTT-3.1.2-5 | MUST | Implemented | Clean Start=0 with existing session: resume |
| MQTT-3.1.2-6 | MUST | Implemented | Clean Start=0 with no session: create new |
| MQTT-3.1.2-7 | MUST | Structural | Will Flag=1: Will Message stored on Server. Verified indirectly by will publish and will delay tests. |
| MQTT-3.1.2-8 | MUST | Implemented | Will Message published after connection closed unexpectedly |
| MQTT-3.1.2-9 | MUST | Structural | Will Flag=1: Will fields must be present in Payload. Enforced by codec encoding. |
| MQTT-3.1.2-10 | MUST | Implemented | Will Message removed once published or on clean DISCONNECT |
| MQTT-3.1.2-11 | MUST | Implemented | Will Flag=0: Will QoS must be 0 |
| MQTT-3.1.2-12 | MUST | Implemented | Will QoS=3 is invalid/malformed |
| MQTT-3.1.2-13 | MUST | Implemented | Will Flag=0: Will Retain must be 0 |
| MQTT-3.1.2-14 | MUST | Implemented | Will Flag=1, Will Retain=0: publish as non-retained |
| MQTT-3.1.2-15 | MUST | Implemented | Will Flag=1, Will Retain=1: publish as retained |
| MQTT-3.1.2-16 | MUST | Structural | Username Flag=0: Username must not be in Payload. Enforced by codec encoding. |
| MQTT-3.1.2-17 | MUST | Structural | Username Flag=1: Username must be in Payload. Enforced by codec encoding. |
| MQTT-3.1.2-18 | MUST | Structural | Password Flag=0: Password must not be in Payload. Enforced by codec encoding. |
| MQTT-3.1.2-19 | MUST | Implemented | Password Flag=1: Password must be in Payload |
| MQTT-3.1.2-20 | MUST | Client | Client must send PINGREQ within Keep Alive. Client-side obligation. |
| MQTT-3.1.2-21 | MUST | Client | Client must use Server Keep Alive if returned. Client-side obligation. |
| MQTT-3.1.2-22 | MUST | Implemented | Server must close connection if no packet within 1.5x Keep Alive |
| MQTT-3.1.2-23 | MUST | Not tested | Client and Server must store Session State if Session Expiry > 0. Partially covered by session tests but not explicitly verified for both sides. |
| MQTT-3.1.2-24 | MUST | Implemented | Server must not send packets exceeding client's Maximum Packet Size |
| MQTT-3.1.2-25 | MUST | Not tested | Server must discard oversized packets silently. Hard to verify discard-and-continue behavior. |
| MQTT-3.1.2-26 | MUST | Implemented | Server must not send Topic Alias greater than client's Topic Alias Maximum |
| MQTT-3.1.2-27 | MUST | Implemented | Topic Alias Maximum absent/zero: Server must not send any Topic Aliases |
| MQTT-3.1.2-28 | MUST | Implemented | Request Response Information=0: Server must not return Response Information |
| MQTT-3.1.2-29 | MUST | Not tested | Request Problem Information=0: Server must not send Reason String/User Properties except on PUBLISH/CONNACK/DISCONNECT. Complex multi-packet verification needed. |
| MQTT-3.1.2-30 | MUST | Client | Client must not send non-AUTH/DISCONNECT before CONNACK when Auth Method set. Client-side obligation. |
| MQTT-3.1.3-1 | MUST | Structural | Payload fields must appear in order. Enforced by codec encoding. |
| MQTT-3.1.3-2 | MUST | Structural | ClientID identifies Session state. Implicit in all session tests. |
| MQTT-3.1.3-3 | MUST | Implemented | ClientID must be present and first in CONNECT Payload |
| MQTT-3.1.3-4 | MUST | Implemented | ClientID must be UTF-8 Encoded String |
| MQTT-3.1.3-5 | MUST | Implemented | Server must allow ClientIDs 1-23 bytes of [0-9a-zA-Z] |
| MQTT-3.1.3-6 | MUST | Not tested | Server may allow zero-length ClientID, must treat as special case. Tested via MQTT-3.1.3-7 (Assigned Client Identifier) but not the "special case" aspect. |
| MQTT-3.1.3-7 | MUST | Implemented | Server must return Assigned Client Identifier for zero-length ClientID |
| MQTT-3.1.3-8 | MUST | Implemented | Server rejecting ClientID: may respond 0x85, must close connection |
| MQTT-3.1.3-9 | MUST | Implemented | New connection before Will Delay passes: must not send Will Message |
| MQTT-3.1.3-10 | MUST | Implemented | Server must maintain order of User Properties in Will Message |
| MQTT-3.1.3-11 | MUST | Structural | Will Topic must be UTF-8 Encoded String. Enforced by codec encoding. |
| MQTT-3.1.3-12 | MUST | Structural | Username must be UTF-8 Encoded String. Enforced by codec encoding. |
| MQTT-3.1.4-1 | MUST | Implemented | Server must validate CONNECT format and close connection if invalid |
| MQTT-3.1.4-2 | MUST | Implemented | Validation failure: Server must close connection |
| MQTT-3.1.4-3 | MUST | Implemented | Duplicate ClientID: Server must send DISCONNECT 0x8E and close old connection |
| MQTT-3.1.4-4 | MUST | Implemented | Server must perform Clean Start processing |
| MQTT-3.1.4-5 | MUST | Implemented | Server must acknowledge CONNECT with CONNACK 0x00 |
| MQTT-3.1.4-6 | MUST | Not tested | Server rejecting CONNECT must not process data after CONNECT except AUTH. Hard to verify server ignores subsequent packets. |

## Section 3.2 — CONNACK

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.2.0-1 | MUST | Implemented | Server must send CONNACK before any other packet (except AUTH) |
| MQTT-3.2.0-2 | MUST | Not tested | Server must not send more than one CONNACK. Would require monitoring for duplicate CONNACK. |
| MQTT-3.2.2-1 | MUST | Not tested | CONNACK flags bits 7-1 must be 0. Would require inspecting raw CONNACK bytes. |
| MQTT-3.2.2-2 | MUST | Implemented | Clean Start=1 accepted: Session Present must be 0 |
| MQTT-3.2.2-3 | MUST | Implemented | Session Present must accompany 0x00 Reason Code |
| MQTT-3.2.2-4 | MUST | Client | Client receiving unexpected Session Present=1 must close connection. Client-side obligation. |
| MQTT-3.2.2-5 | MUST | Client | Client receiving Session Present=0 with local state must discard state. Client-side obligation. |
| MQTT-3.2.2-6 | MUST | Implemented | Non-zero CONNACK Reason Code: Session Present must be 0 |
| MQTT-3.2.2-7 | MUST | Implemented | CONNACK Reason Code >= 128: Server must close connection |
| MQTT-3.2.2-8 | MUST | Structural | CONNACK must use defined Reason Code values. Implicitly verified by all CONNACK parsing. |
| MQTT-3.2.2-9 | MUST | Implemented | Server not supporting QoS 1/2 must send Maximum QoS in CONNACK |
| MQTT-3.2.2-10 | MUST | Implemented | Server not supporting QoS 1/2 must still accept SUBSCRIBE with any QoS |
| MQTT-3.2.2-11 | MUST | Client | Client must not send PUBLISH exceeding server's Maximum QoS. Client-side obligation. |
| MQTT-3.2.2-12 | MUST | Implemented | Server receiving QoS exceeding Maximum QoS must close connection |
| MQTT-3.2.2-13 | MUST | Implemented | Server not supporting retain receiving RETAIN=1 must close connection |
| MQTT-3.2.2-14 | MUST | Implemented | Client receiving Retain Available=0 must not send RETAIN=1 |
| MQTT-3.2.2-15 | MUST | Implemented | Client must not send packets exceeding server's Maximum Packet Size |
| MQTT-3.2.2-16 | MUST | Implemented | Assigned Client Identifier must be unique |
| MQTT-3.2.2-17 | MUST | Implemented | Client must not send Topic Alias greater than server's Topic Alias Maximum |
| MQTT-3.2.2-18 | MUST | Implemented | Topic Alias Maximum absent/0: Client must not send Topic Aliases |
| MQTT-3.2.2-19 | MUST | Implemented | Server must not send Response Information exceeding Maximum Packet Size |
| MQTT-3.2.2-20 | MUST | Implemented | Server must not send Server Reference exceeding Maximum Packet Size |
| MQTT-3.2.2-21 | MUST | Implemented | Client must use Server Keep Alive value |
| MQTT-3.2.2-22 | MUST | Not tested | Server not sending Server Keep Alive must use Client's value. Implicitly true but not isolated. |

## Section 3.3 — PUBLISH

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.3.1-1 | MUST | Implemented | DUP=1 when re-delivering PUBLISH |
| MQTT-3.3.1-2 | MUST | Implemented | DUP must be 0 for all QoS 0 messages |
| MQTT-3.3.1-3 | MUST | Client | Outgoing DUP determined solely by retransmission status. Client-side obligation. |
| MQTT-3.3.1-4 | MUST | Implemented | QoS bits must not both be 1 (QoS 3 invalid) |
| MQTT-3.3.1-5 | MUST | Implemented | RETAIN=1: replace existing retained message |
| MQTT-3.3.1-6 | MUST | Implemented | Zero-byte retained payload: remove existing retained message |
| MQTT-3.3.1-7 | MUST | Implemented | Zero-byte retained payload must not be stored |
| MQTT-3.3.1-8 | MUST | Implemented | RETAIN=0: must not store or replace retained messages |
| MQTT-3.3.1-9 | MUST | Implemented | Retain Handling=0: send retained messages on subscribe |
| MQTT-3.3.1-10 | MUST | Implemented | Retain Handling=1: send retained only if new subscription |
| MQTT-3.3.1-11 | MUST | Implemented | Retain Handling=2: must not send retained messages |
| MQTT-3.3.1-12 | MUST | Implemented | Retain As Published=0: set RETAIN=0 when forwarding |
| MQTT-3.3.1-13 | MUST | Implemented | Retain As Published=1: RETAIN matches received PUBLISH |
| MQTT-3.3.2-1 | MUST | Implemented | Topic Name must be UTF-8 Encoded String |
| MQTT-3.3.2-2 | MUST | Implemented | Topic Name in PUBLISH must not contain wildcards |
| MQTT-3.3.2-3 | MUST | Implemented | Server-to-client Topic Name must match subscription filter |
| MQTT-3.3.2-4 | MUST | Implemented | Payload Format Indicator sent unaltered to subscribers |
| MQTT-3.3.2-5 | MUST | Not tested | Server must delete expired messages. Partially covered by message expiry test but not deletion verification. |
| MQTT-3.3.2-6 | MUST | Implemented | Forwarded PUBLISH must contain adjusted Message Expiry Interval |
| MQTT-3.3.2-7 | MUST | Implemented | Topic Alias mappings must not carry across connections |
| MQTT-3.3.2-8 | MUST | Implemented | Must not send Topic Alias value 0 |
| MQTT-3.3.2-9 | MUST | Implemented | Client must not send Topic Alias exceeding server maximum |
| MQTT-3.3.2-10 | MUST | Implemented | Client must accept valid Topic Alias values from server |
| MQTT-3.3.2-11 | MUST | Implemented | Server must not send Topic Alias exceeding client maximum |
| MQTT-3.3.2-12 | MUST | Implemented | Server must accept valid Topic Alias values from client |
| MQTT-3.3.2-13 | MUST | Implemented | Response Topic must be UTF-8 Encoded String |
| MQTT-3.3.2-14 | MUST | Implemented | Response Topic must not contain wildcards |
| MQTT-3.3.2-15 | MUST | Implemented | Server must send Response Topic unaltered |
| MQTT-3.3.2-16 | MUST | Implemented | Server must send Correlation Data unaltered |
| MQTT-3.3.2-17 | MUST | Implemented | Server must send all User Properties unaltered when forwarding |
| MQTT-3.3.2-18 | MUST | Implemented | Server must maintain User Property order when forwarding |
| MQTT-3.3.2-19 | MUST | Implemented | Content Type must be UTF-8 Encoded String |
| MQTT-3.3.2-20 | MUST | Implemented | Server must send Content Type unaltered |
| MQTT-3.3.4-1 | MUST | Structural | Receiver must respond to PUBLISH per QoS rules. Implicitly verified by all QoS tests. |
| MQTT-3.3.4-2 | MUST | Implemented | Server must deliver at maximum QoS of matching subscriptions |
| MQTT-3.3.4-3 | MUST | Implemented | Server must include Subscription Identifiers in forwarded messages |
| MQTT-3.3.4-4 | MUST | Implemented | Single copy with multiple matching subscriptions must include all Subscription Identifiers |
| MQTT-3.3.4-5 | MUST | Not tested | Multiple copies must each include matching Subscription Identifier. Requires multi-copy delivery scenario not tested. |
| MQTT-3.3.4-6 | MUST | Client | Client-to-Server PUBLISH must not contain Subscription Identifier. Client-side obligation. |
| MQTT-3.3.4-7 | MUST | Implemented | Client must not send more than Receive Maximum unacked QoS>0 PUBLISH |
| MQTT-3.3.4-8 | MUST | Client | Client must not delay non-PUBLISH due to Receive Maximum. Client-side obligation. |
| MQTT-3.3.4-9 | MUST | Implemented | Server must not send more than Receive Maximum unacked QoS>0 PUBLISH |
| MQTT-3.3.4-10 | MUST | Implemented | Server must not delay non-PUBLISH due to Receive Maximum |

## Section 3.4 — PUBACK

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.4.2-1 | MUST | Implemented | PUBACK must use defined Reason Codes |
| MQTT-3.4.2-2 | MUST | Not tested | Must not send Reason String exceeding Maximum Packet Size. Requires small Maximum Packet Size and error-triggering scenario. |
| MQTT-3.4.2-3 | MUST | Not tested | Must not send User Property exceeding Maximum Packet Size. Same constraint as above. |

## Section 3.5 — PUBREC

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.5.2-1 | MUST | Structural | PUBREC must use defined Reason Codes. Implicitly verified by QoS 2 tests. |
| MQTT-3.5.2-2 | MUST | Client | Must not send Reason String exceeding Maximum Packet Size. Client-side obligation. |
| MQTT-3.5.2-3 | MUST | Client | Must not send User Property exceeding Maximum Packet Size. Client-side obligation. |

## Section 3.6 — PUBREL

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.6.1-1 | MUST | Structural | PUBREL fixed header bits must be 0010. Verified by codec and implicitly by QoS 2 tests. |
| MQTT-3.6.2-1 | MUST | Structural | PUBREL must use defined Reason Codes. Implicitly verified by QoS 2 tests. |
| MQTT-3.6.2-2 | MUST | Client | Must not send Reason String exceeding Maximum Packet Size. Client-side obligation. |
| MQTT-3.6.2-3 | MUST | Client | Must not send User Property exceeding Maximum Packet Size. Client-side obligation. |

## Section 3.7 — PUBCOMP

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.7.2-1 | MUST | Structural | PUBCOMP must use defined Reason Codes. Implicitly verified by QoS 2 tests. |
| MQTT-3.7.2-2 | MUST | Client | Must not send Reason String exceeding Maximum Packet Size. Client-side obligation. |
| MQTT-3.7.2-3 | MUST | Client | Must not send User Property exceeding Maximum Packet Size. Client-side obligation. |

## Section 3.8 — SUBSCRIBE

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.8.1-1 | MUST | Implemented | SUBSCRIBE fixed header bits must be 0010 |
| MQTT-3.8.3-1 | MUST | Implemented | Topic Filters must be UTF-8 Encoded Strings |
| MQTT-3.8.3-2 | MUST | Implemented | Payload must contain at least one Topic Filter |
| MQTT-3.8.3-3 | MUST | Implemented | No Local=1: messages must not be forwarded to same ClientID |
| MQTT-3.8.3-4 | MUST | Implemented | No Local on Shared Subscription is Protocol Error |
| MQTT-3.8.3-5 | MUST | Implemented | Reserved bits in subscription options must be zero |
| MQTT-3.8.4-1 | MUST | Implemented | Server must respond to SUBSCRIBE with SUBACK |
| MQTT-3.8.4-2 | MUST | Structural | SUBACK must have same Packet Identifier as SUBSCRIBE. Verified implicitly by all subscribe tests. |
| MQTT-3.8.4-3 | MUST | Implemented | Identical non-shared subscription: replace existing |
| MQTT-3.8.4-4 | MUST | Implemented | Retain Handling=0: retained messages re-sent, messages not lost |
| MQTT-3.8.4-5 | MUST | Implemented | Multiple Topic Filters: handle as sequence, single SUBACK |
| MQTT-3.8.4-6 | MUST | Implemented | SUBACK must contain Reason Code per Topic Filter |
| MQTT-3.8.4-7 | MUST | Implemented | Reason Code shows granted QoS or failure |
| MQTT-3.8.4-8 | MUST | Implemented | Delivered QoS = min(published QoS, granted QoS) |

## Section 3.9 — SUBACK

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.9.2-1 | MUST | Not tested | Server must not send Reason String exceeding Maximum Packet Size. Requires small packet size and error scenario. |
| MQTT-3.9.2-2 | MUST | Not tested | Server must not send User Property exceeding Maximum Packet Size. Same constraint. |
| MQTT-3.9.3-1 | MUST | Implemented | SUBACK Reason Codes must match order of SUBSCRIBE filters |
| MQTT-3.9.3-2 | MUST | Structural | Server must use Subscribe Reason Code values. Verified implicitly by all SUBACK parsing. |

## Section 3.10 — UNSUBSCRIBE

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.10.1-1 | MUST | Implemented | UNSUBSCRIBE fixed header bits must be 0010 |
| MQTT-3.10.3-1 | MUST | Implemented | UNSUBSCRIBE Topic Filters must be UTF-8 |
| MQTT-3.10.3-2 | MUST | Structural | UNSUBSCRIBE must contain at least one Topic Filter. Enforced by codec encoding. |
| MQTT-3.10.4-1 | MUST | Implemented | Matching filter: delete subscription |
| MQTT-3.10.4-2 | MUST | Implemented | Stop adding new messages for unsubscribed filter |
| MQTT-3.10.4-3 | MUST | Implemented | Complete delivery of in-flight QoS 1/2 messages |
| MQTT-3.10.4-4 | MUST | Implemented | Server must respond with UNSUBACK |
| MQTT-3.10.4-5 | MUST | Implemented | Even with no deletions, Server must respond with UNSUBACK |
| MQTT-3.10.4-6 | MUST | Implemented | Multiple filters: process as sequence, single UNSUBACK |

## Section 3.11 — UNSUBACK

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.11.2-1 | MUST | Not tested | Server must not send Reason String exceeding Maximum Packet Size. |
| MQTT-3.11.2-2 | MUST | Not tested | Server must not send User Property exceeding Maximum Packet Size. |
| MQTT-3.11.3-1 | MUST | Implemented | UNSUBACK Reason Codes must match order of UNSUBSCRIBE filters |
| MQTT-3.11.3-2 | MUST | Structural | Server must use Unsubscribe Reason Code values. Verified implicitly by UNSUBACK parsing. |

## Section 3.12 — PINGREQ / PINGRESP

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.12.4-1 | MUST | Implemented | Server must send PINGRESP in response to PINGREQ |

## Section 3.14 — DISCONNECT

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.14.0-1 | MUST | Implemented | Server must not send DISCONNECT until after CONNACK with Reason Code < 0x80 |
| MQTT-3.14.1-1 | MUST | Implemented | DISCONNECT reserved bits: malformed if non-zero |
| MQTT-3.14.2-1 | MUST | Implemented | DISCONNECT must use defined Reason Code values |
| MQTT-3.14.2-2 | MUST | Implemented | Session Expiry Interval must not be sent on server DISCONNECT |
| MQTT-3.14.2-3 | MUST | Implemented | Must not send Reason String exceeding Maximum Packet Size |
| MQTT-3.14.2-4 | MUST | Client | Must not send User Property exceeding Maximum Packet Size. Client-side obligation. |
| MQTT-3.14.4-1 | MUST | Implemented | After DISCONNECT, sender must not send more packets |
| MQTT-3.14.4-2 | MUST | Implemented | After DISCONNECT, sender must close Network Connection |
| MQTT-3.14.4-3 | MUST | Implemented | On DISCONNECT 0x00, Server must discard Will Message |

## Section 3.15 — AUTH

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-3.15.1-1 | MUST | Implemented | AUTH fixed header bits must be 0000 |
| MQTT-3.15.2-1 | MUST | Structural | AUTH must use defined Reason Codes. Verified by auth test codec. |
| MQTT-3.15.2-2 | MUST | Client | Must not send Reason String exceeding Maximum Packet Size. Client-side obligation. |
| MQTT-3.15.2-3 | MUST | Client | Must not send User Property exceeding Maximum Packet Size. Client-side obligation. |

## Section 4.1 — Session State

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.1.0-1 | MUST | Implemented | Must not discard Session State while connection open |
| MQTT-4.1.0-2 | MUST | Implemented | Server must discard Session State after Session Expiry Interval passes |

## Section 4.2 — Network Connections

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.2.0-1 | MUST | Implemented | Must support ordered, lossless byte stream transport |

## Section 4.3 — QoS Levels

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.3.1-1 | MUST | Implemented | QoS 0: send PUBLISH with QoS=0, DUP=0 |
| MQTT-4.3.2-1 | MUST | Implemented | QoS 1: assign unused Packet Identifier |
| MQTT-4.3.2-2 | MUST | Implemented | QoS 1: send PUBLISH with QoS=1, DUP=0 |
| MQTT-4.3.2-3 | N/A | N/A | Reference to section 4.4 |
| MQTT-4.3.2-4 | MUST | Structural | QoS 1 receiver must respond with PUBACK. Verified implicitly by all QoS 1 tests. |
| MQTT-4.3.2-5 | MUST | Structural | After PUBACK, treat same Packet ID as new. Implicitly tested by sequential QoS 1 publishes. |
| MQTT-4.3.3-1 | MUST | Implemented | QoS 2: assign unused Packet Identifier |
| MQTT-4.3.3-2 | MUST | Implemented | QoS 2: send PUBLISH with QoS=2, DUP=0 |
| MQTT-4.3.3-3 | MUST | Implemented | PUBLISH unacknowledged until PUBREC received |
| MQTT-4.3.3-4 | MUST | Structural | PUBREL must have same Packet Identifier as PUBLISH. Enforced by codec/test flow. |
| MQTT-4.3.3-5 | MUST | Client | PUBREL unacknowledged until PUBCOMP received. Client-side obligation. |
| MQTT-4.3.3-6 | MUST | Client | Must not re-send PUBLISH once PUBREL sent. Client-side obligation. |
| MQTT-4.3.3-7 | MUST | Not tested | Must not apply Message Expiry if PUBLISH already sent. Requires timing test during QoS 2 flow. |
| MQTT-4.3.3-8 | MUST | Structural | QoS 2 receiver must respond with PUBREC. Verified implicitly by QoS 2 tests. |
| MQTT-4.3.3-9 | MUST | Structural | After PUBREC with Reason >= 0x80, treat subsequent PUBLISH as new. Implied by error handling. |
| MQTT-4.3.3-10 | MUST | Implemented | Until PUBREL, receiver must not cause duplicate delivery |
| MQTT-4.3.3-11 | MUST | Structural | Receiver responds to PUBREL with PUBCOMP. Verified implicitly by QoS 2 tests. |
| MQTT-4.3.3-12 | MUST | Structural | After PUBCOMP, treat subsequent same-ID PUBLISH as new. Implied by QoS 2 flow. |
| MQTT-4.3.3-13 | MUST | Implemented | Continue QoS 2 ack sequence even after message expiry |

## Section 4.4 — Message Delivery Retry

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.4.0-1 | MUST | Implemented | Reconnect Clean Start=0: resend unacked PUBLISH/PUBREL; must not resend otherwise |
| MQTT-4.4.0-2 | MUST | Implemented | PUBACK/PUBREC with Reason >= 0x80: must not retransmit |

## Section 4.5 — Message Receipt

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.5.0-1 | MUST | Implemented | Server must add incoming message to matching subscriptions |
| MQTT-4.5.0-2 | MUST | Client | Client must acknowledge PUBLISH per QoS rules. Client-side obligation. |

## Section 4.6 — Message Ordering

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.6.0-1 | MUST | Implemented | Client must re-send PUBLISH in original order |
| MQTT-4.6.0-2 | MUST | Client | Client must send PUBACK in order of received PUBLISH. Client-side obligation. |
| MQTT-4.6.0-3 | MUST | Client | Client must send PUBREC in order. Client-side obligation. |
| MQTT-4.6.0-4 | MUST | Client | Client must send PUBREL in order. Client-side obligation. |
| MQTT-4.6.0-5 | MUST | Implemented | Server must send PUBLISH to consumers in order received |
| MQTT-4.6.0-6 | MUST | Structural | Server must treat every Topic as Ordered by default. Implicit in ordering tests. |

## Section 4.7 — Topic Names and Filters

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.7.0-1 | MUST | Implemented | Wildcards must not be used in Topic Names |
| MQTT-4.7.1-1 | MUST | Implemented | '#' must be last character in Topic Filter |
| MQTT-4.7.1-2 | MUST | Implemented | '+' must occupy entire level of filter |
| MQTT-4.7.2-1 | MUST | Implemented | Server must not match wildcards with $-prefixed Topic Names |
| MQTT-4.7.3-1 | MUST | Implemented | Topic Names/Filters must be at least one character |
| MQTT-4.7.3-2 | MUST | Structural | Topics must not include null character. Enforced by UTF-8 validation (MQTT-1.5.4-2). |
| MQTT-4.7.3-3 | MUST | Implemented | Topics must not exceed 65,535 bytes |
| MQTT-4.7.3-4 | MUST | Implemented | Server must not normalize Topic Names or Filters |

## Section 4.8 — Subscriptions

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.8.2-1 | MUST | Implemented | Shared Subscription must start with $share/ and ShareName >= 1 char |
| MQTT-4.8.2-2 | MUST | Implemented | ShareName must be followed by / then Topic Filter |
| MQTT-4.8.2-3 | MUST | Implemented | Server must respect granted QoS for shared subscription clients |
| MQTT-4.8.2-4 | MUST | Implemented | Server must complete QoS 2 delivery on reconnect |
| MQTT-4.8.2-5 | MUST | Not tested | If session terminates before reconnect, must not send to other subscriber. Requires session termination timing. |
| MQTT-4.8.2-6 | MUST | Implemented | PUBACK/PUBREC with Reason >= 0x80: discard message |

## Section 4.9 — Flow Control

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.9.0-1 | MUST | Implemented | Initial send quota must be non-zero, not exceeding Receive Maximum |
| MQTT-4.9.0-2 | MUST | Structural | If quota=0, must not send more QoS>0 PUBLISH. Tested via Receive Maximum tests. |
| MQTT-4.9.0-3 | MUST | Implemented | Must continue processing other packets even if quota is zero |

## Section 4.10 — Request / Response

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.10.0-1 | MUST | Implemented | Request/Response basic pattern works end-to-end |
| MQTT-4.10.0-2 | MUST | Implemented | Response Topic forwarded correctly |
| MQTT-4.10.0-3 | MUST | Implemented | Correlation Data forwarded correctly |
| MQTT-4.10.0-4 | MUST | Implemented | Request/Response with Correlation Data round-trip |

## Section 4.11 — Server Redirection

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.11.0-1 | MUST | Implemented | Server Reference property recognized in CONNACK |

## Section 4.12 — Enhanced Authentication

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.12.0-1 | MUST | Implemented | Server must close connection for unsupported Auth Method |
| MQTT-4.12.0-2 | MUST | Implemented | AUTH must have Reason Code 0x18 for continued auth. Skips at runtime if broker lacks auth plugin. |
| MQTT-4.12.0-3 | MUST | Implemented | Client AUTH response must use Reason Code 0x18. Skips at runtime if broker lacks auth plugin. |
| MQTT-4.12.0-4 | MUST | Implemented | Failed auth: may send CONNACK >= 0x80, must close. Skips at runtime if broker lacks auth plugin. |
| MQTT-4.12.0-5 | MUST | Implemented | All AUTH and CONNACK must include same Auth Method. Skips at runtime if broker lacks auth plugin. |
| MQTT-4.12.0-6 | MUST | Implemented | No Auth Method in CONNECT: Server must not send AUTH or Auth Method in CONNACK |
| MQTT-4.12.0-7 | MUST | Client | Client must not send AUTH if no Auth Method in CONNECT. Client-side obligation. |
| MQTT-4.12.1-1 | MUST | Implemented | Re-auth must use same Auth Method. Skips at runtime if broker lacks auth plugin. |
| MQTT-4.12.1-2 | MUST | Implemented | Failed re-auth: should DISCONNECT, must close. Skips at runtime if broker lacks auth plugin. |

## Section 4.13 — Handling Errors

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-4.13.1-1 | MUST | Implemented | Malformed Packet or Protocol Error with Reason Code: close connection |
| MQTT-4.13.2-1 | MUST | Structural | Reason Code >= 0x80: connection must be closed. Verified by all error-path tests. |

## Section 6 — WebSocket Transport

| Requirement | Level | Status | Description |
|-------------|-------|--------|-------------|
| MQTT-6.0.0-1 | MUST | WebSocket | Non-binary WebSocket frame: must close connection. Out of scope (TCP/TLS only). |
| MQTT-6.0.0-2 | MUST | WebSocket | Must not assume MQTT packets aligned on WebSocket frames. Out of scope (TCP/TLS only). |
| MQTT-6.0.0-3 | MUST | WebSocket | Client must include "mqtt" in WebSocket Sub Protocols. Out of scope (TCP/TLS only). |
| MQTT-6.0.0-4 | MUST | WebSocket | WebSocket Subprotocol returned must be "mqtt". Out of scope (TCP/TLS only). |
