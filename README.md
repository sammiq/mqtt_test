# mqtt_test

MQTT v5 broker compliance testing tool. Tests brokers (not client libraries) against the [MQTT v5.0 OASIS specification](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html), reporting MUST, SHOULD, and MAY compliance levels.

Uses a custom MQTT v5 packet codec — no external MQTT client library — giving full control over packet construction for edge-case and malformed-packet testing.

## Test suites

| Suite | Description |
|-------|-------------|
| Transport | TCP and TLS connectivity (MQTT §4.2) |
| Connect | CONNECT/CONNACK handshake, session flags, keep-alive, will messages |
| Ping | PINGREQ/PINGRESP |
| Publish | QoS 0/1/2 delivery, retain, topic aliases, message expiry, flow control |
| Subscribe | Wildcards, shared subscriptions, subscription identifiers, QoS handling |
| Session | Session persistence, expiry, takeover, redelivery on resume |
| Malformed | Invalid packets, reserved flags, encoding violations |
| Disconnect | DISCONNECT handling, will message lifecycle, reason codes |
| Request/Response | Request/response pattern, response topic, correlation data |
| Auth | Enhanced authentication (MQTT §4.12), skips gracefully without auth plugin |
| WebSocket | WebSocket transport (MQTT §6), subprotocol negotiation, frame handling |

See [REQUIREMENTS_TABLE.md](REQUIREMENTS_TABLE.md) for a full mapping of every normative spec requirement to its test coverage status.

## Requirement reference validation

To keep requirement coverage traceable, this repo validates requirement IDs used in tests against `REQUIREMENTS_TABLE.md`.

Run locally:

```sh
python3 scripts/validate_requirements_refs.py
```

The validator enforces:

- every `TestContext.refs` entry in `src/tests/*.rs` is a known canonical requirement ID from `REQUIREMENTS_TABLE.md`
- every requirement marked `Implemented` in `REQUIREMENTS_TABLE.md` is referenced by at least one test

The CI workflow also runs this validation (`.github/workflows/build.yml`).

### Waivers

If a requirement is marked `Implemented` but currently has no direct `refs` mapping, add it to:

- `scripts/requirements_implemented_waivers.txt`

Guidelines:

- keep waivers temporary and minimal
- include one requirement ID per line
- remove a waiver as soon as a matching test ref is added

### Canonical ID note

The MQTT v5 spec uses `MQTT-4.2-1` in prose and `MQTT-4.2.0-1` in the conformance statement table; the validator treats these as equivalent.

## Requirements

- Rust (edition 2024)
- An MQTT v5 broker to test against
- Docker (optional, for broker test scripts)

## Building

```
cargo build
```

## Usage

```
mqtt_test [OPTIONS] [HOST]
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | Broker hostname or IP address |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--tcp-port <PORT>` | `1883` | TCP port for MQTT |
| `--tls-port <PORT>` | `8883` | TLS port for MQTT |
| `--no-tls` | | Skip TLS transport tests |
| `--ws-port <PORT>` | `8083` | WebSocket port for MQTT |
| `--ws-path <PATH>` | `/mqtt` | WebSocket path for MQTT |
| `--no-ws` | | Skip WebSocket transport tests |
| `--ca-cert <PATH>` | | CA certificate PEM file for TLS verification (insecure if omitted) |
| `-t, --timeout-ms <MS>` | `5000` | Timeout in milliseconds for each broker response |
| `-s, --suite <SUITES>` | all | Run only specific suites (comma-separated) |
| `--order <ORDER>` | `suite` | Report ordering: `suite`, `requirement`, or `level` |
| `--failures-only` | | Only show failing tests in the report |
| `-V, --verbose` | | Show full packet debug output for failed tests |
| `--debug` | | Enable debug logging |
| `--trace` | | Enable trace logging (implies --debug) |

### Examples

```sh
# Test a local broker on default ports (TCP 1883, TLS 8883)
cargo run -- 127.0.0.1

# Test with TLS certificate verification
cargo run -- 127.0.0.1 --ca-cert /path/to/ca.crt

# Skip TLS tests
cargo run -- 127.0.0.1 --no-tls

# Run only the publish and subscribe suites
cargo run -- 127.0.0.1 --suite publish,subscribe

# Sort results by spec section instead of test suite
cargo run -- 127.0.0.1 --order requirement

# Sort results by compliance level (MUST, SHOULD, MAY)
cargo run -- 127.0.0.1 --order level

# Show only failing tests
cargo run -- 127.0.0.1 --failures-only
```

### Quick test with Docker

Each script spins up a broker container with TCP, TLS, and WebSocket, runs the full suite, and cleans up:

```sh
./test-broker-mosquitto.sh   # Eclipse Mosquitto
./test-broker-hivemq.sh      # HiveMQ CE
./test-broker-emqx.sh        # EMQX Enterprise
./test-broker-vernemq.sh     # VerneMQ
```

## Sample output

When outputting to a terminal, results are colorized (green for pass, red for fail, dim for skip/unsupported).

```
Summary
  Required (MUST):       121/121
  Recommended (SHOULD):  15/15
  Optional (MAY):        13/25

  Broker satisfies all required MQTT v5 behaviours.
```

Each test reports a spec requirement ID, compliance level, and result:

```
  [PASS] MUST   [MQTT-3.1.2-4, MQTT-3.2.2-2] Clean Start=1: server MUST start a new session
  [PASS] MUST   [MQTT-4.3.3-1 ] QoS 2 PUBLISH MUST complete PUBREC / PUBREL / PUBCOMP flow
  [SKIP] MUST   [MQTT-4.12.0-2] Server MUST send AUTH ... — Broker does not support enhanced auth
  [ YES] MAY    [MQTT-3.3.1-5 ] Retain flag: broker stores and delivers retained message
```

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
