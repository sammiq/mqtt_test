# mqtt_test

MQTT v5 broker compliance testing tool written in Rust. Tests brokers (not client libraries) against the MQTT v5 specification, reporting MUST/SHOULD/MAY compliance levels.

## Project structure

- `src/main.rs` — CLI entry point (clap), runs all test suites and prints report
- `src/client.rs` — `RawClient` async TCP/TLS wrapper, `AutoDisconnect` RAII wrapper, `Transport` enum
- `src/codec.rs` — Custom MQTT v5 packet encoder/decoder (no external MQTT library)
- `src/types.rs` — `Compliance` (Must/Should/May), `Outcome`, `TestResult`, `Suite`
- `src/report.rs` — Report formatting/printing
- `src/tests/` — Test suites
- `spec/mqtt-v5.0-os.html` — Local copy of the MQTT v5.0 OASIS specification for reference

## Architecture

- Custom codec by design — full control over packet construction for compliance testing
- Each test suite in `src/tests/` returns a `Suite` of `TestResult`s
- `tests::run_all()` aggregates suites and returns a report
- `AutoDisconnect` wraps `RawClient` and sends DISCONNECT on drop (via `try_write`). `connect()` and `connect_and_subscribe()` return `AutoDisconnect` by default
- Use `into_raw()` to escape auto-disconnect when a test intentionally skips DISCONNECT (e.g. abrupt disconnects for session resumption)
- Use `RawClient` directly when DISCONNECT is the subject of the test and should be explicit in the code
- Transport suite (MQTT §4.2) tests TCP and TLS connectivity; TLS via `tokio-rustls` with explicit `TlsConfig` — other suites always use plain TCP
- Dependencies are minimal: tokio, bytes, clap, anyhow, thiserror, tokio-rustls, rustls-pemfile

## Building and running

```
cargo build
cargo run -- 127.0.0.1                                # TCP :1883, tries TLS :8883
cargo run -- 127.0.0.1 --ca-cert /path/to/ca.crt      # verify TLS certs
cargo run -- 127.0.0.1 --no-tls                        # skip TLS transport test
cargo clippy   # should produce zero warnings
./test-broker.sh   # spins up mosquitto in Docker, runs full suite (TCP + TLS)
```

## Conventions

- After making changes to code, always run existing tests and look to add tests for missing cases
- Never commit changes as part of another task, unless you have asked explicitly to do so
- Ensure any relevant information in CLAUDE.md is correct after making changes
- Use `#[allow(dead_code)]` for public API surface not yet consumed (codec structs, client methods) rather than removing it
- QoS enum variants use standard MQTT naming (AtMostOnce, AtLeastOnce, ExactlyOnce)
- Prefer struct initialization syntax over field reassignment after Default::default()
- Each test suite has a `TEST_COUNT` constant (transport uses `TCP_TEST_COUNT` + `TLS_TEST_COUNT`) — update when adding/removing tests
- `test-broker.sh` runs a single pass with TCP (port 1883) and TLS transport (port 8883)
