# mqtt_test

MQTT v5 broker compliance testing tool written in Rust. Tests brokers (not client libraries) against the MQTT v5 specification, reporting MUST/SHOULD/MAY compliance levels.

## Project structure

- `src/main.rs` — CLI entry point (clap), runs all test suites and prints report
- `src/client.rs` — `RawClient` async TCP/TLS/WebSocket wrapper, `AutoDisconnect` RAII wrapper, `Transport` enum, `RecvError` (Timeout/Closed/Other)
- `src/ws.rs` — WebSocket support: HTTP upgrade handshake, `WsFramer` frame codec, `WsStream` (AsyncRead/AsyncWrite over framed TCP)
- `src/codec.rs` — Custom MQTT v5 packet encoder/decoder (no external MQTT library)
- `src/types.rs` — `Compliance` (Must/Should/May), `Outcome`, `TestResult`, `Suite`, `SuiteRunner`, `TestConfig`
- `src/report.rs` — Report formatting/printing
- `src/tests/` — Test suites
- `REQUIREMENTS_TABLE.md` — List of MQTT v5 requirements and their implementation status in the project

## Architecture

- Custom codec by design — full control over packet construction for compliance testing
- Each test suite in `src/tests/` exposes a `tests()` function returning a `SuiteRunner` — test count is derived automatically from the number of registered tests
- `SuiteRunner::run(&pb)` executes tests sequentially, wrapping each with `run_test` for error handling and progress reporting
- `tests::run_selected()` creates runners, sizes progress bars from `runner.count()`, and collects results into a `Report`
- `AutoDisconnect` wraps `RawClient` and sends DISCONNECT on drop (via `try_write`). `connect()` and `connect_and_subscribe()` return `AutoDisconnect` by default
- Use `into_raw()` to escape auto-disconnect when a test intentionally skips DISCONNECT (e.g. abrupt disconnects for session resumption)
- Use `RawClient` directly when DISCONNECT is the subject of the test and should be explicit in the code
- Transport suite (MQTT §4.2) tests TCP and TLS connectivity; TLS via `tokio-rustls` with explicit `TlsConfig` — other suites always use plain TCP
- WebSocket suite (MQTT §6) tests MQTT-over-WebSocket; uses a minimal custom WebSocket client (`WsFramer`) with HTTP upgrade handshake — no external WS library
- `RawClient::recv()` returns `Result<Packet, RecvError>` — tests match on `RecvError::Closed` (clean TCP close), `RecvError::Timeout`, and `RecvError::Other` (I/O errors including connection reset) to distinguish broker behaviour from infrastructure failures
- Dependencies are minimal: tokio, bytes, clap, anyhow, thiserror, tokio-rustls, rustls-pki-types, base64

## Building and running

```
cargo build
cargo run -- 127.0.0.1                                # TCP :1883, tries TLS :8883
cargo run -- 127.0.0.1 --ca-cert /path/to/ca.crt      # verify TLS certs
cargo run -- 127.0.0.1 --no-tls                        # skip TLS transport test
cargo run -- 127.0.0.1 --ws-port 8083                   # test WebSocket on port 8083
cargo clippy   # should produce zero warnings
./test-broker-mosquitto.sh  # spins up mosquitto in Docker, runs full suite (TCP + TLS + WebSocket)
./test-broker-hivemq.sh     # spins up HiveMQ CE in Docker, runs full suite (TCP + TLS + WebSocket)
./test-broker-emqx.sh       # spins up EMQX Enterprise in Docker, runs full suite (TCP + TLS + WebSocket)
```

## Conventions

- After making changes to code, run `cargo clippy` and `cargo fmt`
- After making changes to code, always run existing tests and look to add tests for missing cases
- NEVER commit changes, unless you have asked explicitly to do so
- Ensure any relevant information in CLAUDE.md is correct after making changes
- Only use `#[allow(dead_code)]` on the specific item that triggers a warning (field, method, function) — not on entire structs/enums/impl blocks. Remove annotations once the item is consumed. Periodically audit by removing all annotations and running `cargo check`.
- QoS enum variants use standard MQTT naming (AtMostOnce, AtLeastOnce, ExactlyOnce)
- Prefer struct initialization syntax over field reassignment after Default::default()
- `TestConfig` is `Copy` — passed by value everywhere; no `&` or `*` needed
- Test count is derived automatically from `SuiteRunner` — just add tests via `suite.add(CTX, test_fn(config))` in the module's `tests()` function
- All test suites receive the same `TestConfig` (including TLS and WebSocket info); tests that don't use TLS/WS simply ignore it, TLS tests return SKIP when `config.tls_info` is `None`, WS tests when `config.ws_info` is `None`
- Tests that require broker features not universally supported (e.g. enhanced auth) should always register and return SKIP with a descriptive reason, rather than being conditionally omitted
- `test-broker-mosquitto.sh` runs a single pass with TCP (port 1883), TLS transport (port 8883), and WebSocket (port 8083)
- `test-broker-hivemq.sh` runs HiveMQ CE with TCP (port 1884), TLS (port 8884), and WebSocket (port 8084)
- `test-broker-emqx.sh` runs EMQX Enterprise with TCP (port 1885), TLS (port 8885), and WebSocket (port 8085)
- When matching `recv()` results in tests: `RecvError::Closed` = broker cleanly closed (pass for "expect disconnect" tests), `RecvError::Timeout` = broker didn't respond (fail for "expect disconnect", pass for "expect no message"), `RecvError::Other` = I/O error like connection reset (always fail — prevents false passes when broker isn't ready)
- Tests that use `RawClient::connect_tcp` directly (pre-CONNECT malformed packet tests) rely on `RecvError::Other` catching connection resets from unready brokers; tests that go through `client::connect()` are already protected by the CONNACK handshake
