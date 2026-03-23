# mqtt_test

MQTT v5 broker compliance testing tool written in Rust. Tests brokers (not client libraries) against the MQTT v5 specification, reporting MUST/SHOULD/MAY compliance levels.

## Project structure

- `src/main.rs` — CLI entry point (clap), runs all test suites and prints report
- `src/client.rs` — `RawClient` async TCP/TLS wrapper, `AutoDisconnect` RAII wrapper, `Transport` enum
- `src/codec.rs` — Custom MQTT v5 packet encoder/decoder (no external MQTT library)
- `src/types.rs` — `Compliance` (Must/Should/May), `Outcome`, `TestResult`, `Suite`, `SuiteRunner`, `TestConfig`
- `src/report.rs` — Report formatting/printing
- `src/tests/` — Test suites
- `spec/mqtt-v5.0-os.html` — Local copy of the MQTT v5.0 OASIS specification for reference

## Architecture

- Custom codec by design — full control over packet construction for compliance testing
- Each test suite in `src/tests/` exposes a `tests()` function returning a `SuiteRunner` — test count is derived automatically from the number of registered tests
- `SuiteRunner::run(&pb)` executes tests sequentially, wrapping each with `run_test` for error handling and progress reporting
- `tests::run_selected()` creates runners, sizes progress bars from `runner.count()`, and collects results into a `Report`
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

- After making changes to code, run `cargo fmt` before finishing to keep formatting consistent
- After making changes to code, always run existing tests and look to add tests for missing cases
- Never commit changes as part of another task, unless you have asked explicitly to do so
- Ensure any relevant information in CLAUDE.md is correct after making changes
- Use `#[allow(dead_code)]` for public API surface not yet consumed (codec structs, client methods) rather than removing it
- QoS enum variants use standard MQTT naming (AtMostOnce, AtLeastOnce, ExactlyOnce)
- Prefer struct initialization syntax over field reassignment after Default::default()
- `TestConfig` is `Copy` — passed by value everywhere; no `&` or `*` needed
- Test count is derived automatically from `SuiteRunner` — just add tests via `suite.add(CTX, test_fn(config))` in the module's `tests()` function
- All test suites receive the same `TestConfig` (including TLS info); tests that don't use TLS simply ignore it, TLS tests return SKIP when `config.tls_info` is `None`
- Tests that require broker features not universally supported (e.g. enhanced auth) should always register and return SKIP with a descriptive reason, rather than being conditionally omitted
- `test-broker.sh` runs a single pass with TCP (port 1883) and TLS transport (port 8883)
