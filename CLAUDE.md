# mqtt_test

MQTT v5 broker compliance testing tool written in Rust. Tests brokers (not client libraries) against the MQTT v5 specification, reporting MUST/SHOULD/MAY compliance levels.

## Project structure

- `src/main.rs` — CLI entry point (clap), runs all test suites and prints report
- `src/client.rs` — `RawClient` async TCP wrapper for sending/receiving MQTT packets
- `src/codec.rs` — Custom MQTT v5 packet encoder/decoder (no external MQTT library)
- `src/types.rs` — `Compliance` (Must/Should/May), `Outcome`, `TestResult`, `Suite`
- `src/report.rs` — Report formatting/printing
- `src/tests/` — Test suites: `connect`, `ping`, `publish`, `subscribe`

## Architecture

- Custom codec by design — full control over packet construction for compliance testing
- Each test suite in `src/tests/` returns a `Suite` of `TestResult`s
- `tests::run_all()` aggregates suites and returns a report
- Dependencies are minimal: tokio, bytes, clap, anyhow, thiserror

## Building and running

```
cargo build
cargo run -- --broker 127.0.0.1:1883
cargo clippy   # should produce zero warnings
```

## Conventions

- Use `#[allow(dead_code)]` for public API surface not yet consumed (codec structs, client methods) rather than removing it
- QoS enum variants use standard MQTT naming (AtMostOnce, AtLeastOnce, ExactlyOnce)
- Prefer struct initialization syntax over field reassignment after Default::default()
- After making changes to code, always run existing tests and look to add tests for missing cases
