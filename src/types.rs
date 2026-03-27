use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use indicatif::ProgressBar;

use crate::client::TlsConfig;
use crate::codec::Packet;
use crate::report::run_test;

/// Shared configuration passed to every test suite and individual test.
#[derive(Clone, Copy)]
pub struct TestConfig<'a> {
    /// TCP broker address (e.g. "127.0.0.1:1883").
    pub addr: &'a str,
    /// How long to wait for each broker response.
    pub recv_timeout: Duration,
    /// TLS endpoint address and config, if available.
    pub tls_info: Option<(&'a str, &'a TlsConfig)>,
    /// WebSocket endpoint address, hostname, and path, if available.
    pub ws_info: Option<(&'a str, &'a str, &'a str)>,
}

/// How the MQTT v5 specification describes a behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compliance {
    /// The spec says MUST — non-compliance is a protocol violation.
    Must,
    /// The spec says SHOULD — deviation is noteworthy but not a violation.
    Should,
    /// The spec says MAY — the feature is optional; support is reported.
    May,
}

/// Identifies a single compliance test — defined once per test function.
/// A test may cover one or more MQTT spec requirements (`refs`).
#[derive(Debug, Clone, Copy)]
pub struct TestContext {
    pub refs: &'static [&'static str],
    pub description: &'static str,
    pub compliance: Compliance,
}

impl TestContext {
    /// The first (primary) spec reference, used for sorting and display.
    pub fn primary_ref(&self) -> &'static str {
        self.refs.first().unwrap_or(&"UNKNOWN")
    }
}

/// The result of running a single test.
///
/// For MUST/SHOULD tests the question is "did the broker comply?":
///   Pass = yes, Fail = no (protocol violation).
///
/// For MAY tests the question is "does the broker do this?":
///   Pass = yes (supported), Unsupported = no (not supported).
///   Fail is still valid for MAY tests when something genuinely breaks
///   (e.g. broker advertised support but then errored), but Unsupported
///   is preferred when the broker simply doesn't exhibit the behaviour.
///
/// Skip applies to all compliance levels: the test couldn't run
/// (missing config, prerequisite not met).
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The broker behaves as described.
    /// For MAY tests, this means the broker supports the optional behaviour
    /// and is displayed as "YES" in the report.
    Pass,
    /// The broker violated a requirement or behaved incorrectly.
    /// Displayed as "FAIL" for MUST/SHOULD tests, "NO" for MAY tests.
    Fail {
        message: String,
        verbose: Option<String>,
    },
    /// The broker does not exhibit this optional (MAY) behaviour, and that's
    /// fine — it's not a protocol violation. Prefer this over Fail for MAY
    /// tests when the broker simply doesn't do the optional thing.
    /// Displayed as "NO" in the report; not counted as a failure.
    Unsupported(String),
    /// The test could not run (missing config, prerequisite not met, etc.).
    /// Excluded from pass/total counts in the summary.
    Skip(String),
}

impl Outcome {
    pub fn fail(reason: impl Into<String>) -> Self {
        Outcome::Fail {
            message: reason.into(),
            verbose: None,
        }
    }

    #[allow(dead_code)]
    pub fn fail_verbose(reason: impl Into<String>, verbose: impl Into<String>) -> Self {
        Outcome::Fail {
            message: reason.into(),
            verbose: Some(verbose.into()),
        }
    }

    pub fn fail_packet(expected: &str, got: &Packet) -> Self {
        Outcome::Fail {
            message: format!("Expected {expected}, got {got}"),
            verbose: Some(format!("Expected {expected}, got {got:?}")),
        }
    }

    pub fn skip(reason: impl Into<String>) -> Self {
        Outcome::Skip(reason.into())
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Outcome::Unsupported(reason.into())
    }
}

/// Extension trait for `Result<T, Outcome>` — collapses a helper result into
/// a plain `Outcome` when the caller doesn't need the success value.
///
/// - `Ok(_)` → `Outcome::Pass`
/// - `Err(outcome)` → `outcome`
pub trait IntoOutcome {
    fn into_outcome(self) -> Outcome;
}

impl<T> IntoOutcome for Result<T, Outcome> {
    fn into_outcome(self) -> Outcome {
        match self {
            Ok(_) => Outcome::Pass,
            Err(o) => o,
        }
    }
}

/// A single compliance test result.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub ctx: TestContext,
    pub outcome: Outcome,
}

/// A named group of related test results.
pub struct Suite {
    pub name: &'static str,
    pub results: Vec<TestResult>,
}

/// A boxed, Send-safe test future.
type TestFuture<'a> = Pin<Box<dyn Future<Output = Result<Outcome>> + Send + 'a>>;

/// Collects test futures before execution, deriving the count automatically.
///
/// Each test module builds a `SuiteRunner` via `add()`, then `mod.rs` creates
/// a progress bar from `count()` and calls `run()` to execute them all.
pub struct SuiteRunner<'a> {
    pub name: &'static str,
    tests: Vec<(TestContext, TestFuture<'a>)>,
}

impl<'a> SuiteRunner<'a> {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            tests: Vec::new(),
        }
    }

    /// Register a test. The future is created eagerly but not polled until `run()`.
    pub fn add(
        &mut self,
        ctx: TestContext,
        fut: impl Future<Output = Result<Outcome>> + Send + 'a,
    ) {
        self.tests.push((ctx, Box::pin(fut)));
    }

    /// Number of registered tests (used for progress bar sizing).
    pub fn count(&self) -> usize {
        self.tests.len()
    }

    /// Execute all tests sequentially, wrapping each with `run_test` for
    /// error handling and progress reporting.
    pub async fn run(self, pb: &ProgressBar) -> Suite {
        let mut results = Vec::with_capacity(self.tests.len());
        for (ctx, fut) in self.tests {
            results.push(run_test(ctx, pb, fut).await);
        }
        Suite {
            name: self.name,
            results,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{ConnAck, Properties};

    const CTX: TestContext = TestContext {
        refs: &["TEST-1"],
        description: "test description",
        compliance: Compliance::Must,
    };

    #[test]
    fn fail_stores_message() {
        match Outcome::fail("something broke") {
            Outcome::Fail { message, verbose } => {
                assert_eq!(message, "something broke");
                assert!(verbose.is_none());
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn fail_verbose_stores_both() {
        match Outcome::fail_verbose("short", "long details") {
            Outcome::Fail { message, verbose } => {
                assert_eq!(message, "short");
                assert_eq!(verbose.as_deref(), Some("long details"));
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn fail_packet_formats_display_and_debug() {
        let connack = Packet::ConnAck(ConnAck {
            session_present: false,
            reason_code: 0x85,
            properties: Properties::default(),
        });
        match Outcome::fail_packet("SUBACK(1)", &connack) {
            Outcome::Fail { message, verbose } => {
                assert!(message.contains("SUBACK(1)"));
                assert!(message.contains("CONNACK"));
                // verbose should contain Debug representation
                let v = verbose.unwrap();
                assert!(v.contains("reason_code: 133")); // 0x85 = 133
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn skip_stores_reason() {
        match Outcome::skip("broker does not support feature") {
            Outcome::Skip(reason) => {
                assert_eq!(reason, "broker does not support feature");
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn context_copy_semantics() {
        let ctx = TestContext {
            refs: &["COPY-1"],
            description: "copy test",
            compliance: Compliance::Should,
        };
        let copied = ctx;
        assert_eq!(copied.primary_ref(), "COPY-1");
        assert!(matches!(copied.compliance, Compliance::Should));
        // Original still usable (Copy trait)
        assert_eq!(ctx.primary_ref(), "COPY-1");
    }

    #[test]
    fn suite_holds_results() {
        let suite = Suite {
            name: "test-suite",
            results: vec![
                TestResult {
                    ctx: CTX,
                    outcome: Outcome::Pass,
                },
                TestResult {
                    ctx: CTX,
                    outcome: Outcome::fail("oops"),
                },
                TestResult {
                    ctx: CTX,
                    outcome: Outcome::skip("n/a"),
                },
            ],
        };
        assert_eq!(suite.name, "test-suite");
        assert_eq!(suite.results.len(), 3);
        assert!(matches!(suite.results[0].outcome, Outcome::Pass));
        assert!(matches!(suite.results[1].outcome, Outcome::Fail { .. }));
        assert!(matches!(suite.results[2].outcome, Outcome::Skip(_)));
    }

    #[test]
    fn unsupported_stores_reason() {
        match Outcome::unsupported("broker does not do this") {
            Outcome::Unsupported(reason) => {
                assert_eq!(reason, "broker does not do this");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn into_outcome_ok_is_pass() {
        let r: Result<&str, Outcome> = Ok("data");
        assert!(matches!(r.into_outcome(), Outcome::Pass));
    }

    #[test]
    fn into_outcome_err_is_fail() {
        let r: Result<(), Outcome> = Err(Outcome::fail("broken"));
        match r.into_outcome() {
            Outcome::Fail { message, .. } => assert_eq!(message, "broken"),
            other => panic!("expected Fail, got {other:?}"),
        }
    }
}
