use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

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
}

/// How the MQTT v5 specification describes a behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
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
#[derive(Debug, Clone)]
pub enum Outcome {
    Pass,
    Fail {
        message: String,
        verbose: Option<String>,
    },
    Skip(String),
}

/// A single compliance test result.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub ctx: TestContext,
    pub outcome: Outcome,
}

impl TestResult {
    pub fn pass(ctx: &TestContext) -> Self {
        Self {
            ctx: *ctx,
            outcome: Outcome::Pass,
        }
    }

    pub fn fail(ctx: &TestContext, reason: impl Into<String>) -> Self {
        Self {
            ctx: *ctx,
            outcome: Outcome::Fail {
                message: reason.into(),
                verbose: None,
            },
        }
    }

    #[allow(dead_code)]
    pub fn fail_verbose(
        ctx: &TestContext,
        reason: impl Into<String>,
        verbose: impl Into<String>,
    ) -> Self {
        Self {
            ctx: *ctx,
            outcome: Outcome::Fail {
                message: reason.into(),
                verbose: Some(verbose.into()),
            },
        }
    }

    pub fn fail_packet(ctx: &TestContext, expected: &str, got: &Packet) -> Self {
        Self {
            ctx: *ctx,
            outcome: Outcome::Fail {
                message: format!("Expected {expected}, got {got}"),
                verbose: Some(format!("Expected {expected}, got {got:?}")),
            },
        }
    }

    pub fn skip(ctx: &TestContext, reason: impl Into<String>) -> Self {
        Self {
            ctx: *ctx,
            outcome: Outcome::Skip(reason.into()),
        }
    }
}

/// A named group of related test results.
pub struct Suite {
    pub name: &'static str,
    pub results: Vec<TestResult>,
}

/// A boxed, Send-safe test future.
type TestFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<TestResult>> + Send + 'a>>;

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
        fut: impl Future<Output = anyhow::Result<TestResult>> + Send + 'a,
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
    fn pass_preserves_context() {
        let r = TestResult::pass(&CTX);
        assert_eq!(r.ctx.primary_ref(), "TEST-1");
        assert_eq!(r.ctx.description, "test description");
        assert!(matches!(r.ctx.compliance, Compliance::Must));
        assert!(matches!(r.outcome, Outcome::Pass));
    }

    #[test]
    fn fail_stores_message() {
        let r = TestResult::fail(&CTX, "something broke");
        match r.outcome {
            Outcome::Fail { message, verbose } => {
                assert_eq!(message, "something broke");
                assert!(verbose.is_none());
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn fail_verbose_stores_both() {
        let r = TestResult::fail_verbose(&CTX, "short", "long details");
        match r.outcome {
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
        let r = TestResult::fail_packet(&CTX, "SUBACK(1)", &connack);
        match r.outcome {
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
        let r = TestResult::skip(&CTX, "broker does not support feature");
        match r.outcome {
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
                TestResult::pass(&CTX),
                TestResult::fail(&CTX, "oops"),
                TestResult::skip(&CTX, "n/a"),
            ],
        };
        assert_eq!(suite.name, "test-suite");
        assert_eq!(suite.results.len(), 3);
        assert!(matches!(suite.results[0].outcome, Outcome::Pass));
        assert!(matches!(suite.results[1].outcome, Outcome::Fail { .. }));
        assert!(matches!(suite.results[2].outcome, Outcome::Skip(_)));
    }
}
