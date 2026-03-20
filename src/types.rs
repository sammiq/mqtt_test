use crate::codec::Packet;

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
#[derive(Debug, Clone, Copy)]
pub struct TestContext {
    pub id: &'static str,
    pub description: &'static str,
    pub compliance: Compliance,
}

/// The result of running a single test.
#[derive(Debug, Clone)]
pub enum Outcome {
    Pass,
    Fail { message: String, verbose: Option<String> },
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
        Self { ctx: *ctx, outcome: Outcome::Pass }
    }

    pub fn fail(ctx: &TestContext, reason: impl Into<String>) -> Self {
        Self { ctx: *ctx, outcome: Outcome::Fail { message: reason.into(), verbose: None } }
    }

    #[allow(dead_code)]
    pub fn fail_verbose(
        ctx: &TestContext,
        reason: impl Into<String>,
        verbose: impl Into<String>,
    ) -> Self {
        Self { ctx: *ctx, outcome: Outcome::Fail { message: reason.into(), verbose: Some(verbose.into()) } }
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
        Self { ctx: *ctx, outcome: Outcome::Skip(reason.into()) }
    }
}

/// A named group of related test results.
pub struct Suite {
    pub name: &'static str,
    pub results: Vec<TestResult>,
}
