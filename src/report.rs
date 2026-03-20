use indicatif::ProgressBar;

use crate::types::{Compliance, Outcome, Suite, TestContext, TestResult};

pub struct Report {
    pub suites: Vec<Suite>,
}

impl Report {
    pub fn new() -> Self {
        Self { suites: Vec::new() }
    }

    pub fn add(&mut self, suite: Suite) {
        self.suites.push(suite);
    }

    pub fn print(&self, verbose: bool) {
        println!("MQTT v5 Compliance Report");
        println!("{}", "=".repeat(60));

        for suite in &self.suites {
            println!("\n{}", suite.name);
            println!("{}", "-".repeat(suite.name.len()));

            for r in &suite.results {
                let level = match r.ctx.compliance {
                    Compliance::Must   => "MUST  ",
                    Compliance::Should => "SHOULD",
                    Compliance::May    => "MAY   ",
                };
                let is_may = r.ctx.compliance == Compliance::May;
                let (status, detail) = match &r.outcome {
                    Outcome::Pass => (if is_may { " YES" } else { "PASS" }, String::new()),
                    Outcome::Fail { message, verbose: verbose_detail } => {
                        let msg = if verbose {
                            verbose_detail.as_deref().unwrap_or(message)
                        } else {
                            message
                        };
                        (if is_may { "  NO" } else { "FAIL" }, format!(" — {msg}"))
                    }
                    Outcome::Skip(msg) => ("SKIP", format!(" — {msg}")),
                };
                println!("  [{status}] {level} [{:<16}] {}{detail}", r.ctx.id, r.ctx.description);
            }
        }

        self.print_summary();
    }

    fn print_summary(&self) {
        let mut must_pass = 0usize;
        let mut must_total = 0usize;
        let mut should_pass = 0usize;
        let mut should_total = 0usize;
        let mut may_pass = 0usize;
        let mut may_total = 0usize;

        for suite in &self.suites {
            for r in &suite.results {
                if matches!(r.outcome, Outcome::Skip(_)) {
                    continue;
                }
                let passed = matches!(r.outcome, Outcome::Pass);
                match r.ctx.compliance {
                    Compliance::Must => {
                        must_total += 1;
                        if passed { must_pass += 1; }
                    }
                    Compliance::Should => {
                        should_total += 1;
                        if passed { should_pass += 1; }
                    }
                    Compliance::May => {
                        may_total += 1;
                        if passed { may_pass += 1; }
                    }
                }
            }
        }

        println!("\n{}", "=".repeat(60));
        println!("Summary");
        println!("  Required (MUST):       {must_pass}/{must_total}");
        println!("  Recommended (SHOULD):  {should_pass}/{should_total}");
        println!("  Optional (MAY):        {may_pass}/{may_total}");

        if must_total > 0 && must_pass == must_total {
            println!("\n  Broker satisfies all required MQTT v5 behaviours.");
        } else if must_total > 0 {
            println!("\n  Broker has {} required compliance failure(s).", must_total - must_pass);
        }
    }
}

/// Convenience: wrap a test body so any `anyhow::Error` becomes a Fail result.
/// Ticks the progress bar and prints a per-test status line when each test completes.
pub fn run_test<F, Fut>(
    ctx: TestContext,
    pb: &ProgressBar,
    f: F,
) -> impl std::future::Future<Output = TestResult>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<TestResult>>,
{
    tracing::debug!(id = ctx.id, ctx.description, "running test");
    pb.set_message(ctx.id);
    let fut = f();
    let pb = pb.clone();
    async move {
        let result = match fut.await {
            Ok(r)  => r,
            Err(e) => TestResult::fail(&ctx, format!("test error: {e:#}")),
        };
        tracing::debug!(id = ctx.id, outcome = ?result.outcome, "test complete");

        let is_may = ctx.compliance == Compliance::May;
        let symbol = match (&result.outcome, is_may) {
            (Outcome::Pass,      false) => "\x1b[32m✓\x1b[0m",  // green check
            (Outcome::Pass,      true)  => "\x1b[36m●\x1b[0m",  // cyan dot (supported)
            (Outcome::Fail {..}, false) => "\x1b[31m✗\x1b[0m",  // red cross
            (Outcome::Fail {..}, true)  => "\x1b[90m·\x1b[0m",  // dim dot (not supported)
            (Outcome::Skip(_),   _)     => "\x1b[90m○\x1b[0m",  // dim circle (skipped)
        };
        pb.println(format!("  {symbol} {}", ctx.description));
        pb.inc(1);

        result
    }
}
