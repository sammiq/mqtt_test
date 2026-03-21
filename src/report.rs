use std::time::Duration;

use clap::ValueEnum;
use indicatif::{HumanDuration, ProgressBar};

use crate::types::{Compliance, Outcome, Suite, TestContext, TestResult};

/// How to order the final compliance report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportOrder {
    /// Group results by test suite (default).
    Suite,
    /// Sort all results by MQTT spec requirement number.
    Requirement,
}

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

    pub fn print(&self, verbose: bool, order: ReportOrder, elapsed: Duration) {
        println!("MQTT v5 Compliance Report");
        println!("{}", "=".repeat(60));

        match order {
            ReportOrder::Suite => self.print_by_suite(verbose),
            ReportOrder::Requirement => self.print_by_requirement(verbose),
        }

        self.print_summary(elapsed);
    }

    fn print_by_suite(&self, verbose: bool) {
        for suite in &self.suites {
            println!("\n{}", suite.name);
            println!("{}", "-".repeat(suite.name.len()));

            for r in &suite.results {
                println!("  {}", format_result(r, verbose));
            }
        }
    }

    fn print_by_requirement(&self, verbose: bool) {
        let mut all_results: Vec<&TestResult> = self.suites.iter()
            .flat_map(|s| &s.results)
            .collect();
        all_results.sort_by(|a, b| parse_requirement_key(a.ctx.id).cmp(&parse_requirement_key(b.ctx.id)));

        let mut last_section = String::new();
        for r in &all_results {
            let section = requirement_section(r.ctx.id);
            if section != last_section {
                println!("\nMQTT {section}");
                println!("{}", "-".repeat(6 + section.len()));
                last_section = section;
            }
            println!("  {}", format_result(r, verbose));
        }
    }

    fn print_summary(&self, elapsed: Duration) {
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
        println!("Summary  ({})", HumanDuration(elapsed));
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

fn format_result(r: &TestResult, verbose: bool) -> String {
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
    format!("[{status}] {level} [{:<14}] {}{detail}", r.ctx.id, r.ctx.description)
}

/// Parse "MQTT-3.1.2-4" into a sortable tuple of numeric parts.
fn parse_requirement_key(id: &str) -> Vec<u32> {
    id.strip_prefix("MQTT-")
        .unwrap_or(id)
        .split(['.', '-'])
        .map(|part| {
            // Handle suffixes like "5a", "5b" — strip trailing alpha for primary sort
            let numeric: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            numeric.parse().unwrap_or(0)
        })
        .collect()
}

/// Extract the spec section from an ID, e.g. "MQTT-3.1.2-4" -> "3.1.2".
fn requirement_section(id: &str) -> String {
    let stripped = id.strip_prefix("MQTT-").unwrap_or(id);
    // Take everything up to the last '-' which is the requirement number within the section
    match stripped.rsplit_once('-') {
        Some((section, _)) => section.to_string(),
        None => stripped.to_string(),
    }
}

/// Convenience: wrap a test body so any `anyhow::Error` becomes a Fail result.
/// Ticks the progress bar and prints a per-test status line when each test completes.
pub async fn run_test(
    ctx: TestContext,
    pb: &ProgressBar,
    fut: impl std::future::Future<Output = anyhow::Result<TestResult>>,
) -> TestResult {
    tracing::debug!(id = ctx.id, ctx.description, "running test");
    pb.set_message(ctx.id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_requirement_key_standard() {
        assert_eq!(parse_requirement_key("MQTT-3.1.2-4"), vec![3, 1, 2, 4]);
    }

    #[test]
    fn parse_requirement_key_with_suffix() {
        // "5a" should parse the numeric prefix as 5
        assert_eq!(parse_requirement_key("MQTT-3.8.3-5a"), vec![3, 8, 3, 5]);
        assert_eq!(parse_requirement_key("MQTT-3.8.3-5b"), vec![3, 8, 3, 5]);
    }

    #[test]
    fn parse_requirement_key_no_prefix() {
        assert_eq!(parse_requirement_key("3.1.2-4"), vec![3, 1, 2, 4]);
    }

    #[test]
    fn parse_requirement_key_ordering() {
        let a = parse_requirement_key("MQTT-3.1.2-4");
        let b = parse_requirement_key("MQTT-3.2.0-1");
        let c = parse_requirement_key("MQTT-4.3.1-1");
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn requirement_section_standard() {
        assert_eq!(requirement_section("MQTT-3.1.2-4"), "3.1.2");
    }

    #[test]
    fn requirement_section_deep() {
        assert_eq!(requirement_section("MQTT-4.7.1-2"), "4.7.1");
    }

    #[test]
    fn requirement_section_no_prefix() {
        assert_eq!(requirement_section("3.1.2-4"), "3.1.2");
    }

    #[test]
    fn requirement_section_no_dash() {
        assert_eq!(requirement_section("MQTT-3.1.2"), "3.1.2");
    }

    #[test]
    fn format_result_must_pass() {
        let ctx = TestContext { id: "MQTT-3.1.2-4", description: "Test desc", compliance: Compliance::Must };
        let r = TestResult::pass(&ctx);
        let s = format_result(&r, false);
        assert!(s.contains("PASS"));
        assert!(s.contains("MUST"));
        assert!(s.contains("MQTT-3.1.2-4"));
        assert!(s.contains("Test desc"));
    }

    #[test]
    fn format_result_must_fail() {
        let ctx = TestContext { id: "MQTT-3.1.2-4", description: "Test desc", compliance: Compliance::Must };
        let r = TestResult::fail(&ctx, "bad thing");
        let s = format_result(&r, false);
        assert!(s.contains("FAIL"));
        assert!(s.contains("bad thing"));
    }

    #[test]
    fn format_result_may_pass_shows_yes() {
        let ctx = TestContext { id: "MQTT-3.1.3-8", description: "Optional feature", compliance: Compliance::May };
        let r = TestResult::pass(&ctx);
        let s = format_result(&r, false);
        assert!(s.contains("YES"));
        assert!(s.contains("MAY"));
    }

    #[test]
    fn format_result_may_fail_shows_no() {
        let ctx = TestContext { id: "MQTT-3.1.3-8", description: "Optional feature", compliance: Compliance::May };
        let r = TestResult::fail(&ctx, "not supported");
        let s = format_result(&r, false);
        assert!(s.contains("NO"));
    }

    #[test]
    fn format_result_skip() {
        let ctx = TestContext { id: "MQTT-3.1.3-8", description: "Test", compliance: Compliance::Must };
        let r = TestResult::skip(&ctx, "prereq not met");
        let s = format_result(&r, false);
        assert!(s.contains("SKIP"));
        assert!(s.contains("prereq not met"));
    }

    #[test]
    fn format_result_verbose_uses_verbose_detail() {
        let ctx = TestContext { id: "MQTT-3.1.2-4", description: "Test", compliance: Compliance::Must };
        let r = TestResult::fail_verbose(&ctx, "short", "long detailed message");
        let short = format_result(&r, false);
        let long = format_result(&r, true);
        assert!(short.contains("short"));
        assert!(!short.contains("long detailed"));
        assert!(long.contains("long detailed message"));
    }
}
