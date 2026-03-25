use std::io::IsTerminal;
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
    /// Sort all results by compliance level (MUST, SHOULD, MAY).
    Level,
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

    pub fn print(&self, verbose: bool, order: ReportOrder, failures_only: bool, elapsed: Duration) {
        let color = std::io::stdout().is_terminal();

        println!("MQTT v5 Compliance Report");
        println!("{}", "=".repeat(60));

        match order {
            ReportOrder::Suite => self.print_by_suite(verbose, failures_only, color),
            ReportOrder::Requirement => self.print_by_requirement(verbose, failures_only, color),
            ReportOrder::Level => self.print_by_level(verbose, failures_only, color),
        }

        self.print_summary(color, elapsed);
    }

    fn print_by_suite(&self, verbose: bool, failures_only: bool, color: bool) {
        for suite in &self.suites {
            let results: Vec<_> = suite
                .results
                .iter()
                .filter(|r| !failures_only || is_failure(r))
                .collect();
            if failures_only && results.is_empty() {
                continue;
            }
            println!("\n{}", suite.name);
            println!("{}", "-".repeat(suite.name.len()));

            for r in &results {
                println!("  {}", format_result(r, verbose, color));
            }
        }
    }

    fn print_by_requirement(&self, verbose: bool, failures_only: bool, color: bool) {
        let mut all_results: Vec<&TestResult> = self
            .suites
            .iter()
            .flat_map(|s| &s.results)
            .filter(|r| !failures_only || is_failure(r))
            .collect();
        all_results.sort_by(|a, b| {
            parse_requirement_key(a.ctx.primary_ref())
                .cmp(&parse_requirement_key(b.ctx.primary_ref()))
        });

        let mut last_section = String::new();
        for r in &all_results {
            let section = requirement_section(r.ctx.primary_ref());
            if section != last_section {
                println!("\nSection {section}");
                println!("{}", "-".repeat(9 + section.len()));
                last_section = section;
            }
            println!("  {}", format_result(r, verbose, color));
        }
    }

    fn print_by_level(&self, verbose: bool, failures_only: bool, color: bool) {
        let mut all_results: Vec<&TestResult> = self
            .suites
            .iter()
            .flat_map(|s| &s.results)
            .filter(|r| !failures_only || is_failure(r))
            .collect();
        all_results.sort_by(|a, b| {
            let level_ord =
                compliance_order(a.ctx.compliance).cmp(&compliance_order(b.ctx.compliance));
            level_ord.then_with(|| {
                parse_requirement_key(a.ctx.primary_ref())
                    .cmp(&parse_requirement_key(b.ctx.primary_ref()))
            })
        });

        let mut last_level = None;
        for r in &all_results {
            if last_level != Some(r.ctx.compliance) {
                let label = match r.ctx.compliance {
                    Compliance::Must => "MUST",
                    Compliance::Should => "SHOULD",
                    Compliance::May => "MAY",
                };
                println!("\n{label}");
                println!("{}", "-".repeat(label.len()));
                last_level = Some(r.ctx.compliance);
            }
            println!("  {}", format_result(r, verbose, color));
        }
    }

    fn print_summary(&self, color: bool, elapsed: Duration) {
        let mut must_pass = 0usize;
        let mut must_total = 0usize;
        let mut must_skip = 0usize;
        let mut should_pass = 0usize;
        let mut should_total = 0usize;
        let mut should_skip = 0usize;
        let mut may_pass = 0usize;
        let mut may_total = 0usize;
        let mut may_skip = 0usize;

        for suite in &self.suites {
            for r in &suite.results {
                if matches!(r.outcome, Outcome::Skip(_)) {
                    match r.ctx.compliance {
                        Compliance::Must => must_skip += 1,
                        Compliance::Should => should_skip += 1,
                        Compliance::May => may_skip += 1,
                    }
                    continue;
                }
                let passed = matches!(r.outcome, Outcome::Pass);
                match r.ctx.compliance {
                    Compliance::Must => {
                        must_total += 1;
                        if passed {
                            must_pass += 1;
                        }
                    }
                    Compliance::Should => {
                        should_total += 1;
                        if passed {
                            should_pass += 1;
                        }
                    }
                    Compliance::May => {
                        may_total += 1;
                        if passed {
                            may_pass += 1;
                        }
                    }
                }
            }
        }

        println!("\n{}", "=".repeat(60));
        println!("Summary  ({})", HumanDuration(elapsed));

        let fmt_score = |pass: usize, total: usize, skip: usize| -> String {
            let score = if !color || pass == total {
                format!("{pass}/{total}")
            } else {
                format!("\x1b[31m{pass}/{total}\x1b[0m")
            };
            if skip > 0 {
                format!("{score} ({skip} skipped)")
            } else {
                score
            }
        };

        println!(
            "  Required (MUST):       {}",
            fmt_score(must_pass, must_total, must_skip)
        );
        println!(
            "  Recommended (SHOULD):  {}",
            fmt_score(should_pass, should_total, should_skip)
        );
        let may_score = format!("{may_pass}/{may_total}");
        if may_skip > 0 {
            println!("  Optional (MAY):        {may_score} ({may_skip} skipped)");
        } else {
            println!("  Optional (MAY):        {may_score}");
        }

        if must_total > 0 && must_pass == must_total {
            let msg = "Broker satisfies all required MQTT v5 behaviours.";
            if color {
                println!("\n  \x1b[32m{msg}\x1b[0m");
            } else {
                println!("\n  {msg}");
            }
        } else if must_total > 0 {
            let count = must_total - must_pass;
            let msg = format!("Broker has {count} required compliance failure(s).");
            if color {
                println!("\n  \x1b[31m{msg}\x1b[0m");
            } else {
                println!("\n  {msg}");
            }
        }
    }
}

/// Returns true if the result is a failure (not pass, not skip).
fn is_failure(r: &TestResult) -> bool {
    matches!(r.outcome, Outcome::Fail { .. })
}

/// Ordering value for compliance levels: MUST first, then SHOULD, then MAY.
fn compliance_order(c: Compliance) -> u8 {
    match c {
        Compliance::Must => 0,
        Compliance::Should => 1,
        Compliance::May => 2,
    }
}

fn format_result(r: &TestResult, verbose: bool, color: bool) -> String {
    let level = match r.ctx.compliance {
        Compliance::Must => "MUST  ",
        Compliance::Should => "SHOULD",
        Compliance::May => "MAY   ",
    };
    let is_may = r.ctx.compliance == Compliance::May;
    let (status_text, detail) = match &r.outcome {
        Outcome::Pass => (if is_may { " YES" } else { "PASS" }, String::new()),
        Outcome::Fail {
            message,
            verbose: verbose_detail,
        } => {
            let msg = if verbose {
                verbose_detail.as_deref().unwrap_or(message)
            } else {
                message
            };
            (if is_may { "  NO" } else { "FAIL" }, format!(" — {msg}"))
        }
        Outcome::Skip(msg) => ("SKIP", format!(" — {msg}")),
    };
    let status = if color {
        match &r.outcome {
            Outcome::Pass => format!("\x1b[32m{status_text}\x1b[0m"),
            Outcome::Fail { .. } if is_may => format!("\x1b[90m{status_text}\x1b[0m"),
            Outcome::Fail { .. } => format!("\x1b[31m{status_text}\x1b[0m"),
            Outcome::Skip(_) => format!("\x1b[90m{status_text}\x1b[0m"),
        }
    } else {
        status_text.to_string()
    };
    let refs_str = r.ctx.refs.join(", ");
    format!(
        "[{status}] {level} [{refs_str:<14}] {}{detail}",
        r.ctx.description
    )
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

/// Extract the spec section from an ID, e.g. "MQTT-3.1.2-4" -> "3.1".
///
/// Chapters 3 and 4 are grouped at the X.Y level (e.g. 3.1 = CONNECT,
/// 4.7 = Topic Names and Filters).  Chapters 1, 2, and 6 are each a
/// single section and group at the chapter level.
fn requirement_section(id: &str) -> String {
    let stripped = id.strip_prefix("MQTT-").unwrap_or(id);
    let parts: Vec<&str> = stripped.split('.').collect();
    match parts.first().copied() {
        // Chapters 3 (Control Packets) and 4 (Operational Behavior) have
        // distinct sections per packet type / topic, so group at X.Y.
        Some("3") | Some("4") if parts.len() >= 2 => {
            format!("{}.{}", parts[0], parts[1])
        }
        Some(chapter) => chapter.to_string(),
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
    tracing::debug!(id = ctx.primary_ref(), ctx.description, "running test");
    pb.set_message(ctx.primary_ref());
    let result = match fut.await {
        Ok(r) => r,
        Err(e) => TestResult::fail(&ctx, format!("test error: {e:#}")),
    };
    tracing::debug!(id = ctx.primary_ref(), outcome = ?result.outcome, "test complete");

    let is_may = ctx.compliance == Compliance::May;
    let symbol = match (&result.outcome, is_may) {
        (Outcome::Pass, false) => "\x1b[32m✓\x1b[0m", // green check
        (Outcome::Pass, true) => "\x1b[36m●\x1b[0m",  // cyan dot (supported)
        (Outcome::Fail { .. }, false) => "\x1b[31m✗\x1b[0m", // red cross
        (Outcome::Fail { .. }, true) => "\x1b[90m·\x1b[0m", // dim dot (not supported)
        (Outcome::Skip(_), _) => "\x1b[90m○\x1b[0m",  // dim circle (skipped)
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
        assert_eq!(requirement_section("MQTT-3.1.2-4"), "3.1");
    }

    #[test]
    fn requirement_section_deep() {
        assert_eq!(requirement_section("MQTT-4.7.1-2"), "4.7");
    }

    #[test]
    fn requirement_section_no_prefix() {
        assert_eq!(requirement_section("3.1.2-4"), "3.1");
    }

    #[test]
    fn requirement_section_chapter_only() {
        assert_eq!(requirement_section("MQTT-1.5.4-1"), "1");
        assert_eq!(requirement_section("MQTT-2.2.1-3"), "2");
        assert_eq!(requirement_section("MQTT-6.0.0-1"), "6");
    }

    #[test]
    fn format_result_must_pass() {
        let ctx = TestContext {
            refs: &["MQTT-3.1.2-4"],
            description: "Test desc",
            compliance: Compliance::Must,
        };
        let r = TestResult::pass(&ctx);
        let s = format_result(&r, false, false);
        assert!(s.contains("PASS"));
        assert!(s.contains("MUST"));
        assert!(s.contains("MQTT-3.1.2-4"));
        assert!(s.contains("Test desc"));
    }

    #[test]
    fn format_result_must_fail() {
        let ctx = TestContext {
            refs: &["MQTT-3.1.2-4"],
            description: "Test desc",
            compliance: Compliance::Must,
        };
        let r = TestResult::fail(&ctx, "bad thing");
        let s = format_result(&r, false, false);
        assert!(s.contains("FAIL"));
        assert!(s.contains("bad thing"));
    }

    #[test]
    fn format_result_may_pass_shows_yes() {
        let ctx = TestContext {
            refs: &["MQTT-3.1.3-8"],
            description: "Optional feature",
            compliance: Compliance::May,
        };
        let r = TestResult::pass(&ctx);
        let s = format_result(&r, false, false);
        assert!(s.contains("YES"));
        assert!(s.contains("MAY"));
    }

    #[test]
    fn format_result_may_fail_shows_no() {
        let ctx = TestContext {
            refs: &["MQTT-3.1.3-8"],
            description: "Optional feature",
            compliance: Compliance::May,
        };
        let r = TestResult::fail(&ctx, "not supported");
        let s = format_result(&r, false, false);
        assert!(s.contains("NO"));
    }

    #[test]
    fn format_result_skip() {
        let ctx = TestContext {
            refs: &["MQTT-3.1.3-8"],
            description: "Test",
            compliance: Compliance::Must,
        };
        let r = TestResult::skip(&ctx, "prereq not met");
        let s = format_result(&r, false, false);
        assert!(s.contains("SKIP"));
        assert!(s.contains("prereq not met"));
    }

    #[test]
    fn format_result_verbose_uses_verbose_detail() {
        let ctx = TestContext {
            refs: &["MQTT-3.1.2-4"],
            description: "Test",
            compliance: Compliance::Must,
        };
        let r = TestResult::fail_verbose(&ctx, "short", "long detailed message");
        let short = format_result(&r, false, false);
        let long = format_result(&r, true, false);
        assert!(short.contains("short"));
        assert!(!short.contains("long detailed"));
        assert!(long.contains("long detailed message"));
    }
}
