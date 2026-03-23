pub mod auth;
pub mod connect;
pub mod disconnect;
pub mod malformed;
pub mod ping;
pub mod publish;
pub mod request_response;
pub mod session;
pub mod subscribe;
pub mod transport;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::report::Report;
use crate::types::TestConfig;
use crate::SuiteName;

fn make_progress_bar(mp: &MultiProgress, name: &str, count: usize) -> ProgressBar {
    let pb = mp.add(ProgressBar::new(count as u64));
    pb.set_style(
        ProgressStyle::with_template("{prefix:.bold} [{bar:20.cyan/dim}] {pos}/{len} ({elapsed})")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb.set_prefix(format!("{name:<24}"));
    pb
}

/// Run only the named suites against the broker.
pub async fn run_selected(
    config: TestConfig<'_>,
    suites: &[SuiteName],
    mp: &MultiProgress,
) -> Report {
    let mut report = Report::new();
    for suite in suites {
        let runner = match suite {
            SuiteName::Transport => transport::tests(config),
            SuiteName::Connect => connect::tests(config),
            SuiteName::Ping => ping::tests(config),
            SuiteName::Publish => publish::tests(config),
            SuiteName::Subscribe => subscribe::tests(config),
            SuiteName::Session => session::tests(config),
            SuiteName::Malformed => malformed::tests(config),
            SuiteName::Disconnect => disconnect::tests(config),
            SuiteName::RequestResponse => request_response::tests(config),
            SuiteName::Auth => auth::tests(config),
        };
        let pb = make_progress_bar(mp, runner.name, runner.count());
        pb.println(format!(
            "\n{}\n{}",
            runner.name,
            "-".repeat(runner.name.len())
        ));
        report.add(runner.run(&pb).await);
        pb.finish_and_clear();
    }
    report
}
