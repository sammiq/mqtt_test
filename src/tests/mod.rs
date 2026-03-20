pub mod connect;
pub mod disconnect;
pub mod ping;
pub mod publish;
pub mod subscribe;

use std::time::Duration;

use crate::report::Report;
use crate::SuiteName;

/// Run only the named suites against the broker at `addr`.
pub async fn run_selected(addr: &str, recv_timeout: Duration, suites: &[SuiteName]) -> Report {
    let mut report = Report::new();
    for suite in suites {
        match suite {
            SuiteName::Connect   => report.add(connect::run(addr, recv_timeout).await),
            SuiteName::Ping      => report.add(ping::run(addr, recv_timeout).await),
            SuiteName::Publish   => report.add(publish::run(addr, recv_timeout).await),
            SuiteName::Subscribe => report.add(subscribe::run(addr, recv_timeout).await),
            SuiteName::Disconnect => report.add(disconnect::run(addr, recv_timeout).await),
        }
    }
    report
}
