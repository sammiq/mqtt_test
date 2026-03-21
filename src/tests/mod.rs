pub mod connect;
pub mod disconnect;
pub mod malformed;
pub mod ping;
pub mod publish;
pub mod request_response;
pub mod session;
pub mod subscribe;
pub mod tls;

use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::client::TlsConfig;
use crate::report::Report;
use crate::SuiteName;

fn make_progress_bar(mp: &MultiProgress, name: &str, count: usize) -> ProgressBar {
    let pb = mp.add(ProgressBar::new(count as u64));
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.bold} [{bar:20.cyan/dim}] {pos}/{len} ({elapsed})"
        )
        .unwrap()
        .progress_chars("█▓░"),
    );
    pb.set_prefix(format!("{name:<24}"));
    pb
}

/// Run only the named suites against the broker at `addr`.
/// TLS-specific suites use `tls_info` (address + config) when provided.
pub async fn run_selected(
    addr: &str,
    tls_info: Option<(&str, &TlsConfig)>,
    recv_timeout: Duration,
    suites: &[SuiteName],
    mp: &MultiProgress,
) -> Report {
    let mut report = Report::new();
    for suite in suites {
        let (name, count) = match suite {
            SuiteName::Connect    => ("CONNECT / CONNACK",      connect::TEST_COUNT),
            SuiteName::Ping       => ("PINGREQ / PINGRESP",     ping::TEST_COUNT),
            SuiteName::Publish    => ("PUBLISH",                publish::TEST_COUNT),
            SuiteName::Subscribe  => ("SUBSCRIBE / UNSUBSCRIBE", subscribe::TEST_COUNT),
            SuiteName::Session    => ("SESSION",                session::TEST_COUNT),
            SuiteName::Malformed        => ("MALFORMED PACKETS",      malformed::TEST_COUNT),
            SuiteName::Disconnect       => ("DISCONNECT",             disconnect::TEST_COUNT),
            SuiteName::RequestResponse  => ("REQUEST / RESPONSE",    request_response::TEST_COUNT),
            SuiteName::Tls              => ("TLS",                   tls::TEST_COUNT),
        };
        let pb = make_progress_bar(mp, name, count);
        pb.println(format!("\n{name}\n{}", "-".repeat(name.len())));

        match suite {
            SuiteName::Connect    => report.add(connect::run(addr, recv_timeout, &pb).await),
            SuiteName::Ping       => report.add(ping::run(addr, recv_timeout, &pb).await),
            SuiteName::Publish    => report.add(publish::run(addr, recv_timeout, &pb).await),
            SuiteName::Subscribe  => report.add(subscribe::run(addr, recv_timeout, &pb).await),
            SuiteName::Session    => report.add(session::run(addr, recv_timeout, &pb).await),
            SuiteName::Malformed        => report.add(malformed::run(addr, recv_timeout, &pb).await),
            SuiteName::Disconnect       => report.add(disconnect::run(addr, recv_timeout, &pb).await),
            SuiteName::RequestResponse  => report.add(request_response::run(addr, recv_timeout, &pb).await),
            SuiteName::Tls => {
                if let Some((tls_addr, tls_config)) = tls_info {
                    report.add(tls::run(tls_addr, tls_config, recv_timeout, &pb).await);
                } else {
                    pb.println("  [SKIP] TLS suite requires --tls-broker");
                }
            }
        }

        pb.finish_and_clear();
    }
    report
}
