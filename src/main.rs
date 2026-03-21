mod client;
mod codec;
mod report;
mod tests;
mod types;

use std::io::IsTerminal;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use report::ReportOrder;
use indicatif::{MultiProgress, ProgressDrawTarget};
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SuiteName {
    Connect,
    Ping,
    Publish,
    Subscribe,
    Session,
    Malformed,
    Disconnect,
    RequestResponse,
}

impl std::fmt::Display for SuiteName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect    => write!(f, "connect"),
            Self::Ping       => write!(f, "ping"),
            Self::Publish    => write!(f, "publish"),
            Self::Subscribe  => write!(f, "subscribe"),
            Self::Session    => write!(f, "session"),
            Self::Malformed  => write!(f, "malformed"),
            Self::Disconnect       => write!(f, "disconnect"),
            Self::RequestResponse  => write!(f, "request-response"),
        }
    }
}

#[derive(Parser)]
#[command(name = "mqtt_test", about = "MQTT v5 broker compliance tester")]
struct Args {
    /// Broker address, e.g. 127.0.0.1:1883
    #[arg(short, long, default_value = "127.0.0.1:1883")]
    broker: String,

    /// Timeout in milliseconds to wait for each broker response
    #[arg(short, long, default_value_t = 5000)]
    timeout_ms: u64,

    /// Show full packet debug output for failed tests
    #[arg(short = 'V', long)]
    verbose: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Enable trace logging (implies --debug)
    #[arg(long)]
    trace: bool,

    /// Run only specific suites (comma-separated: connect,ping,publish,subscribe)
    #[arg(short, long, value_delimiter = ',')]
    suite: Option<Vec<SuiteName>>,

    /// Report ordering: "suite" (default) groups by test suite, "requirement" sorts by spec section
    #[arg(long, default_value = "suite")]
    order: ReportOrder,

    /// Use TLS for the broker connection
    #[arg(long)]
    tls: bool,

    /// Path to CA certificate PEM file for TLS verification
    #[arg(long)]
    ca_cert: Option<std::path::PathBuf>,

    /// Skip TLS certificate verification (insecure)
    #[arg(long)]
    insecure: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Set up tracing
    let level = if args.trace {
        LevelFilter::TRACE
    } else if args.debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::OFF
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    let recv_timeout = Duration::from_millis(args.timeout_ms);

    // Set up TLS if requested
    if args.tls {
        let host = args.broker.split(':').next().unwrap_or("localhost");
        let tls = client::TlsConfig::build(
            args.ca_cert.as_deref(),
            args.insecure,
            host,
        )
        .expect("failed to build TLS configuration");
        client::set_tls_config(Some(tls));
    } else {
        client::set_tls_config(None);
    }

    // Resolve which suites to run
    let all_suites = [SuiteName::Connect, SuiteName::Ping, SuiteName::Publish, SuiteName::Subscribe, SuiteName::Session, SuiteName::Malformed, SuiteName::Disconnect, SuiteName::RequestResponse];
    let suites_to_run = args.suite.as_deref().unwrap_or(&all_suites);

    let tls_label = if args.tls { " (TLS)" } else { "" };
    println!("Testing broker at {}{} (timeout: {}ms)", args.broker, tls_label, args.timeout_ms);
    println!("Suites: {}\n", suites_to_run.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "));

    // Preflight: Verify TCP reachability
    print!("Preflight: TCP connection ... ");
    match tokio::time::timeout(
        recv_timeout,
        tokio::net::TcpStream::connect(&args.broker),
    )
    .await
    {
        Ok(Ok(stream)) => {
            drop(stream);
            println!("ok");
        }
        Ok(Err(e)) => {
            eprintln!("FAILED\n  Cannot connect to {}: {e}", args.broker);
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("FAILED\n  Connection to {} timed out", args.broker);
            std::process::exit(1);
        }
    }

    println!();

    // Set up progress bars — hide when debug logging is active or stdout is not a TTY.
    let mp = MultiProgress::new();
    let show_progress = !args.debug && !args.trace && std::io::stderr().is_terminal();
    if !show_progress {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }

    let report = tests::run_selected(&args.broker, recv_timeout, suites_to_run, &mp).await;

    println!();
    report.print(args.verbose, args.order);
}
