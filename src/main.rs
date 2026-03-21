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
    Tls,
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
            Self::Tls              => write!(f, "tls"),
        }
    }
}

#[derive(Parser)]
#[command(name = "mqtt_test", about = "MQTT v5 broker compliance tester")]
struct Args {
    /// Broker address for TCP tests, e.g. 127.0.0.1:1883
    #[arg(short, long, default_value = "127.0.0.1:1883")]
    broker: String,

    /// TLS broker address for TLS-specific tests, e.g. 127.0.0.1:8883.
    /// When provided, the TLS suite is included automatically.
    #[arg(long)]
    tls_broker: Option<String>,

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

    /// Run only specific suites (comma-separated: connect,ping,publish,subscribe,tls)
    #[arg(short, long, value_delimiter = ',')]
    suite: Option<Vec<SuiteName>>,

    /// Report ordering: "suite" (default) groups by test suite, "requirement" sorts by spec section
    #[arg(long, default_value = "suite")]
    order: ReportOrder,

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

    // Build TLS config if a TLS broker was specified
    let tls_config = args.tls_broker.as_ref().map(|tls_addr| {
        let host = tls_addr.split(':').next().unwrap_or("localhost");
        client::TlsConfig::build(
            args.ca_cert.as_deref(),
            args.insecure,
            host,
        )
        .expect("failed to build TLS configuration")
    });

    // Resolve which suites to run
    let all_suites = if tls_config.is_some() {
        vec![
            SuiteName::Connect, SuiteName::Ping, SuiteName::Publish,
            SuiteName::Subscribe, SuiteName::Session, SuiteName::Malformed,
            SuiteName::Disconnect, SuiteName::RequestResponse, SuiteName::Tls,
        ]
    } else {
        vec![
            SuiteName::Connect, SuiteName::Ping, SuiteName::Publish,
            SuiteName::Subscribe, SuiteName::Session, SuiteName::Malformed,
            SuiteName::Disconnect, SuiteName::RequestResponse,
        ]
    };
    let suites_to_run = args.suite.as_deref().unwrap_or(&all_suites);

    println!("Testing broker at {} (timeout: {}ms)", args.broker, args.timeout_ms);
    if let Some(ref tls_addr) = args.tls_broker {
        println!("TLS broker at {tls_addr}");
    }
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

    // Preflight: Verify TLS reachability if configured
    if let Some(ref tls_addr) = args.tls_broker {
        print!("Preflight: TLS connection ... ");
        match tokio::time::timeout(
            recv_timeout,
            tokio::net::TcpStream::connect(tls_addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                println!("ok");
            }
            Ok(Err(e)) => {
                eprintln!("FAILED\n  Cannot connect to {tls_addr}: {e}");
                std::process::exit(1);
            }
            Err(_) => {
                eprintln!("FAILED\n  Connection to {tls_addr} timed out");
                std::process::exit(1);
            }
        }
    }

    println!();

    // Set up progress bars — hide when debug logging is active or stdout is not a TTY.
    let mp = MultiProgress::new();
    let show_progress = !args.debug && !args.trace && std::io::stderr().is_terminal();
    if !show_progress {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }

    let tls_info = args.tls_broker.as_deref().zip(tls_config.as_ref());
    let report = tests::run_selected(&args.broker, tls_info, recv_timeout, suites_to_run, &mp).await;

    println!();
    report.print(args.verbose, args.order);
}
