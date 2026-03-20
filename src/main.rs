mod client;
mod codec;
mod report;
mod tests;
mod types;

use std::time::Duration;

use clap::{Parser, ValueEnum};
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
            Self::Disconnect => write!(f, "disconnect"),
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

    // Resolve which suites to run
    let all_suites = [SuiteName::Connect, SuiteName::Ping, SuiteName::Publish, SuiteName::Subscribe, SuiteName::Session, SuiteName::Malformed, SuiteName::Disconnect];
    let suites_to_run = args.suite.as_deref().unwrap_or(&all_suites);

    println!("Testing broker at {} (timeout: {}ms)", args.broker, args.timeout_ms);
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
    let report = tests::run_selected(&args.broker, recv_timeout, suites_to_run).await;
    report.print(args.verbose);
}
