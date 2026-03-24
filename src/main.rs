mod client;
mod codec;
mod report;
mod tests;
mod types;

use std::io::IsTerminal;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use indicatif::{MultiProgress, ProgressDrawTarget};
use report::ReportOrder;
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SuiteName {
    Transport,
    Connect,
    Ping,
    Publish,
    Subscribe,
    Session,
    Malformed,
    Disconnect,
    RequestResponse,
    Auth,
    #[value(name = "websocket")]
    WebSocket,
}

impl std::fmt::Display for SuiteName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => write!(f, "transport"),
            Self::Connect => write!(f, "connect"),
            Self::Ping => write!(f, "ping"),
            Self::Publish => write!(f, "publish"),
            Self::Subscribe => write!(f, "subscribe"),
            Self::Session => write!(f, "session"),
            Self::Malformed => write!(f, "malformed"),
            Self::Disconnect => write!(f, "disconnect"),
            Self::RequestResponse => write!(f, "request-response"),
            Self::Auth => write!(f, "auth"),
            Self::WebSocket => write!(f, "websocket"),
        }
    }
}

#[derive(Parser)]
#[command(name = "mqtt_test", about = "MQTT v5 broker compliance tester")]
struct Args {
    /// Broker hostname or IP address
    #[arg(default_value = "127.0.0.1")]
    host: String,

    /// TCP port for MQTT
    #[arg(long, default_value_t = 1883)]
    tcp_port: u16,

    /// TLS port for MQTT (default: 8883)
    #[arg(long, default_value_t = 8883)]
    tls_port: u16,

    /// Skip TLS tests entirely
    #[arg(long)]
    no_tls: bool,

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

    /// Run only specific suites (comma-separated: transport,connect,ping,publish,...)
    #[arg(short, long, value_delimiter = ',')]
    suite: Option<Vec<SuiteName>>,

    /// Report ordering: "suite" (default) groups by test suite, "requirement" sorts by spec section
    #[arg(long, default_value = "suite")]
    order: ReportOrder,

    /// Path to CA certificate PEM file for TLS verification (omit for insecure)
    #[arg(long)]
    ca_cert: Option<std::path::PathBuf>,

    /// WebSocket port for MQTT (default: 8083)
    #[arg(long, default_value_t = 8083)]
    ws_port: u16,

    /// Skip WebSocket transport tests
    #[arg(long)]
    no_ws: bool,
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
    let tcp_addr = format!("{}:{}", args.host, args.tcp_port);

    // Determine whether to run TLS tests.
    // By default we probe :8883 and skip gracefully if unreachable.
    // --no-tls disables TLS entirely. Explicit --tls-port makes failure fatal.
    let tls_port_is_explicit = std::env::args().any(|a| a.starts_with("--tls-port"));
    let (tls_addr, tls_config) = if args.no_tls {
        (None, None)
    } else {
        let addr = format!("{}:{}", args.host, args.tls_port);

        // Preflight TLS probe
        let tls_reachable = matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect(&addr),
            )
            .await,
            Ok(Ok(_))
        );

        if !tls_reachable {
            if tls_port_is_explicit {
                eprintln!("Error: cannot connect to TLS endpoint at {addr}");
                std::process::exit(1);
            }
            // Default port, not reachable — skip TLS gracefully
            (None, None)
        } else {
            // No --ca-cert means insecure mode
            let insecure = args.ca_cert.is_none();
            let config = client::TlsConfig::build(args.ca_cert.as_deref(), insecure, &args.host)
                .expect("failed to build TLS configuration");
            (Some(addr), Some(config))
        }
    };

    // Determine whether to run WebSocket tests.
    let ws_port_is_explicit = std::env::args().any(|a| a.starts_with("--ws-port"));
    let ws_addr = if args.no_ws {
        None
    } else {
        let addr = format!("{}:{}", args.host, args.ws_port);

        let ws_reachable = matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect(&addr),
            )
            .await,
            Ok(Ok(_))
        );

        if !ws_reachable {
            if ws_port_is_explicit {
                eprintln!("Error: cannot connect to WebSocket endpoint at {addr}");
                std::process::exit(1);
            }
            None
        } else {
            Some(addr)
        }
    };

    // Resolve which suites to run
    let all_suites = vec![
        SuiteName::Transport,
        SuiteName::Connect,
        SuiteName::Ping,
        SuiteName::Publish,
        SuiteName::Subscribe,
        SuiteName::Session,
        SuiteName::Malformed,
        SuiteName::Disconnect,
        SuiteName::RequestResponse,
        SuiteName::Auth,
        SuiteName::WebSocket,
    ];
    let suites_to_run = args.suite.as_deref().unwrap_or(&all_suites);

    println!(
        "Testing broker at {tcp_addr} (timeout: {}ms)",
        args.timeout_ms
    );
    if let Some(ref addr) = tls_addr {
        println!("TLS endpoint at {addr}");
    } else if !args.no_tls {
        println!("TLS endpoint not reachable, skipping TLS transport test");
    }
    if let Some(ref addr) = ws_addr {
        println!("WebSocket endpoint at {addr}");
    } else if !args.no_ws {
        println!("WebSocket endpoint not reachable, skipping WebSocket tests");
    }
    println!(
        "Suites: {}\n",
        suites_to_run
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Set up progress bars — hide when debug logging is active or stdout is not a TTY.
    let mp = MultiProgress::new();
    let show_progress = !args.debug && !args.trace && std::io::stderr().is_terminal();
    if !show_progress {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }

    let tls_info = tls_addr.as_deref().zip(tls_config.as_ref());
    let ws_info = ws_addr.as_deref().map(|addr| (addr, args.host.as_str()));
    let config = types::TestConfig {
        addr: &tcp_addr,
        recv_timeout,
        tls_info,
        ws_info,
    };
    let start = std::time::Instant::now();
    let report = tests::run_selected(config, suites_to_run, &mp).await;
    let elapsed = start.elapsed();

    println!();
    report.print(args.verbose, args.order, elapsed);
}
