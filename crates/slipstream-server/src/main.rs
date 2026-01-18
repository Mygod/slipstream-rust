mod server;
mod streams;
mod target;

use clap::Parser;
use server::{run_server, ServerConfig};
use slipstream_core::{normalize_domain, parse_host_port, AddressKind, HostPort};
use tokio::runtime::Builder;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-server",
    about = "slipstream-server - A high-performance covert channel over DNS (server)"
)]
struct Args {
    #[arg(long = "dns-listen-port", short = 'l', default_value_t = 53)]
    dns_listen_port: u16,
    #[arg(
        long = "target-address",
        short = 'a',
        default_value = "127.0.0.1:5201",
        value_parser = parse_target_address
    )]
    target_address: HostPort,
    #[arg(long = "cert", short = 'c', value_name = "PATH")]
    cert: String,
    #[arg(long = "key", short = 'k', value_name = "PATH")]
    key: String,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain, required = true)]
    domains: Vec<String>,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
    #[arg(long = "debug-commands")]
    debug_commands: bool,
}

fn main() {
    init_logging();
    let args = Args::parse();

    let config = ServerConfig {
        dns_listen_port: args.dns_listen_port,
        target_address: args.target_address,
        cert: args.cert,
        key: args.key,
        domains: args.domains,
        debug_streams: args.debug_streams,
        debug_commands: args.debug_commands,
    };

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to build Tokio runtime");
    match runtime.block_on(run_server(&config)) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            tracing::error!("Server error: {}", err);
            std::process::exit(1);
        }
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}

fn parse_domain(input: &str) -> Result<String, String> {
    normalize_domain(input).map_err(|err| err.to_string())
}

fn parse_target_address(input: &str) -> Result<HostPort, String> {
    parse_host_port(input, 5201, AddressKind::Target).map_err(|err| err.to_string())
}
