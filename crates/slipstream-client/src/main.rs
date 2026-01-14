mod client;
mod dns;
mod pacing;
mod pinning;
mod streams;

use clap::Parser;
use slipstream_core::{normalize_domain, parse_host_port, AddressKind, HostPort};
use slipstream_ffi::ClientConfig;
use tokio::runtime::Builder;
use tracing_subscriber::EnvFilter;

use client::run_client;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - A high-performance covert channel over DNS (client)"
)]
struct Args {
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,
    #[arg(long = "resolver", short = 'r', value_parser = parse_resolver, required = true)]
    resolver: Vec<HostPort>,
    #[arg(
        long = "congestion-control",
        short = 'c',
        value_parser = ["bbr", "dcubic"]
    )]
    congestion_control: Option<String>,
    #[arg(long = "authoritative")]
    authoritative: bool,
    #[arg(
        short = 'g',
        long = "gso",
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true"
    )]
    gso: bool,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domain: String,
    #[arg(
        long = "max-qname-len",
        value_name = "LEN",
        default_value_t = 253,
        value_parser = parse_max_qname_len
    )]
    max_qname_len: usize,
    #[arg(long = "cert", value_name = "PATH")]
    cert: Option<String>,
    #[arg(long = "keep-alive-interval", short = 't', default_value_t = 400)]
    keep_alive_interval: u16,
    #[arg(long = "debug-poll")]
    debug_poll: bool,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
}

fn main() {
    init_logging();
    let args = Args::parse();

    let congestion_control = args.congestion_control.unwrap_or_else(|| {
        if args.authoritative {
            "bbr".to_string()
        } else {
            "dcubic".to_string()
        }
    });

    let config = ClientConfig {
        tcp_listen_port: args.tcp_listen_port,
        resolvers: &args.resolver,
        congestion_control: &congestion_control,
        authoritative: args.authoritative,
        gso: args.gso,
        domain: &args.domain,
        max_qname_len: args.max_qname_len,
        cert: args.cert.as_deref(),
        keep_alive_interval: args.keep_alive_interval as usize,
        debug_poll: args.debug_poll,
        debug_streams: args.debug_streams,
    };

    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to build Tokio runtime");
    match runtime.block_on(run_client(&config)) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            tracing::error!("Client error: {}", err);
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

fn parse_resolver(input: &str) -> Result<HostPort, String> {
    parse_host_port(input, 53, AddressKind::Resolver).map_err(|err| err.to_string())
}

fn parse_max_qname_len(input: &str) -> Result<usize, String> {
    let value: usize = input
        .parse()
        .map_err(|_| "Max QNAME length must be a positive integer".to_string())?;
    if !(1..=253).contains(&value) {
        return Err("Max QNAME length must be between 1 and 253".to_string());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn max_qname_len_defaults_to_253() {
        let args = Args::try_parse_from([
            "slipstream-client",
            "--resolver",
            "1.1.1.1",
            "--domain",
            "example.com",
        ])
        .expect("parse args");
        assert_eq!(args.max_qname_len, 253);
    }

    #[test]
    fn max_qname_len_rejects_out_of_range() {
        let result = Args::try_parse_from([
            "slipstream-client",
            "--resolver",
            "1.1.1.1",
            "--domain",
            "example.com",
            "--max-qname-len",
            "254",
        ]);
        assert!(result.is_err());
    }
}
