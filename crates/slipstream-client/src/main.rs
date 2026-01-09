mod client;

use clap::Parser;
use slipstream_core::{normalize_domain, parse_resolver_addresses};
use slipstream_ffi::ClientConfig;
use tokio::runtime::Builder;

use client::run_client;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - A high-performance covert channel over DNS (client)"
)]
struct Args {
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,
    #[arg(long = "resolver", short = 'r', action = clap::ArgAction::Append)]
    resolver: Vec<String>,
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
    #[arg(long = "domain", short = 'd')]
    domain: Option<String>,
    #[arg(long = "keep-alive-interval", short = 't', default_value_t = 400)]
    keep_alive_interval: u16,
    #[arg(long = "debug-poll")]
    debug_poll: bool,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
}

fn main() {
    let args = Args::parse();

    let domain = match args.domain {
        Some(domain) if !domain.trim().is_empty() => domain,
        _ => {
            eprintln!("Client error: Missing required --domain option");
            std::process::exit(1);
        }
    };

    if args.resolver.is_empty() {
        eprintln!("Client error: Missing required --resolver option (at least one required)");
        std::process::exit(1);
    }

    let domain = match normalize_domain(&domain) {
        Ok(domain) => domain,
        Err(err) => {
            eprintln!("Client error: {}", err);
            std::process::exit(1);
        }
    };

    let resolver_addresses = match parse_resolver_addresses(&args.resolver) {
        Ok(addrs) => addrs,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    let congestion_control = args.congestion_control.unwrap_or_else(|| {
        if args.authoritative {
            "bbr".to_string()
        } else {
            "dcubic".to_string()
        }
    });

    let config = ClientConfig {
        tcp_listen_port: args.tcp_listen_port,
        resolvers: &resolver_addresses,
        congestion_control: &congestion_control,
        authoritative: args.authoritative,
        gso: args.gso,
        domain: &domain,
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
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }
}
