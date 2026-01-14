mod server;

use clap::Parser;
use server::{run_server, ServerConfig};
use slipstream_core::{normalize_domain, parse_host_port, AddressKind};
use slipstream_dns::max_payload_len_for_domain_with_subdomain_limit;
use tokio::runtime::Builder;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-server",
    about = "slipstream-server - A high-performance covert channel over DNS (server)"
)]
struct Args {
    #[arg(long = "dns-listen-port", short = 'l', default_value_t = 53)]
    dns_listen_port: u16,
    #[arg(long = "dns-listen-ipv6", short = '6', default_value_t = false)]
    dns_listen_ipv6: bool,
    #[arg(long = "target-address", short = 'a', default_value = "127.0.0.1:5201")]
    target_address: String,
    #[arg(long = "cert", short = 'c', default_value = ".github/certs/cert.pem")]
    cert: String,
    #[arg(long = "key", short = 'k', default_value = ".github/certs/key.pem")]
    key: String,
    #[arg(long = "domain", short = 'd')]
    domain: Option<String>,
    #[arg(
        long = "max-subdomain-len",
        value_name = "LEN",
        value_parser = clap::value_parser!(usize),
        help = "Maximum dotted subdomain length before the domain suffix"
    )]
    max_subdomain_len: Option<usize>,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
    #[arg(long = "debug-commands")]
    debug_commands: bool,
}

fn main() {
    let args = Args::parse();

    let domain = match args.domain {
        Some(domain) if !domain.trim().is_empty() => domain,
        _ => {
            eprintln!("Server error: Missing required --domain option");
            std::process::exit(1);
        }
    };

    let domain = match normalize_domain(&domain) {
        Ok(domain) => domain,
        Err(err) => {
            eprintln!("Server error: {}", err);
            std::process::exit(1);
        }
    };
    if let Err(err) =
        max_payload_len_for_domain_with_subdomain_limit(&domain, args.max_subdomain_len)
    {
        eprintln!("Server error: {}", err);
        std::process::exit(1);
    }

    let target_address = match parse_host_port(&args.target_address, 5201, AddressKind::Target) {
        Ok(address) => address,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    let config = ServerConfig {
        dns_listen_port: args.dns_listen_port,
        dns_listen_ipv6: args.dns_listen_ipv6,
        target_address,
        cert: args.cert,
        key: args.key,
        domain,
        max_subdomain_len: args.max_subdomain_len,
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
            eprintln!("Server error: {}", err);
            std::process::exit(1);
        }
    }
}
