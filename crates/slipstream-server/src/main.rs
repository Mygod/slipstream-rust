mod server;
mod streams;
mod target;
mod udp_fallback;

use clap::{parser::ValueSource, CommandFactory, FromArgMatches, Parser};
use server::{run_server, ServerConfig};
use slipstream_core::{
    normalize_domain, parse_host_port, parse_host_port_parts, sip003, AddressKind, HostPort,
};
use tokio::runtime::Builder;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-server",
    about = "slipstream-server - A high-performance covert channel over DNS (server)"
)]
struct Args {
    #[arg(long = "dns-listen-host", default_value = "::")]
    dns_listen_host: String,
    #[arg(long = "dns-listen-port", short = 'l', default_value_t = 53)]
    dns_listen_port: u16,
    #[arg(
        long = "target-address",
        short = 'a',
        default_value = "127.0.0.1:5201",
        value_parser = parse_target_address
    )]
    target_address: HostPort,
    #[arg(long = "fallback", value_name = "HOST:PORT", value_parser = parse_fallback_address)]
    fallback: Option<HostPort>,
    #[arg(long = "cert", short = 'c', value_name = "PATH")]
    cert: Option<String>,
    #[arg(long = "key", short = 'k', value_name = "PATH")]
    key: Option<String>,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domains: Vec<String>,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
    #[arg(long = "debug-commands")]
    debug_commands: bool,
}

fn main() {
    init_logging();
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    let sip003_env = sip003::read_sip003_env().unwrap_or_else(|err| {
        tracing::error!("SIP003 env error: {}", err);
        std::process::exit(2);
    });
    if sip003_env.is_present() {
        tracing::info!("SIP003 env detected; applying SS_* overrides with CLI precedence");
    }

    let sip003_remote = if !cli_provided(&matches, "dns_listen_host")
        && !cli_provided(&matches, "dns_listen_port")
    {
        sip003::parse_endpoint(
            sip003_env.remote_host.as_deref(),
            sip003_env.remote_port.as_deref(),
            "SS_REMOTE",
        )
        .unwrap_or_else(|err| {
            tracing::error!("SIP003 env error: {}", err);
            std::process::exit(2);
        })
    } else {
        None
    };
    let dns_listen_host = if cli_provided(&matches, "dns_listen_host") {
        args.dns_listen_host.clone()
    } else if let Some(endpoint) = &sip003_remote {
        endpoint.host.clone()
    } else {
        args.dns_listen_host.clone()
    };
    let dns_listen_port = if cli_provided(&matches, "dns_listen_port") {
        args.dns_listen_port
    } else if let Some(endpoint) = &sip003_remote {
        endpoint.port
    } else {
        args.dns_listen_port
    };

    let sip003_local = if cli_provided(&matches, "target_address") {
        None
    } else {
        sip003::parse_endpoint(
            sip003_env.local_host.as_deref(),
            sip003_env.local_port.as_deref(),
            "SS_LOCAL",
        )
        .unwrap_or_else(|err| {
            tracing::error!("SIP003 env error: {}", err);
            std::process::exit(2);
        })
    };
    let target_address = if let Some(endpoint) = &sip003_local {
        parse_host_port_parts(&endpoint.host, endpoint.port, AddressKind::Target).unwrap_or_else(
            |err| {
                tracing::error!("SIP003 env error: {}", err);
                std::process::exit(2);
            },
        )
    } else {
        args.target_address.clone()
    };
    let fallback_address = if cli_provided(&matches, "fallback") {
        args.fallback.clone()
    } else {
        last_option_value(&sip003_env.plugin_options, "fallback").map(|value| {
            parse_fallback_address(&value).unwrap_or_else(|err| {
                tracing::error!("SIP003 env error: {}", err);
                std::process::exit(2);
            })
        })
    };

    let domains = if !args.domains.is_empty() {
        args.domains.clone()
    } else {
        let option_domains =
            parse_domains_from_options(&sip003_env.plugin_options).unwrap_or_else(|err| {
                tracing::error!("SIP003 env error: {}", err);
                std::process::exit(2);
            });
        if option_domains.is_empty() {
            tracing::error!("At least one domain is required");
            std::process::exit(2);
        }
        option_domains
    };

    let cert = if let Some(cert) = args.cert.clone() {
        cert
    } else if let Some(cert) = last_option_value(&sip003_env.plugin_options, "cert") {
        cert
    } else {
        tracing::error!("A certificate path is required");
        std::process::exit(2);
    };

    let key = if let Some(key) = args.key.clone() {
        key
    } else if let Some(key) = last_option_value(&sip003_env.plugin_options, "key") {
        key
    } else {
        tracing::error!("A key path is required");
        std::process::exit(2);
    };

    let config = ServerConfig {
        dns_listen_host,
        dns_listen_port,
        target_address,
        fallback_address,
        cert,
        key,
        domains,
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

fn parse_fallback_address(input: &str) -> Result<HostPort, String> {
    let parsed = parse_host_port(input, 0, AddressKind::Fallback).map_err(|err| err.to_string())?;
    if parsed.port == 0 {
        return Err("fallback address must include a port".to_string());
    }
    Ok(parsed)
}

fn cli_provided(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn parse_domains_from_options(options: &[sip003::Sip003Option]) -> Result<Vec<String>, String> {
    let mut domains = None;
    for option in options {
        if option.key == "domain" {
            if domains.is_some() {
                return Err("SIP003 domain option must not be repeated".to_string());
            }
            let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
            let mut parsed = Vec::new();
            for entry in entries {
                let normalized = normalize_domain(&entry).map_err(|err| err.to_string())?;
                parsed.push(normalized);
            }
            domains = Some(parsed);
        }
    }
    Ok(domains.unwrap_or_default())
}

fn last_option_value(options: &[sip003::Sip003Option], key: &str) -> Option<String> {
    let mut last = None;
    for option in options {
        if option.key == key {
            last = Some(option.value.trim().to_string());
        }
    }
    last
}
