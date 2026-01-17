mod client;
mod dns;
mod pacing;
mod pinning;
mod streams;

use clap::{ArgGroup, CommandFactory, FromArgMatches, Parser};
use slipstream_core::{normalize_domain, parse_host_port, AddressKind, HostPort};
use slipstream_ffi::{ClientConfig, ResolverMode, ResolverSpec};
use tokio::runtime::Builder;
use tracing_subscriber::EnvFilter;

use client::run_client;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - A high-performance covert channel over DNS (client)",
    group(
        ArgGroup::new("resolvers")
            .required(true)
            .multiple(true)
            .args(["resolver", "authoritative"])
    )
)]
struct Args {
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,
    #[arg(long = "resolver", short = 'r', value_parser = parse_resolver)]
    resolver: Vec<HostPort>,
    #[arg(
        long = "congestion-control",
        short = 'c',
        value_parser = ["bbr", "dcubic"]
    )]
    congestion_control: Option<String>,
    #[arg(long = "authoritative", value_parser = parse_resolver)]
    authoritative: Vec<HostPort>,
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
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    let resolvers = build_resolvers(&matches).unwrap_or_else(|err| {
        tracing::error!("Resolver error: {}", err);
        std::process::exit(2);
    });

    let config = ClientConfig {
        tcp_listen_port: args.tcp_listen_port,
        resolvers: &resolvers,
        congestion_control: args.congestion_control.as_deref(),
        gso: args.gso,
        domain: &args.domain,
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

fn build_resolvers(matches: &clap::ArgMatches) -> Result<Vec<ResolverSpec>, String> {
    let mut ordered = Vec::new();
    collect_resolvers(matches, "resolver", ResolverMode::Recursive, &mut ordered)?;
    collect_resolvers(
        matches,
        "authoritative",
        ResolverMode::Authoritative,
        &mut ordered,
    )?;
    if ordered.is_empty() {
        return Err("At least one resolver is required".to_string());
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    Ok(ordered.into_iter().map(|(_, spec)| spec).collect())
}

fn collect_resolvers(
    matches: &clap::ArgMatches,
    name: &str,
    mode: ResolverMode,
    ordered: &mut Vec<(usize, ResolverSpec)>,
) -> Result<(), String> {
    let indices: Vec<usize> = matches.indices_of(name).into_iter().flatten().collect();
    let values: Vec<HostPort> = matches
        .get_many::<HostPort>(name)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if indices.len() != values.len() {
        return Err(format!("Mismatched {} arguments", name));
    }
    for (idx, resolver) in indices.into_iter().zip(values) {
        ordered.push((idx, ResolverSpec { resolver, mode }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_ordered_resolvers() {
        let matches = Args::command()
            .try_get_matches_from([
                "slipstream-client",
                "--domain",
                "example.com",
                "--resolver",
                "1.1.1.1",
                "--authoritative",
                "2.2.2.2",
                "--resolver",
                "3.3.3.3:5353",
            ])
            .expect("matches should parse");
        let resolvers = build_resolvers(&matches).expect("resolvers should parse");
        assert_eq!(resolvers.len(), 3);
        assert_eq!(resolvers[0].resolver.host, "1.1.1.1");
        assert_eq!(resolvers[0].resolver.port, 53);
        assert_eq!(resolvers[0].mode, ResolverMode::Recursive);
        assert_eq!(resolvers[1].resolver.host, "2.2.2.2");
        assert_eq!(resolvers[1].mode, ResolverMode::Authoritative);
        assert_eq!(resolvers[2].resolver.host, "3.3.3.3");
        assert_eq!(resolvers[2].resolver.port, 5353);
    }

    #[test]
    fn maps_authoritative_first() {
        let matches = Args::command()
            .try_get_matches_from([
                "slipstream-client",
                "--domain",
                "example.com",
                "--authoritative",
                "8.8.8.8",
                "--resolver",
                "9.9.9.9",
            ])
            .expect("matches should parse");
        let resolvers = build_resolvers(&matches).expect("resolvers should parse");
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].resolver.host, "8.8.8.8");
        assert_eq!(resolvers[0].mode, ResolverMode::Authoritative);
        assert_eq!(resolvers[1].resolver.host, "9.9.9.9");
        assert_eq!(resolvers[1].mode, ResolverMode::Recursive);
    }
}
