use slipstream_ffi::picoquic::picoquic_quic_t;
use slipstream_ffi::socket_addr_to_storage;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub(crate) const MAX_UDP_PACKET_SIZE: usize = 65535;
const FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const FALLBACK_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const NON_DNS_STREAK_THRESHOLD: usize = 16;

struct FallbackSession {
    socket: Arc<TokioUdpSocket>,
    last_seen: Arc<Mutex<Instant>>,
    shutdown_tx: watch::Sender<bool>,
    reply_task: JoinHandle<()>,
}

struct DnsPeerState {
    last_seen: Instant,
    non_dns_streak: usize,
}

pub(crate) struct PacketContext<'a> {
    pub(crate) domains: &'a [&'a str],
    pub(crate) quic: *mut picoquic_quic_t,
    pub(crate) current_time: u64,
    pub(crate) local_addr_storage: &'a libc::sockaddr_storage,
}

/// Tracks per-peer routing for UDP fallback based on DNS decoding outcomes.
///
/// The first packet sets the initial classification:
/// - Packets that decode as DNS (including DNS error replies we generate) mark the peer as DNS-only.
/// - Packets that fail DNS decoding are forwarded to fallback and create a fallback session.
///
/// For DNS-only peers, a streak of non-DNS packets can switch the peer to fallback once it
/// reaches the non-DNS streak threshold. Classification is per source address and expires after
/// idle timeout.
pub(crate) struct FallbackManager {
    fallback_addr: SocketAddr,
    main_socket: Arc<TokioUdpSocket>,
    map_ipv4_peers: bool,
    dns_peers: HashMap<SocketAddr, DnsPeerState>,
    sessions: HashMap<SocketAddr, FallbackSession>,
    last_cleanup: Instant,
}

mod decode;
mod forwarding;
mod session;

pub(crate) use decode::handle_packet;

fn dummy_sockaddr_storage() -> libc::sockaddr_storage {
    socket_addr_to_storage(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        12345,
    ))
}

#[cfg(test)]
mod tests;
