use slipstream_core::{net::is_transient_udp_error, resolve_host_port, HostPort};
use slipstream_dns::{
    decode_query_with_domains, encode_response, DecodeQueryError, Question, Rcode, ResponseParams,
};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_create, picoquic_current_time, picoquic_incoming_packet_ex,
    picoquic_prepare_packet_ex, picoquic_quic_t, slipstream_disable_ack_delay,
    slipstream_server_cc_algorithm, PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX,
};
use slipstream_ffi::{configure_quic_with_custom, socket_addr_to_storage, QuicGuard};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::ffi::CString;
use std::fmt;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{lookup_host, UdpSocket as TokioUdpSocket};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::streams::{
    drain_commands, handle_command, handle_shutdown, maybe_report_command_stats, server_callback,
    ServerState,
};

// Protocol defaults; see docs/config.md for details.
const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const DNS_MAX_QUERY_SIZE: usize = 512;
const IDLE_SLEEP_MS: u64 = 10;
// Default QUIC MTU for server packets; see docs/config.md for details.
const QUIC_MTU: u32 = 900;
pub(crate) const STREAM_READ_CHUNK_BYTES: usize = 4096;
pub(crate) const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
pub(crate) const TARGET_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;

static SHOULD_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_signum: libc::c_int) {
    SHOULD_SHUTDOWN.store(true, Ordering::Relaxed);
}

#[derive(Debug)]
pub struct ServerError {
    message: String,
}

impl ServerError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ServerError {}

pub struct ServerConfig {
    pub dns_listen_host: String,
    pub dns_listen_port: u16,
    pub target_address: HostPort,
    pub cert: String,
    pub key: String,
    pub domains: Vec<String>,
    pub debug_streams: bool,
    pub debug_commands: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StreamKey {
    pub(crate) cnx: usize,
    pub(crate) stream_id: u64,
}

pub(crate) enum StreamWrite {
    Data(Vec<u8>),
    Fin,
}

#[allow(clippy::enum_variant_names)]
pub(crate) enum Command {
    StreamConnected {
        cnx_id: usize,
        stream_id: u64,
        write_tx: mpsc::UnboundedSender<StreamWrite>,
        data_rx: mpsc::Receiver<Vec<u8>>,
        send_pending: Arc<AtomicBool>,
    },
    StreamConnectError {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamClosed {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamReadable {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamReadError {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamWriteError {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamWriteDrained {
        cnx_id: usize,
        stream_id: u64,
        bytes: usize,
    },
}

struct Slot {
    peer: SocketAddr,
    id: u16,
    rd: bool,
    cd: bool,
    question: Question,
    rcode: Option<Rcode>,
    cnx: *mut picoquic_cnx_t,
    path_id: libc::c_int,
}

pub async fn run_server(config: &ServerConfig) -> Result<i32, ServerError> {
    let target_addr = resolve_host_port(&config.target_address)
        .map_err(|err| ServerError::new(err.to_string()))?;

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ServerError::new("ALPN contains an unexpected null byte"))?;
    let cert = CString::new(config.cert.clone())
        .map_err(|_| ServerError::new("Cert path contains an unexpected null byte"))?;
    let key = CString::new(config.key.clone())
        .map_err(|_| ServerError::new("Key path contains an unexpected null byte"))?;
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let debug_streams = config.debug_streams;
    let debug_commands = config.debug_commands;
    let mut state = Box::new(ServerState::new(
        target_addr,
        command_tx,
        debug_streams,
        debug_commands,
    ));
    let state_ptr: *mut ServerState = &mut *state;
    let _state = state;

    let current_time = unsafe { picoquic_current_time() };
    let quic = unsafe {
        picoquic_create(
            8,
            cert.as_ptr(),
            key.as_ptr(),
            std::ptr::null(),
            alpn.as_ptr(),
            Some(server_callback),
            state_ptr as *mut _,
            None,
            std::ptr::null_mut(),
            std::ptr::null(),
            current_time,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if quic.is_null() {
        return Err(ServerError::new("Could not create QUIC context"));
    }
    let _quic_guard = QuicGuard::new(quic);
    unsafe {
        if slipstream_server_cc_algorithm.is_null() {
            return Err(ServerError::new(
                "Slipstream server congestion algorithm is unavailable",
            ));
        }
        configure_quic_with_custom(quic, slipstream_server_cc_algorithm, QUIC_MTU);
    }

    let udp = bind_udp_socket(&config.dns_listen_host, config.dns_listen_port).await?;
    let udp_local_addr = udp.local_addr().map_err(map_io)?;
    let map_ipv4_peers = matches!(udp_local_addr, SocketAddr::V6(_));
    let local_addr_storage = socket_addr_to_storage(udp_local_addr);
    warn_overlapping_domains(&config.domains);
    let domains: Vec<&str> = config.domains.iter().map(String::as_str).collect();
    if domains.is_empty() {
        return Err(ServerError::new("At least one domain must be configured"));
    }

    unsafe {
        libc::signal(libc::SIGTERM, handle_sigterm as usize);
    }

    let mut recv_buf = vec![0u8; DNS_MAX_QUERY_SIZE];
    let mut send_buf = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];

    loop {
        drain_commands(state_ptr, &mut command_rx);

        if SHOULD_SHUTDOWN.load(Ordering::Relaxed) {
            let state = unsafe { &mut *state_ptr };
            if handle_shutdown(quic, state) {
                break;
            }
        }

        let mut slots = Vec::new();

        tokio::select! {
            command = command_rx.recv() => {
                if let Some(command) = command {
                    handle_command(state_ptr, command);
                }
            }
            recv = udp.recv_from(&mut recv_buf) => {
                match recv {
                    Ok((size, peer)) => {
                        let loop_time = unsafe { picoquic_current_time() };
                        if let Some(slot) = decode_slot(
                            &recv_buf[..size],
                            peer,
                            &domains,
                            quic,
                            loop_time,
                            &local_addr_storage,
                        )? {
                            slots.push(slot);
                        }
                        for _ in 1..PICOQUIC_PACKET_LOOP_RECV_MAX {
                            match udp.try_recv_from(&mut recv_buf) {
                                Ok((size, peer)) => {
                                    if let Some(slot) = decode_slot(
                                        &recv_buf[..size],
                                        peer,
                                        &domains,
                                        quic,
                                        loop_time,
                                        &local_addr_storage,
                                    )? {
                                        slots.push(slot);
                                    }
                                }
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                                Err(err) => {
                                    if is_transient_udp_error(&err) {
                                        break;
                                    }
                                    return Err(map_io(err));
                                }
                            }
                        }
                    }
                    Err(err) => {
                        if !is_transient_udp_error(&err) {
                            return Err(map_io(err));
                        }
                    }
                }
            }
            _ = sleep(Duration::from_millis(IDLE_SLEEP_MS)) => {}
        }

        drain_commands(state_ptr, &mut command_rx);
        maybe_report_command_stats(state_ptr);

        if slots.is_empty() {
            continue;
        }

        let loop_time = unsafe { picoquic_current_time() };

        for slot in slots.iter_mut() {
            let mut send_length = 0usize;
            let mut addr_to: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut if_index: libc::c_int = 0;

            if slot.rcode.is_none() && !slot.cnx.is_null() {
                let ret = unsafe {
                    picoquic_prepare_packet_ex(
                        slot.cnx,
                        slot.path_id,
                        loop_time,
                        send_buf.as_mut_ptr(),
                        send_buf.len(),
                        &mut send_length,
                        &mut addr_to,
                        &mut addr_from,
                        &mut if_index,
                        std::ptr::null_mut(),
                    )
                };
                if ret < 0 {
                    return Err(ServerError::new("Failed to prepare QUIC packet"));
                }
            }

            let (payload, rcode) = if send_length > 0 {
                (Some(&send_buf[..send_length]), slot.rcode)
            } else if slot.rcode.is_none() {
                // No QUIC payload ready; still answer the poll with NOERROR and empty payload to clear it.
                (None, Some(slipstream_dns::Rcode::Ok))
            } else {
                (None, slot.rcode)
            };
            let response = encode_response(&ResponseParams {
                id: slot.id,
                rd: slot.rd,
                cd: slot.cd,
                question: &slot.question,
                payload,
                rcode,
            })
            .map_err(|err| ServerError::new(err.to_string()))?;
            let peer = if map_ipv4_peers {
                normalize_dual_stack_addr(slot.peer)
            } else {
                slot.peer
            };
            if let Err(err) = udp.send_to(&response, peer).await {
                if !is_transient_udp_error(&err) {
                    return Err(map_io(err));
                }
            }
        }
    }

    Ok(0)
}

fn decode_slot(
    packet: &[u8],
    peer: SocketAddr,
    domains: &[&str],
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &libc::sockaddr_storage,
) -> Result<Option<Slot>, ServerError> {
    match decode_query_with_domains(packet, domains) {
        Ok(query) => {
            let mut peer_storage = dummy_sockaddr_storage();
            let mut local_storage = unsafe { std::ptr::read(local_addr_storage) };
            let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
            let mut first_path: libc::c_int = -1;
            let ret = unsafe {
                picoquic_incoming_packet_ex(
                    quic,
                    query.payload.as_ptr() as *mut u8,
                    query.payload.len(),
                    &mut peer_storage as *mut _ as *mut libc::sockaddr,
                    &mut local_storage as *mut _ as *mut libc::sockaddr,
                    0,
                    0,
                    &mut first_cnx,
                    &mut first_path,
                    current_time,
                )
            };
            if ret < 0 {
                return Err(ServerError::new("Failed to process QUIC packet"));
            }
            if first_cnx.is_null() {
                return Ok(None);
            }
            unsafe {
                slipstream_disable_ack_delay(first_cnx);
            }
            Ok(Some(Slot {
                peer,
                id: query.id,
                rd: query.rd,
                cd: query.cd,
                question: query.question,
                rcode: None,
                cnx: first_cnx,
                path_id: first_path,
            }))
        }
        Err(DecodeQueryError::Drop) => Ok(None),
        Err(DecodeQueryError::Reply {
            id,
            rd,
            cd,
            question,
            rcode,
        }) => {
            let question = match question {
                Some(question) => question,
                None => return Ok(None),
            };
            Ok(Some(Slot {
                peer,
                id,
                rd,
                cd,
                question,
                rcode: Some(rcode),
                cnx: std::ptr::null_mut(),
                path_id: -1,
            }))
        }
    }
}

async fn bind_udp_socket(host: &str, port: u16) -> Result<TokioUdpSocket, ServerError> {
    let addrs: Vec<SocketAddr> = lookup_host((host, port)).await.map_err(map_io)?.collect();
    if addrs.is_empty() {
        return Err(ServerError::new(format!(
            "No addresses resolved for {}:{}",
            host, port
        )));
    }
    let mut last_err = None;
    for addr in addrs {
        match bind_udp_socket_addr(addr) {
            Ok(socket) => return Ok(socket),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        ServerError::new(format!("Failed to bind UDP socket on {}:{}", host, port))
    }))
}

fn bind_udp_socket_addr(addr: SocketAddr) -> Result<TokioUdpSocket, ServerError> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(map_io)?;
    if let SocketAddr::V6(_) = addr {
        if let Err(err) = socket.set_only_v6(false) {
            tracing::warn!(
                "Failed to enable dual-stack UDP listener on {}: {}",
                addr,
                err
            );
        }
    }
    let sock_addr = SockAddr::from(addr);
    socket.bind(&sock_addr).map_err(map_io)?;
    socket.set_nonblocking(true).map_err(map_io)?;
    let std_socket: std::net::UdpSocket = socket.into();
    TokioUdpSocket::from_std(std_socket).map_err(map_io)
}

fn normalize_dual_stack_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        SocketAddr::V6(v6) => SocketAddr::V6(v6),
    }
}

fn dummy_sockaddr_storage() -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let sockaddr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 12345u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets(),
        },
        sin6_scope_id: 0,
    };
    unsafe {
        std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, sockaddr);
    }
    storage
}

fn map_io(err: std::io::Error) -> ServerError {
    ServerError::new(err.to_string())
}

fn warn_overlapping_domains(domains: &[String]) {
    if domains.len() < 2 {
        return;
    }

    let trimmed: Vec<String> = domains
        .iter()
        .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
        .collect();

    for i in 0..trimmed.len() {
        for j in (i + 1)..trimmed.len() {
            let left = &trimmed[i];
            let right = &trimmed[j];

            if left == right {
                tracing::warn!(
                    "Duplicate domain configured: '{}' and '{}'",
                    domains[i],
                    domains[j]
                );
                continue;
            }

            if is_label_suffix(left, right) || is_label_suffix(right, left) {
                tracing::warn!(
                    "Configured domains overlap; longest suffix wins: '{}' and '{}'",
                    domains[i],
                    domains[j]
                );
            }
        }
    }
}

fn is_label_suffix(domain: &str, suffix: &str) -> bool {
    if domain.len() <= suffix.len() {
        return false;
    }
    if !domain.ends_with(suffix) {
        return false;
    }
    domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
}
