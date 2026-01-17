use crate::client::ClientError;
use crate::pacing::{PacingBudgetSnapshot, PacingPollBudget};
use slipstream_core::resolve_host_port;
use slipstream_dns::{build_qname, decode_response, encode_query, QueryParams, CLASS_IN, RR_TXT};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_current_time, picoquic_get_path_addr, picoquic_incoming_packet_ex,
    picoquic_prepare_packet_ex, picoquic_probe_new_path_ex, picoquic_quic_t,
    slipstream_find_path_id_by_addr, slipstream_get_path_id_from_unique, slipstream_request_poll,
    slipstream_set_default_path_mode, PICOQUIC_PACKET_LOOP_RECV_MAX,
};
use slipstream_ffi::{socket_addr_to_storage, ClientConfig, ResolverMode, ResolverSpec};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV6};
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::{debug, info, warn};

const PATH_PROBE_INITIAL_DELAY_US: u64 = 250_000;
const PATH_PROBE_MAX_DELAY_US: u64 = 10_000_000;
const DEBUG_REPORT_INTERVAL_US: u64 = 1_000_000;
const MAX_POLL_BURST: usize = PICOQUIC_PACKET_LOOP_RECV_MAX;
const AUTHORITATIVE_POLL_TIMEOUT_US: u64 = 5_000_000;

pub(crate) struct ResolverState {
    pub(crate) addr: SocketAddr,
    pub(crate) storage: libc::sockaddr_storage,
    pub(crate) local_addr_storage: Option<libc::sockaddr_storage>,
    pub(crate) mode: ResolverMode,
    pub(crate) added: bool,
    pub(crate) path_id: libc::c_int,
    pub(crate) unique_path_id: Option<u64>,
    pub(crate) probe_attempts: u32,
    pub(crate) next_probe_at: u64,
    pub(crate) pending_polls: usize,
    pub(crate) inflight_poll_ids: HashMap<u16, u64>,
    pub(crate) pacing_budget: Option<PacingPollBudget>,
    pub(crate) last_pacing_snapshot: Option<PacingBudgetSnapshot>,
    pub(crate) debug: DebugMetrics,
}

impl ResolverState {
    pub(crate) fn label(&self) -> String {
        format!(
            "path_id={} unique_id={:?} resolver={} mode={:?}",
            self.path_id, self.unique_path_id, self.addr, self.mode
        )
    }
}

pub(crate) struct DebugMetrics {
    pub(crate) enabled: bool,
    pub(crate) last_report_at: u64,
    pub(crate) dns_responses: u64,
    pub(crate) zero_send_loops: u64,
    pub(crate) zero_send_with_streams: u64,
    pub(crate) enqueued_bytes: u64,
    pub(crate) send_packets: u64,
    pub(crate) send_bytes: u64,
    pub(crate) polls_sent: u64,
    pub(crate) last_enqueue_at: u64,
    pub(crate) last_report_dns: u64,
    pub(crate) last_report_zero: u64,
    pub(crate) last_report_zero_streams: u64,
    pub(crate) last_report_enqueued: u64,
    pub(crate) last_report_send_packets: u64,
    pub(crate) last_report_send_bytes: u64,
    pub(crate) last_report_polls: u64,
}

impl DebugMetrics {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_report_at: 0,
            dns_responses: 0,
            zero_send_loops: 0,
            zero_send_with_streams: 0,
            enqueued_bytes: 0,
            send_packets: 0,
            send_bytes: 0,
            polls_sent: 0,
            last_enqueue_at: 0,
            last_report_dns: 0,
            last_report_zero: 0,
            last_report_zero_streams: 0,
            last_report_enqueued: 0,
            last_report_send_packets: 0,
            last_report_send_bytes: 0,
            last_report_polls: 0,
        }
    }
}

pub(crate) struct DnsResponseContext<'a> {
    pub(crate) quic: *mut picoquic_quic_t,
    pub(crate) local_addr_storage: &'a libc::sockaddr_storage,
    pub(crate) resolvers: &'a mut [ResolverState],
}

pub(crate) fn resolve_resolvers(
    resolvers: &[ResolverSpec],
    mtu: u32,
    debug_poll: bool,
) -> Result<Vec<ResolverState>, ClientError> {
    let mut resolved = Vec::with_capacity(resolvers.len());
    let mut seen = HashMap::new();
    for (idx, resolver) in resolvers.iter().enumerate() {
        let addr = resolve_host_port(&resolver.resolver)
            .map_err(|err| ClientError::new(err.to_string()))?;
        let addr = normalize_dual_stack_addr(addr);
        if let Some(existing_mode) = seen.get(&addr) {
            return Err(ClientError::new(format!(
                "Duplicate resolver address {} (modes: {:?} and {:?})",
                addr, existing_mode, resolver.mode
            )));
        }
        seen.insert(addr, resolver.mode);
        let is_primary = idx == 0;
        resolved.push(ResolverState {
            addr,
            storage: socket_addr_to_storage(addr),
            local_addr_storage: None,
            mode: resolver.mode,
            added: is_primary,
            path_id: if is_primary { 0 } else { -1 },
            unique_path_id: if is_primary { Some(0) } else { None },
            probe_attempts: 0,
            next_probe_at: 0,
            pending_polls: 0,
            inflight_poll_ids: HashMap::new(),
            pacing_budget: match resolver.mode {
                ResolverMode::Authoritative => Some(PacingPollBudget::new(mtu)),
                ResolverMode::Recursive => None,
            },
            last_pacing_snapshot: None,
            debug: DebugMetrics::new(debug_poll),
        });
    }
    Ok(resolved)
}

pub(crate) fn refresh_resolver_path(
    cnx: *mut picoquic_cnx_t,
    resolver: &mut ResolverState,
) -> bool {
    if let Some(unique_path_id) = resolver.unique_path_id {
        let path_id = unsafe { slipstream_get_path_id_from_unique(cnx, unique_path_id) };
        if path_id >= 0 {
            resolver.added = true;
            if resolver.path_id != path_id {
                resolver.path_id = path_id;
            }
            return true;
        }
        resolver.unique_path_id = None;
    }
    let peer = &resolver.storage as *const _ as *const libc::sockaddr;
    let path_id = unsafe { slipstream_find_path_id_by_addr(cnx, peer) };
    if path_id < 0 {
        if resolver.added || resolver.path_id >= 0 {
            reset_resolver_path(resolver);
        }
        return false;
    }

    resolver.added = true;
    if resolver.path_id != path_id {
        resolver.path_id = path_id;
    }
    true
}

pub(crate) fn reset_resolver_path(resolver: &mut ResolverState) {
    warn!(
        "Path for resolver {} became unavailable; resetting state",
        resolver.addr
    );
    resolver.added = false;
    resolver.path_id = -1;
    resolver.unique_path_id = None;
    resolver.local_addr_storage = None;
    resolver.pending_polls = 0;
    resolver.inflight_poll_ids.clear();
    resolver.last_pacing_snapshot = None;
    resolver.probe_attempts = 0;
    resolver.next_probe_at = 0;
}

pub(crate) fn normalize_dual_stack_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        SocketAddr::V6(v6) => SocketAddr::V6(v6),
    }
}

pub(crate) fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> Result<SocketAddr, ClientError> {
    slipstream_ffi::sockaddr_storage_to_socket_addr(storage).map_err(ClientError::new)
}

pub(crate) fn expire_inflight_polls(inflight_poll_ids: &mut HashMap<u16, u64>, now: u64) {
    if inflight_poll_ids.is_empty() {
        return;
    }
    let expire_before = now.saturating_sub(AUTHORITATIVE_POLL_TIMEOUT_US);
    let mut expired = Vec::new();
    for (id, sent_at) in inflight_poll_ids.iter() {
        if *sent_at <= expire_before {
            expired.push(*id);
        }
    }
    for id in expired {
        inflight_poll_ids.remove(&id);
    }
}

pub(crate) fn handle_dns_response(
    buf: &[u8],
    peer: SocketAddr,
    ctx: &mut DnsResponseContext<'_>,
) -> Result<(), ClientError> {
    let peer = normalize_dual_stack_addr(peer);
    let response_id = dns_response_id(buf);
    if let Some(payload) = decode_response(buf) {
        let resolver_index = ctx
            .resolvers
            .iter()
            .position(|resolver| resolver.addr == peer);
        let mut peer_storage = socket_addr_to_storage(peer);
        let mut local_storage = if let Some(index) = resolver_index {
            ctx.resolvers[index]
                .local_addr_storage
                .as_ref()
                .map(|storage| unsafe { std::ptr::read(storage) })
                .unwrap_or_else(|| unsafe { std::ptr::read(ctx.local_addr_storage) })
        } else {
            unsafe { std::ptr::read(ctx.local_addr_storage) }
        };
        let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
        let mut first_path: libc::c_int = -1;
        let current_time = unsafe { picoquic_current_time() };
        let ret = unsafe {
            picoquic_incoming_packet_ex(
                ctx.quic,
                payload.as_ptr() as *mut u8,
                payload.len(),
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
            return Err(ClientError::new("Failed processing inbound QUIC packet"));
        }
        let resolver = if let Some(resolver) = find_resolver_by_path_id(ctx.resolvers, first_path) {
            Some(resolver)
        } else {
            find_resolver_by_addr(ctx.resolvers, peer)
        };
        if let Some(resolver) = resolver {
            if first_path >= 0 && resolver.path_id != first_path {
                resolver.path_id = first_path;
                resolver.added = true;
            }
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if let Some(response_id) = response_id {
                if resolver.mode == ResolverMode::Authoritative {
                    resolver.inflight_poll_ids.remove(&response_id);
                }
            }
            if resolver.mode == ResolverMode::Recursive {
                resolver.pending_polls =
                    resolver.pending_polls.saturating_add(1).min(MAX_POLL_BURST);
            }
        }
    } else if let Some(response_id) = response_id {
        if let Some(resolver) = find_resolver_by_addr(ctx.resolvers, peer) {
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if resolver.mode == ResolverMode::Authoritative {
                resolver.inflight_poll_ids.remove(&response_id);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_poll_queries(
    cnx: *mut picoquic_cnx_t,
    udp: &TokioUdpSocket,
    config: &ClientConfig<'_>,
    local_addr_storage: &mut libc::sockaddr_storage,
    dns_id: &mut u16,
    resolver: &mut ResolverState,
    remaining: &mut usize,
    send_buf: &mut [u8],
) -> Result<(), ClientError> {
    if !refresh_resolver_path(cnx, resolver) {
        return Ok(());
    }
    let mut remaining_count = *remaining;
    *remaining = 0;

    while remaining_count > 0 {
        let current_time = unsafe { picoquic_current_time() };
        unsafe {
            slipstream_request_poll(cnx);
        }

        let mut send_length: libc::size_t = 0;
        let mut addr_to: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addr_from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut if_index: libc::c_int = 0;
        let ret = unsafe {
            picoquic_prepare_packet_ex(
                cnx,
                resolver.path_id,
                current_time,
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
            return Err(ClientError::new("Failed preparing poll packet"));
        }
        if send_length == 0 || addr_to.ss_family == 0 {
            *remaining = remaining_count;
            break;
        }

        remaining_count -= 1;
        *local_addr_storage = addr_from;
        resolver.local_addr_storage = Some(unsafe { std::ptr::read(local_addr_storage) });
        resolver.debug.send_packets = resolver.debug.send_packets.saturating_add(1);
        resolver.debug.send_bytes = resolver.debug.send_bytes.saturating_add(send_length as u64);
        resolver.debug.polls_sent = resolver.debug.polls_sent.saturating_add(1);

        let poll_id = *dns_id;
        let qname = build_qname(&send_buf[..send_length], config.domain)
            .map_err(|err| ClientError::new(err.to_string()))?;
        let params = QueryParams {
            id: poll_id,
            qname: &qname,
            qtype: RR_TXT,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        };
        *dns_id = dns_id.wrapping_add(1);
        let packet = encode_query(&params).map_err(|err| ClientError::new(err.to_string()))?;

        let dest = sockaddr_storage_to_socket_addr(&addr_to)?;
        let dest = normalize_dual_stack_addr(dest);
        udp.send_to(&packet, dest)
            .await
            .map_err(|err| ClientError::new(err.to_string()))?;
        if resolver.mode == ResolverMode::Authoritative {
            resolver.inflight_poll_ids.insert(poll_id, current_time);
        }
    }

    Ok(())
}

pub(crate) fn maybe_report_debug(
    resolver: &mut ResolverState,
    now: u64,
    streams_len: usize,
    pending_polls: usize,
    inflight_polls: usize,
    pacing_snapshot: Option<PacingBudgetSnapshot>,
) {
    let label = resolver.label();
    let debug = &mut resolver.debug;
    if !debug.enabled {
        return;
    }
    if debug.last_report_at == 0 {
        debug.last_report_at = now;
        return;
    }
    let elapsed = now.saturating_sub(debug.last_report_at);
    if elapsed < DEBUG_REPORT_INTERVAL_US {
        return;
    }
    let dns_delta = debug.dns_responses.saturating_sub(debug.last_report_dns);
    let zero_delta = debug.zero_send_loops.saturating_sub(debug.last_report_zero);
    let zero_stream_delta = debug
        .zero_send_with_streams
        .saturating_sub(debug.last_report_zero_streams);
    let enq_delta = debug
        .enqueued_bytes
        .saturating_sub(debug.last_report_enqueued);
    let send_pkt_delta = debug
        .send_packets
        .saturating_sub(debug.last_report_send_packets);
    let send_bytes_delta = debug
        .send_bytes
        .saturating_sub(debug.last_report_send_bytes);
    let polls_delta = debug.polls_sent.saturating_sub(debug.last_report_polls);
    let enqueue_ms = if debug.last_enqueue_at == 0 {
        0
    } else {
        now.saturating_sub(debug.last_enqueue_at) / 1_000
    };
    let pacing_summary = if let Some(snapshot) = pacing_snapshot {
        format!(
            " pacing_rate={} qps_target={:.2} target_inflight={} gain={:.2}",
            snapshot.pacing_rate, snapshot.qps, snapshot.target_inflight, snapshot.gain
        )
    } else {
        String::new()
    };
    debug!(
        "debug: {} dns+={} send_pkts+={} send_bytes+={} polls+={} zero_send+={} zero_send_streams+={} streams={} enqueued+={} last_enqueue_ms={} pending_polls={} inflight_polls={}{}",
        label,
        dns_delta,
        send_pkt_delta,
        send_bytes_delta,
        polls_delta,
        zero_delta,
        zero_stream_delta,
        streams_len,
        enq_delta,
        enqueue_ms,
        pending_polls,
        inflight_polls,
        pacing_summary
    );
    debug.last_report_at = now;
    debug.last_report_dns = debug.dns_responses;
    debug.last_report_zero = debug.zero_send_loops;
    debug.last_report_zero_streams = debug.zero_send_with_streams;
    debug.last_report_enqueued = debug.enqueued_bytes;
    debug.last_report_send_packets = debug.send_packets;
    debug.last_report_send_bytes = debug.send_bytes;
    debug.last_report_polls = debug.polls_sent;
}

pub(crate) fn add_paths(
    cnx: *mut picoquic_cnx_t,
    resolvers: &mut [ResolverState],
) -> Result<(), ClientError> {
    if resolvers.len() <= 1 {
        return Ok(());
    }

    let mut local_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let ret = unsafe { picoquic_get_path_addr(cnx, 0, 1, &mut local_storage) };
    if ret != 0 {
        return Ok(());
    }
    let now = unsafe { picoquic_current_time() };
    let primary_mode = resolvers[0].mode;
    let mut default_mode = primary_mode;

    for resolver in resolvers.iter_mut().skip(1) {
        if resolver.added {
            continue;
        }
        if resolver.next_probe_at > now {
            continue;
        }
        if resolver.mode != default_mode {
            unsafe { slipstream_set_default_path_mode(resolver_mode_to_c(resolver.mode)) };
            default_mode = resolver.mode;
        }
        let mut path_id: libc::c_int = -1;
        let ret = unsafe {
            picoquic_probe_new_path_ex(
                cnx,
                &resolver.storage as *const _ as *const libc::sockaddr,
                &local_storage as *const _ as *const libc::sockaddr,
                0,
                now,
                0,
                &mut path_id,
            )
        };
        if ret == 0 && path_id >= 0 {
            resolver.added = true;
            resolver.path_id = path_id;
            info!("Added path {}", resolver.addr);
            continue;
        }
        resolver.probe_attempts = resolver.probe_attempts.saturating_add(1);
        let delay = path_probe_backoff(resolver.probe_attempts);
        resolver.next_probe_at = now.saturating_add(delay);
        warn!(
            "Failed adding path {} (attempt {}), retrying in {}ms",
            resolver.addr,
            resolver.probe_attempts,
            delay / 1000
        );
    }

    if default_mode != primary_mode {
        unsafe { slipstream_set_default_path_mode(resolver_mode_to_c(primary_mode)) };
    }

    Ok(())
}

fn find_resolver_by_path_id(
    resolvers: &mut [ResolverState],
    path_id: libc::c_int,
) -> Option<&mut ResolverState> {
    if path_id < 0 {
        return None;
    }
    resolvers
        .iter_mut()
        .find(|resolver| resolver.added && resolver.path_id == path_id)
}

fn find_resolver_by_addr(
    resolvers: &mut [ResolverState],
    peer: SocketAddr,
) -> Option<&mut ResolverState> {
    let peer = normalize_dual_stack_addr(peer);
    resolvers.iter_mut().find(|resolver| resolver.addr == peer)
}

fn resolver_mode_to_c(mode: ResolverMode) -> libc::c_int {
    match mode {
        ResolverMode::Recursive => 1,
        ResolverMode::Authoritative => 2,
    }
}

fn path_probe_backoff(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(6);
    let delay = PATH_PROBE_INITIAL_DELAY_US.saturating_mul(1u64 << shift);
    delay.min(PATH_PROBE_MAX_DELAY_US)
}

fn dns_response_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use slipstream_core::{AddressFamily, HostPort};

    #[test]
    fn rejects_duplicate_resolver_addr() {
        let resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Authoritative,
            },
        ];

        match resolve_resolvers(&resolvers, 900, false) {
            Ok(_) => panic!("expected duplicate resolver error"),
            Err(err) => assert!(err.to_string().contains("Duplicate resolver address")),
        }
    }
}
