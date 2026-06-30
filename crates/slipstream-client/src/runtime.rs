mod path;
mod setup;

use self::path::{
    apply_path_mode, drain_path_events, fetch_path_quality, find_resolver_by_addr_mut,
    loop_burst_total, path_poll_burst_max,
};
use self::setup::{bind_tcp_listener, bind_udp_socket, compute_mtu, map_io};
use crate::dns::{
    add_paths, expire_inflight_polls, handle_dns_response, maybe_report_debug,
    refresh_resolver_path, resolve_resolvers, resolver_mode_to_c, send_poll_queries,
    sockaddr_storage_to_socket_addr, DnsResponseContext, DnsTransport, PeerAddrMode,
};
use crate::error::ClientError;
use crate::pacing::{
    clamp_authoritative_target, clamp_authoritative_target_with_max, cwnd_target_polls,
    inflight_packet_estimate, sanitize_pacing_gain_probe, MAX_ACTIVE_AUTHORITATIVE_TARGET_INFLIGHT,
};
use crate::pinning::configure_pinned_certificate;
use crate::streams::{
    acceptor::ClientAcceptor, client_callback, drain_commands, drain_stream_data, handle_command,
    ClientState, Command,
};
use slipstream_dns::{
    build_edns_raw_qname, build_qname, encode_query_compact, encode_query_edns_raw, QueryParams,
    CLASS_IN, EDNS_UDP_PAYLOAD, RR_TXT,
};
use slipstream_ffi::{
    configure_quic_with_custom,
    picoquic::{
        picoquic_close, picoquic_cnx_t, picoquic_connection_id_t, picoquic_create,
        picoquic_create_client_cnx, picoquic_current_time, picoquic_disable_keep_alive,
        picoquic_enable_keep_alive, picoquic_enable_path_callbacks,
        picoquic_enable_path_callbacks_default, picoquic_get_next_wake_delay,
        picoquic_prepare_next_packet_ex, picoquic_set_callback, slipstream_get_flow_debug,
        slipstream_has_ready_stream, slipstream_is_flow_blocked, slipstream_mixed_cc_algorithm,
        slipstream_set_cc_override, slipstream_set_default_path_mode,
        PICOQUIC_CONNECTION_ID_MAX_SIZE, PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX,
        PICOQUIC_PACKET_LOOP_SEND_MAX,
    },
    socket_addr_to_storage, take_crypto_errors, ClientConfig, QuicGuard, ResolverMode,
    ResolverTransport, UpstreamEncoding,
};
use std::ffi::CString;
use std::future::pending;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

// Protocol defaults; see docs/config.md for details.
const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const SLIPSTREAM_SNI: &str = "test.example.com";
const DNS_WAKE_DELAY_MAX_US: i64 = 10_000_000;
const DNS_POLL_SLICE_US: u64 = 50_000;
const DNS_IDLE_SLEEP_MIN_US: u64 = 50_000;
pub(crate) const DEFAULT_DNS_TCP_PACKET_LOOP_BURST: usize = 64;
const DNS_TCP_PACKET_LOOP_BURST_MIN: usize = 1;
const DNS_TCP_PACKET_LOOP_BURST_MAX: usize = 512;
const DNS_TCP_RECURSIVE_POLL_CREDIT: usize = 4;
const DNS_TCP_RECURSIVE_POLL_SEED: usize = 16;
const DNS_UDP_RECURSIVE_POLL_CREDIT: usize = 1;
const DNS_UDP_RECURSIVE_POLL_SEED: usize = 1;
const RECONNECT_SLEEP_MIN_MS: u64 = 250;
const RECONNECT_SLEEP_MAX_MS: u64 = 5_000;
const FLOW_BLOCKED_LOG_INTERVAL_US: u64 = 1_000_000;
const NO_PROGRESS_TIMEOUT_US: u64 = 5_000_000;
const NO_PROGRESS_MIN_ENQUEUED_BYTES: u64 = 128 * 1024;
const NO_PROGRESS_ARM_LOG_INTERVAL_US: u64 = 2_000_000;
const DOWNSTREAM_STALE_ZERO_SEND_MIN: u64 = 10_000;
const STALE_STREAM_MIN_ENQUEUED_BYTES: u64 = 1;
const STALE_STREAM_MIN_IDLE_US: u64 = 4_000_000;
const MAX_UPSTREAM_BUFFERED_BYTES: u64 = 16 * 1024 * 1024;
const UPSTREAM_BACKPRESSURE_RECENT_US: u64 = 2_000_000;
const STREAM_ACTIVE_POLL_GRACE_US: u64 = 2_000_000;
// Only applies after streams go quiet. Active transfers still use the normal burst/pacing path.
const IDLE_STREAM_POLL_INTERVAL_US: u64 = 2_000_000;

#[derive(Debug, Default, Clone, Copy)]
struct FlowDebugSnapshot {
    maxdata_remote: u64,
    data_sent: u64,
    maxdata_local: u64,
    data_consumed: u64,
}

impl FlowDebugSnapshot {
    fn tx_window(self) -> u64 {
        self.maxdata_remote.saturating_sub(self.data_sent)
    }

    fn rx_window(self) -> u64 {
        self.maxdata_local.saturating_sub(self.data_consumed)
    }
}

unsafe fn flow_debug_snapshot(cnx: *mut picoquic_cnx_t) -> FlowDebugSnapshot {
    let mut snapshot = FlowDebugSnapshot::default();
    unsafe {
        slipstream_get_flow_debug(
            cnx,
            &mut snapshot.maxdata_remote,
            &mut snapshot.data_sent,
            &mut snapshot.maxdata_local,
            &mut snapshot.data_consumed,
        );
    }
    snapshot
}

unsafe fn upstream_backpressure_bytes(
    state_ptr: *mut ClientState,
    cnx: *mut picoquic_cnx_t,
    now: u64,
) -> Option<u64> {
    let (enqueued_bytes, last_enqueue_at) = unsafe { (*state_ptr).debug_snapshot() };
    let sent_bytes = unsafe { flow_debug_snapshot(cnx) }.data_sent;
    let buffered = enqueued_bytes.saturating_sub(sent_bytes);
    let recent_enqueue = last_enqueue_at != 0
        && now.saturating_sub(last_enqueue_at) < UPSTREAM_BACKPRESSURE_RECENT_US;
    if recent_enqueue && buffered >= MAX_UPSTREAM_BUFFERED_BYTES {
        Some(buffered)
    } else {
        None
    }
}

fn drain_disconnected_commands(command_rx: &mut mpsc::UnboundedReceiver<Command>) -> usize {
    let mut dropped = 0usize;
    while let Ok(command) = command_rx.try_recv() {
        dropped += 1;
        if let Command::NewStream { stream, .. } = command {
            drop(stream);
        }
    }
    dropped
}

pub(crate) fn sanitize_dns_tcp_packet_loop_burst(value: usize) -> usize {
    value.clamp(DNS_TCP_PACKET_LOOP_BURST_MIN, DNS_TCP_PACKET_LOOP_BURST_MAX)
}

fn compute_transport_mtu(config: &ClientConfig<'_>) -> Result<u32, ClientError> {
    match config.upstream_encoding {
        UpstreamEncoding::Qname => {
            let max_mtu = compute_mtu(config.domain)?;
            if config.qname_mtu == 0 {
                Ok(max_mtu)
            } else {
                Ok(config.qname_mtu.clamp(1, max_mtu))
            }
        }
        UpstreamEncoding::EdnsRaw => Ok(EDNS_UDP_PAYLOAD as u32),
    }
}

pub async fn run_client_with_control(
    config: &ClientConfig<'_>,
    mut shutdown_rx: Option<mpsc::UnboundedReceiver<()>>,
    ready_tx: Option<std_mpsc::Sender<bool>>,
) -> Result<i32, ClientError> {
    report_ready(&ready_tx, false);
    let mtu = compute_transport_mtu(config)?;
    info!(
        "QNAME transport mtu={} domain={} upstream={:?}",
        mtu, config.domain, config.upstream_encoding
    );
    let dns_tcp_packet_loop_burst =
        sanitize_dns_tcp_packet_loop_burst(config.dns_tcp_packet_loop_burst);
    let pacing_gain_probe = sanitize_pacing_gain_probe(config.pacing_gain_probe);
    let (packet_loop_send_base, packet_loop_recv_base, recursive_poll_credit, recursive_poll_seed) =
        match config.resolver_transport {
            ResolverTransport::Tcp => (
                dns_tcp_packet_loop_burst,
                dns_tcp_packet_loop_burst,
                DNS_TCP_RECURSIVE_POLL_CREDIT,
                DNS_TCP_RECURSIVE_POLL_SEED,
            ),
            ResolverTransport::Udp => (
                PICOQUIC_PACKET_LOOP_SEND_MAX,
                PICOQUIC_PACKET_LOOP_RECV_MAX,
                DNS_UDP_RECURSIVE_POLL_CREDIT,
                DNS_UDP_RECURSIVE_POLL_SEED,
            ),
        };
    let (mut dns_transport, peer_addr_mode) = match config.resolver_transport {
        ResolverTransport::Udp => {
            let udp = bind_udp_socket().await?;
            let udp_local_addr = udp.local_addr().map_err(map_io)?;
            (
                DnsTransport::udp(udp),
                PeerAddrMode::from_local_addr(udp_local_addr),
            )
        }
        ResolverTransport::Tcp => {
            let peer_addr_mode = PeerAddrMode::Native;
            let resolvers = resolve_resolvers(
                config.resolvers,
                mtu,
                config.debug_poll,
                peer_addr_mode,
                pacing_gain_probe,
            )?;
            if resolvers.is_empty() {
                return Err(ClientError::new("At least one resolver is required"));
            }
            (DnsTransport::tcp(resolvers[0].addr).await?, peer_addr_mode)
        }
    };

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = ClientAcceptor::new();
    let debug_streams = config.debug_streams;
    let tcp_host = config.tcp_listen_host;
    let tcp_port = config.tcp_listen_port;
    let (listener, bound_host) = bind_tcp_listener(tcp_host, tcp_port)
        .await
        .map_err(map_io)?;
    acceptor.spawn(listener, command_tx.clone());
    info!("Listening on TCP port {} (host {})", tcp_port, bound_host);

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ClientError::new("ALPN contains an unexpected null byte"))?;
    let sni = CString::new(SLIPSTREAM_SNI)
        .map_err(|_| ClientError::new("SNI contains an unexpected null byte"))?;
    let cc_override = match config.congestion_control {
        Some(value) => Some(CString::new(value).map_err(|_| {
            ClientError::new("Congestion control contains an unexpected null byte")
        })?),
        None => None,
    };

    let mut state = Box::new(ClientState::new(
        command_tx,
        data_notify.clone(),
        debug_streams,
        acceptor,
    ));
    let state_ptr: *mut ClientState = &mut *state;
    let _state = state;

    let mut reconnect_delay = Duration::from_millis(RECONNECT_SLEEP_MIN_MS);

    loop {
        if shutdown_requested(&mut shutdown_rx) {
            return Ok(0);
        }
        let mut resolvers = resolve_resolvers(
            config.resolvers,
            mtu,
            config.debug_poll,
            peer_addr_mode,
            pacing_gain_probe,
        )?;
        if resolvers.is_empty() {
            return Err(ClientError::new("At least one resolver is required"));
        }

        let mut local_addr_storage =
            socket_addr_to_storage(dns_transport.local_addr().map_err(map_io)?);

        let current_time = unsafe { picoquic_current_time() };
        let quic = unsafe {
            picoquic_create(
                8,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                alpn.as_ptr(),
                Some(client_callback),
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
            let crypto_errors = take_crypto_errors();
            if crypto_errors.is_empty() {
                return Err(ClientError::new("Could not create QUIC context"));
            }
            return Err(ClientError::new(format!(
                "Could not create QUIC context (TLS errors: {})",
                crypto_errors.join("; ")
            )));
        }
        let _quic_guard = QuicGuard::new(quic);
        let mixed_cc = unsafe { slipstream_mixed_cc_algorithm };
        if mixed_cc.is_null() {
            return Err(ClientError::new("Could not load mixed congestion control"));
        }
        unsafe {
            configure_quic_with_custom(quic, mixed_cc, mtu);
            picoquic_enable_path_callbacks_default(quic, 1);
            let override_ptr = cc_override
                .as_ref()
                .map(|value| value.as_ptr())
                .unwrap_or(std::ptr::null());
            slipstream_set_cc_override(override_ptr);
        }
        unsafe {
            slipstream_set_default_path_mode(resolver_mode_to_c(resolvers[0].mode));
        }
        if let Some(cert) = config.cert {
            configure_pinned_certificate(quic, cert).map_err(ClientError::new)?;
        }
        let mut server_storage = resolvers[0].storage;
        // picoquic_create_client_cnx calls picoquic_start_client_cnx internally (see picoquic/quicctx.c).
        let cnx = unsafe {
            picoquic_create_client_cnx(
                quic,
                &mut server_storage as *mut _ as *mut libc::sockaddr,
                current_time,
                0,
                sni.as_ptr(),
                alpn.as_ptr(),
                Some(client_callback),
                state_ptr as *mut _,
            )
        };
        if cnx.is_null() {
            return Err(ClientError::new("Could not create QUIC connection"));
        }

        apply_path_mode(cnx, &mut resolvers[0])?;

        unsafe {
            picoquic_set_callback(cnx, Some(client_callback), state_ptr as *mut _);
            picoquic_enable_path_callbacks(cnx, 1);
            if config.keep_alive_interval > 0 {
                picoquic_enable_keep_alive(cnx, config.keep_alive_interval as u64 * 1000);
            } else {
                picoquic_disable_keep_alive(cnx);
            }
        }

        if config.gso {
            warn!("GSO is not implemented in the Rust client loop yet.");
        }

        let mut dns_id = 1u16;
        let mut recv_buf = vec![0u8; 4096];
        let mut send_buf = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];
        let packet_loop_send_max = loop_burst_total(&resolvers, packet_loop_send_base);
        let packet_loop_recv_max = loop_burst_total(&resolvers, packet_loop_recv_base);
        let recursive_poll_burst_max = packet_loop_send_base;
        let mut zero_send_loops = 0u64;
        let mut zero_send_with_streams = 0u64;
        let mut last_flow_block_log_at = 0u64;
        let mut dns_send_bytes_total = 0u64;
        let mut last_no_progress_enqueued_bytes = 0u64;
        let mut last_no_progress_dns_send_bytes = 0u64;
        let mut no_progress_since = 0u64;
        let mut last_no_progress_arm_log_at = 0u64;
        let mut last_idle_stream_poll_at = 0u64;
        let mut ready_reported = false;
        let mut fatal_no_progress: Option<String> = None;

        loop {
            if shutdown_requested(&mut shutdown_rx) {
                return Ok(0);
            }
            let current_time = unsafe { picoquic_current_time() };
            drain_commands(cnx, state_ptr, &mut command_rx);
            if let Some(upstream_buffered) =
                unsafe { upstream_backpressure_bytes(state_ptr, cnx, current_time) }
            {
                debug!(
                    "upstream backpressure: buffered={} limit={}; pausing local TCP drain",
                    upstream_buffered, MAX_UPSTREAM_BUFFERED_BYTES
                );
            } else {
                drain_stream_data(cnx, state_ptr);
            }
            let closing = unsafe { (*state_ptr).is_closing() };
            if closing {
                break;
            }

            let ready = unsafe { (*state_ptr).is_ready() };
            if ready {
                if !ready_reported {
                    report_ready(&ready_tx, true);
                    ready_reported = true;
                }
                unsafe {
                    (*state_ptr).update_acceptor_limit(cnx);
                }
                if reconnect_delay != Duration::from_millis(RECONNECT_SLEEP_MIN_MS) {
                    reconnect_delay = Duration::from_millis(RECONNECT_SLEEP_MIN_MS);
                }
                add_paths(cnx, &mut resolvers)?;
                for resolver in resolvers.iter_mut() {
                    if resolver.added {
                        apply_path_mode(cnx, resolver)?;
                    }
                }
            }
            drain_path_events(cnx, &mut resolvers, state_ptr, peer_addr_mode);

            for resolver in resolvers.iter_mut() {
                if resolver.mode == ResolverMode::Authoritative {
                    expire_inflight_polls(&mut resolver.inflight_poll_ids, current_time);
                }
            }

            let delay_us =
                unsafe { picoquic_get_next_wake_delay(quic, current_time, DNS_WAKE_DELAY_MAX_US) };
            let delay_us = if delay_us < 0 { 0 } else { delay_us as u64 };
            let streams_len_for_sleep = unsafe { (*state_ptr).streams_len() };
            let (_, last_enqueue_at_for_sleep) = unsafe { (*state_ptr).debug_snapshot() };
            let has_recent_stream_activity_for_sleep = streams_len_for_sleep > 0
                && (last_enqueue_at_for_sleep == 0
                    || current_time.saturating_sub(last_enqueue_at_for_sleep)
                        < STREAM_ACTIVE_POLL_GRACE_US);
            let idle_stream_poll_due_for_sleep = streams_len_for_sleep > 0
                && !has_recent_stream_activity_for_sleep
                && current_time.saturating_sub(last_idle_stream_poll_at)
                    >= IDLE_STREAM_POLL_INTERVAL_US;
            let mut has_work = false;
            for resolver in resolvers.iter_mut() {
                if !refresh_resolver_path(cnx, resolver) {
                    continue;
                }
                let pending_for_sleep = match resolver.mode {
                    ResolverMode::Authoritative => {
                        if ready
                            && streams_len_for_sleep > 0
                            && (has_recent_stream_activity_for_sleep
                                || idle_stream_poll_due_for_sleep)
                        {
                            let quality = fetch_path_quality(cnx, resolver);
                            let max_target = if current_time < resolver.high_throughput_until {
                                MAX_ACTIVE_AUTHORITATIVE_TARGET_INFLIGHT
                            } else {
                                0
                            };
                            let snapshot = resolver.pacing_budget.as_mut().map(|budget| {
                                if max_target > 0 {
                                    budget.target_inflight(&quality, delay_us.max(1), max_target)
                                } else {
                                    budget.target_inflight(&quality, delay_us.max(1), 64)
                                }
                            });
                            resolver.last_pacing_snapshot = snapshot;
                            let target = snapshot
                                .map(|snapshot| snapshot.target_inflight)
                                .unwrap_or_else(|| {
                                    clamp_authoritative_target(
                                        cwnd_target_polls(quality.cwin, mtu),
                                        mtu,
                                    )
                                });
                            let inflight_packets =
                                inflight_packet_estimate(quality.bytes_in_transit, mtu);
                            let deficit = target.saturating_sub(
                                inflight_packets.saturating_add(resolver.inflight_poll_ids.len()),
                            );
                            if has_recent_stream_activity_for_sleep {
                                deficit
                            } else {
                                deficit.min(1)
                            }
                        } else {
                            resolver.last_pacing_snapshot = None;
                            0
                        }
                    }
                    ResolverMode::Recursive => resolver.pending_polls,
                };
                if pending_for_sleep > 0 {
                    has_work = true;
                }
                if resolver.mode == ResolverMode::Authoritative
                    && !resolver.inflight_poll_ids.is_empty()
                {
                    has_work = true;
                }
            }
            // Avoid a tight poll loop when idle, but keep the short slice during active transfers.
            let timeout_us = if has_work {
                delay_us.clamp(1, DNS_POLL_SLICE_US)
            } else if ready {
                delay_us.max(DNS_IDLE_SLEEP_MIN_US)
            } else {
                delay_us.max(1)
            };
            let timeout = Duration::from_micros(timeout_us);

            tokio::select! {
                command = command_rx.recv() => {
                    if let Some(command) = command {
                        handle_command(cnx, state_ptr, command);
                    }
                }
                _ = wait_for_shutdown(&mut shutdown_rx) => {
                    return Ok(0);
                }
                _ = data_notify.notified() => {}
                recv = dns_transport.recv_from(&mut recv_buf) => {
                    match recv {
                        Ok((size, peer)) => {
                            local_addr_storage =
                                socket_addr_to_storage(dns_transport.local_addr().map_err(map_io)?);
                            handle_dns_response(
                                &recv_buf[..size],
                                peer,
                                &mut DnsResponseContext {
                                    quic,
                                    local_addr_storage: &local_addr_storage,
                                    peer_addr_mode,
                                    resolvers: &mut resolvers,
                                    recursive_poll_credit,
                                    recursive_poll_burst_max,
                                },
                            )?;
                            for _ in 1..packet_loop_recv_max {
                                match dns_transport.try_recv_from(&mut recv_buf) {
                                    Ok(Some((size, peer))) => {
                                        local_addr_storage =
                                            socket_addr_to_storage(dns_transport.local_addr().map_err(map_io)?);
                                        handle_dns_response(
                                            &recv_buf[..size],
                                            peer,
                                            &mut DnsResponseContext {
                                                quic,
                                                local_addr_storage: &local_addr_storage,
                                                peer_addr_mode,
                                                resolvers: &mut resolvers,
                                                recursive_poll_credit,
                                                recursive_poll_burst_max,
                                            },
                                        )?;
                                    }
                                    Ok(None) => break,
                                    Err(err) => {
                                        if dns_transport.is_transient_recv_error(&err) {
                                            break;
                                        }
                                        return Err(map_io(err));
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if !dns_transport.is_transient_recv_error(&err) {
                                return Err(map_io(err));
                            }
                        }
                    }
                }
                _ = sleep(timeout) => {}
            }

            drain_commands(cnx, state_ptr, &mut command_rx);
            let current_time = unsafe { picoquic_current_time() };
            if let Some(upstream_buffered) =
                unsafe { upstream_backpressure_bytes(state_ptr, cnx, current_time) }
            {
                debug!(
                    "upstream backpressure: buffered={} limit={}; pausing local TCP drain",
                    upstream_buffered, MAX_UPSTREAM_BUFFERED_BYTES
                );
            } else {
                drain_stream_data(cnx, state_ptr);
            }
            drain_path_events(cnx, &mut resolvers, state_ptr, peer_addr_mode);

            for _ in 0..packet_loop_send_max {
                let current_time = unsafe { picoquic_current_time() };
                let mut send_length: libc::size_t = 0;
                let mut addr_to: slipstream_ffi::SockaddrStorage = unsafe { std::mem::zeroed() };
                let mut addr_from: slipstream_ffi::SockaddrStorage = unsafe { std::mem::zeroed() };
                let mut if_index: libc::c_int = 0;
                let mut log_cid = picoquic_connection_id_t {
                    id: [0; PICOQUIC_CONNECTION_ID_MAX_SIZE],
                    id_len: 0,
                };
                let mut last_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();

                let ret = unsafe {
                    picoquic_prepare_next_packet_ex(
                        quic,
                        current_time,
                        send_buf.as_mut_ptr(),
                        send_buf.len(),
                        &mut send_length,
                        &mut addr_to,
                        &mut addr_from,
                        &mut if_index,
                        &mut log_cid,
                        &mut last_cnx,
                        std::ptr::null_mut(),
                    )
                };
                if ret < 0 {
                    return Err(ClientError::new("Failed preparing outbound QUIC packet"));
                }
                if send_length == 0 {
                    zero_send_loops = zero_send_loops.saturating_add(1);
                    let streams_len = unsafe { (*state_ptr).streams_len() };
                    if streams_len > 0 {
                        zero_send_with_streams = zero_send_with_streams.saturating_add(1);
                        let flow_blocked = unsafe { slipstream_is_flow_blocked(cnx) } != 0;
                        if flow_blocked {
                            for resolver in resolvers.iter_mut() {
                                if resolver.mode == ResolverMode::Recursive && resolver.added {
                                    resolver.pending_polls = resolver
                                        .pending_polls
                                        .max(recursive_poll_seed)
                                        .min(recursive_poll_burst_max);
                                }
                            }
                        }
                    }
                    break;
                }

                if addr_to.ss_family == 0 {
                    break;
                }
                if let Ok(dest) = sockaddr_storage_to_socket_addr(&addr_to) {
                    let dest = peer_addr_mode.canonicalize(dest);
                    if let Some(resolver) =
                        find_resolver_by_addr_mut(&mut resolvers, dest, peer_addr_mode)
                    {
                        resolver.local_addr_storage = Some(unsafe { std::ptr::read(&addr_from) });
                        resolver.debug.send_packets = resolver.debug.send_packets.saturating_add(1);
                        resolver.debug.send_bytes =
                            resolver.debug.send_bytes.saturating_add(send_length as u64);
                    }
                }

                let packet = match config.upstream_encoding {
                    UpstreamEncoding::Qname => {
                        let qname = build_qname(&send_buf[..send_length], config.domain)
                            .map_err(|err| ClientError::new(err.to_string()))?;
                        let params = QueryParams {
                            id: dns_id,
                            qname: &qname,
                            qtype: RR_TXT,
                            qclass: CLASS_IN,
                            rd: true,
                            cd: false,
                            qdcount: 1,
                            is_query: true,
                        };
                        encode_query_compact(&params)
                            .map_err(|err| ClientError::new(err.to_string()))?
                    }
                    UpstreamEncoding::EdnsRaw => {
                        let qname = build_edns_raw_qname(config.domain)
                            .map_err(|err| ClientError::new(err.to_string()))?;
                        encode_query_edns_raw(dns_id, &qname, &send_buf[..send_length], true, false)
                            .map_err(|err| ClientError::new(err.to_string()))?
                    }
                };
                dns_id = dns_id.wrapping_add(1);

                let dest = sockaddr_storage_to_socket_addr(&addr_to)?;
                let dest = peer_addr_mode.canonicalize(dest);
                local_addr_storage = addr_from;
                match dns_transport.send_to(&packet, dest).await {
                    Ok(()) => {
                        dns_send_bytes_total =
                            dns_send_bytes_total.saturating_add(packet.len() as u64);
                    }
                    Err(err) => {
                        if !dns_transport.is_transient_recv_error(&err) {
                            return Err(map_io(err));
                        }
                    }
                }
            }

            let has_ready_stream = unsafe { slipstream_has_ready_stream(cnx) != 0 };
            let flow_blocked = unsafe { slipstream_is_flow_blocked(cnx) != 0 };
            let streams_len = unsafe { (*state_ptr).streams_len() };
            let metrics = unsafe { (*state_ptr).stream_debug_metrics() };
            let (enqueued_bytes, last_enqueue_at) = unsafe { (*state_ptr).debug_snapshot() };
            let now = unsafe { picoquic_current_time() };
            let has_recent_stream_activity = streams_len > 0
                && (last_enqueue_at == 0
                    || now.saturating_sub(last_enqueue_at) < STREAM_ACTIVE_POLL_GRACE_US);
            let idle_stream_poll_due = streams_len > 0
                && !has_recent_stream_activity
                && now.saturating_sub(last_idle_stream_poll_at) >= IDLE_STREAM_POLL_INTERVAL_US;
            let last_enqueue_ms = if last_enqueue_at == 0 {
                0
            } else {
                now.saturating_sub(last_enqueue_at) / 1_000
            };
            if streams_len > 0
                && now.saturating_sub(last_flow_block_log_at) >= FLOW_BLOCKED_LOG_INTERVAL_US
            {
                let backlog = unsafe { (*state_ptr).stream_backlog_summaries(8) };
                let flow_debug = unsafe { flow_debug_snapshot(cnx) };
                if flow_blocked {
                    error!(
                        "transfer_debug: streams={} streams_with_rx_queued={} streams_with_data_rx_queued={} data_rx_queued_chunks_total={} queued_bytes_total={} streams_with_recv_fin={} streams_with_send_fin={} streams_discarding={} streams_with_unconsumed_rx={} enqueued_bytes={} dns_send_bytes_total={} last_enqueue_ms={} zero_send_with_streams={} zero_send_loops={} flow_blocked={} has_ready_stream={} maxdata_remote={} data_sent={} tx_window={} maxdata_local={} data_consumed={} rx_window={} backlog={:?}",
                        streams_len,
                        metrics.streams_with_rx_queued,
                        metrics.streams_with_data_rx_queued,
                        metrics.data_rx_queued_chunks_total,
                        metrics.queued_bytes_total,
                        metrics.streams_with_recv_fin,
                        metrics.streams_with_send_fin,
                        metrics.streams_discarding,
                        metrics.streams_with_unconsumed_rx,
                        enqueued_bytes,
                        dns_send_bytes_total,
                        last_enqueue_ms,
                        zero_send_with_streams,
                        zero_send_loops,
                        flow_blocked,
                        has_ready_stream,
                        flow_debug.maxdata_remote,
                        flow_debug.data_sent,
                        flow_debug.tx_window(),
                        flow_debug.maxdata_local,
                        flow_debug.data_consumed,
                        flow_debug.rx_window(),
                        backlog
                    );
                } else {
                    info!(
                        "transfer_debug: streams={} streams_with_rx_queued={} streams_with_data_rx_queued={} data_rx_queued_chunks_total={} queued_bytes_total={} streams_with_recv_fin={} streams_with_send_fin={} streams_discarding={} streams_with_unconsumed_rx={} enqueued_bytes={} dns_send_bytes_total={} last_enqueue_ms={} zero_send_with_streams={} zero_send_loops={} flow_blocked={} has_ready_stream={} maxdata_remote={} data_sent={} tx_window={} maxdata_local={} data_consumed={} rx_window={} backlog={:?}",
                        streams_len,
                        metrics.streams_with_rx_queued,
                        metrics.streams_with_data_rx_queued,
                        metrics.data_rx_queued_chunks_total,
                        metrics.queued_bytes_total,
                        metrics.streams_with_recv_fin,
                        metrics.streams_with_send_fin,
                        metrics.streams_discarding,
                        metrics.streams_with_unconsumed_rx,
                        enqueued_bytes,
                        dns_send_bytes_total,
                        last_enqueue_ms,
                        zero_send_with_streams,
                        zero_send_loops,
                        flow_blocked,
                        has_ready_stream,
                        flow_debug.maxdata_remote,
                        flow_debug.data_sent,
                        flow_debug.tx_window(),
                        flow_debug.maxdata_local,
                        flow_debug.data_consumed,
                        flow_debug.rx_window(),
                        backlog
                    );
                }
                last_flow_block_log_at = now;
            }

            let connection_ready = unsafe { (*state_ptr).is_ready() };
            let local_pressure = enqueued_bytes > last_no_progress_enqueued_bytes
                || metrics.streams_with_data_rx_queued > 0
                || metrics.data_rx_queued_chunks_total > 0;
            let dns_send_progress = dns_send_bytes_total > last_no_progress_dns_send_bytes;
            let stalled_signal = flow_blocked || !has_ready_stream || zero_send_with_streams > 0;
            let downstream_stale = metrics.data_rx_queued_chunks_total == 0
                && metrics.streams_with_data_rx_queued == 0
                && zero_send_with_streams >= DOWNSTREAM_STALE_ZERO_SEND_MIN;
            let stale_stream = enqueued_bytes >= STALE_STREAM_MIN_ENQUEUED_BYTES
                && last_enqueue_at != 0
                && now.saturating_sub(last_enqueue_at) >= STALE_STREAM_MIN_IDLE_US
                && downstream_stale
                && !has_ready_stream;
            let no_recent_enqueue = last_enqueue_at != 0
                && now.saturating_sub(last_enqueue_at) >= NO_PROGRESS_TIMEOUT_US;
            let large_no_progress = enqueued_bytes >= NO_PROGRESS_MIN_ENQUEUED_BYTES
                && no_recent_enqueue
                && !has_ready_stream
                && (!dns_send_progress || downstream_stale);
            let stalled_no_progress = connection_ready
                && streams_len > 0
                && (large_no_progress || stale_stream)
                && stalled_signal;
            if stalled_no_progress && (local_pressure || no_progress_since != 0) {
                if no_progress_since == 0 {
                    no_progress_since = now;
                    if now.saturating_sub(last_no_progress_arm_log_at)
                        >= NO_PROGRESS_ARM_LOG_INTERVAL_US
                    {
                        last_no_progress_arm_log_at = now;
                        warn!(
                            "no-progress detector armed: reason={} streams={} enqueued_bytes={} dns_send_bytes_total={} last_enqueue_ms={} flow_blocked={} has_ready_stream={} data_rx_queued_chunks_total={} zero_send_with_streams={}",
                            if stale_stream { "stale_stream" } else { "large_no_progress" },
                            streams_len,
                            enqueued_bytes,
                            dns_send_bytes_total,
                            last_enqueue_ms,
                            flow_blocked,
                            has_ready_stream,
                            metrics.data_rx_queued_chunks_total,
                            zero_send_with_streams
                        );
                    }
                } else if now.saturating_sub(no_progress_since) >= NO_PROGRESS_TIMEOUT_US {
                    error!(
                        "no-progress detected for {}ms reason={}: streams={} enqueued_bytes={} dns_send_bytes_total={} last_enqueue_ms={} flow_blocked={} has_ready_stream={} data_rx_queued_chunks_total={} zero_send_with_streams={}; resetting connection",
                        now.saturating_sub(no_progress_since) / 1_000,
                        if stale_stream { "stale_stream" } else { "large_no_progress" },
                        streams_len,
                        enqueued_bytes,
                        dns_send_bytes_total,
                        last_enqueue_ms,
                        flow_blocked,
                        has_ready_stream,
                        metrics.data_rx_queued_chunks_total,
                        zero_send_with_streams
                    );
                    fatal_no_progress = Some(format!(
                        "native no-progress reason={} streams={} enqueued_bytes={} last_enqueue_ms={} zero_send_with_streams={}",
                        if stale_stream { "stale_stream" } else { "large_no_progress" },
                        streams_len,
                        enqueued_bytes,
                        last_enqueue_ms,
                        zero_send_with_streams
                    ));
                    break;
                }
            } else {
                no_progress_since = 0;
            }
            last_no_progress_enqueued_bytes = enqueued_bytes;
            last_no_progress_dns_send_bytes = dns_send_bytes_total;
            for resolver in resolvers.iter_mut() {
                if !refresh_resolver_path(cnx, resolver) {
                    continue;
                }
                match resolver.mode {
                    ResolverMode::Authoritative => {
                        let mut quality_for_log = None;
                        let allow_poll =
                            has_recent_stream_activity || flow_blocked || idle_stream_poll_due;
                        let mut poll_deficit = if streams_len > 0 && allow_poll {
                            let quality = fetch_path_quality(cnx, resolver);
                            let snapshot = resolver.last_pacing_snapshot;
                            let max_target = if current_time < resolver.high_throughput_until {
                                MAX_ACTIVE_AUTHORITATIVE_TARGET_INFLIGHT
                            } else {
                                0
                            };
                            let pacing_target = snapshot
                                .map(|snapshot| snapshot.target_inflight)
                                .unwrap_or_else(|| {
                                    if max_target > 0 {
                                        clamp_authoritative_target_with_max(
                                            cwnd_target_polls(quality.cwin, mtu),
                                            mtu,
                                            max_target,
                                        )
                                    } else {
                                        clamp_authoritative_target(
                                            cwnd_target_polls(quality.cwin, mtu),
                                            mtu,
                                        )
                                    }
                                });
                            let inflight_packets =
                                inflight_packet_estimate(quality.bytes_in_transit, mtu);
                            quality_for_log = Some(quality);
                            pacing_target.saturating_sub(
                                inflight_packets.saturating_add(resolver.inflight_poll_ids.len()),
                            )
                        } else {
                            resolver.last_pacing_snapshot = None;
                            0
                        };
                        if idle_stream_poll_due && !has_recent_stream_activity && !flow_blocked {
                            poll_deficit = poll_deficit.min(1);
                        }
                        if has_ready_stream && !flow_blocked {
                            poll_deficit = 0;
                        }
                        if poll_deficit > 0 && resolver.debug.enabled {
                            let quality = quality_for_log.unwrap_or_default();
                            debug!(
                                "cc_state: {} cwnd={} in_transit={} rtt_us={} flow_blocked={} deficit={}",
                                resolver.label(),
                                quality.cwin,
                                quality.bytes_in_transit,
                                quality.rtt,
                                flow_blocked,
                                poll_deficit
                            );
                        }
                        if poll_deficit > 0 {
                            let burst_max = path_poll_burst_max(resolver, packet_loop_send_base);
                            let mut to_send = poll_deficit.min(burst_max);
                            send_poll_queries(
                                cnx,
                                &mut dns_transport,
                                config,
                                &mut local_addr_storage,
                                &mut dns_id,
                                resolver,
                                peer_addr_mode,
                                &mut to_send,
                                &mut send_buf,
                            )
                            .await?;
                            if idle_stream_poll_due
                                && !has_recent_stream_activity
                                && !flow_blocked
                                && to_send == 0
                            {
                                last_idle_stream_poll_at = current_time;
                            }
                        }
                    }
                    ResolverMode::Recursive => {
                        resolver.last_pacing_snapshot = None;
                        if resolver.pending_polls > 0 {
                            let burst_max = path_poll_burst_max(resolver, packet_loop_send_base);
                            if resolver.pending_polls > burst_max {
                                let mut to_send = burst_max;
                                send_poll_queries(
                                    cnx,
                                    &mut dns_transport,
                                    config,
                                    &mut local_addr_storage,
                                    &mut dns_id,
                                    resolver,
                                    peer_addr_mode,
                                    &mut to_send,
                                    &mut send_buf,
                                )
                                .await?;
                                resolver.pending_polls = resolver
                                    .pending_polls
                                    .saturating_sub(burst_max)
                                    .saturating_add(to_send);
                            } else {
                                let mut pending = resolver.pending_polls;
                                send_poll_queries(
                                    cnx,
                                    &mut dns_transport,
                                    config,
                                    &mut local_addr_storage,
                                    &mut dns_id,
                                    resolver,
                                    peer_addr_mode,
                                    &mut pending,
                                    &mut send_buf,
                                )
                                .await?;
                                resolver.pending_polls = pending;
                            }
                        }
                    }
                }
            }

            let report_time = unsafe { picoquic_current_time() };
            let (enqueued_bytes, last_enqueue_at) = unsafe { (*state_ptr).debug_snapshot() };
            let streams_len = unsafe { (*state_ptr).streams_len() };
            for resolver in resolvers.iter_mut() {
                resolver.debug.enqueued_bytes = enqueued_bytes;
                resolver.debug.last_enqueue_at = last_enqueue_at;
                resolver.debug.zero_send_loops = zero_send_loops;
                resolver.debug.zero_send_with_streams = zero_send_with_streams;
                if !refresh_resolver_path(cnx, resolver) {
                    continue;
                }
                let inflight_polls = resolver.inflight_poll_ids.len();
                let pending_for_debug = match resolver.mode {
                    ResolverMode::Authoritative => {
                        let quality = fetch_path_quality(cnx, resolver);
                        let inflight_packets =
                            inflight_packet_estimate(quality.bytes_in_transit, mtu);
                        resolver
                            .last_pacing_snapshot
                            .map(|snapshot| {
                                snapshot.target_inflight.saturating_sub(inflight_packets)
                            })
                            .unwrap_or(0)
                    }
                    ResolverMode::Recursive => resolver.pending_polls,
                };
                maybe_report_debug(
                    resolver,
                    report_time,
                    streams_len,
                    pending_for_debug,
                    inflight_polls,
                    resolver.last_pacing_snapshot,
                );
            }
        }

        unsafe {
            picoquic_close(cnx, 0);
        }
        report_ready(&ready_tx, false);

        unsafe {
            (*state_ptr).reset_for_reconnect();
        }
        let dropped = drain_disconnected_commands(&mut command_rx);
        if dropped > 0 {
            warn!("Dropped {} queued commands while reconnecting", dropped);
        }
        if let Some(reason) = fatal_no_progress {
            error!("{}; leaving native reconnect to Android service", reason);
            return Err(ClientError::new(reason));
        }
        warn!(
            "Connection closed; reconnecting in {}ms",
            reconnect_delay.as_millis()
        );
        // Sleep in small chunks and drop commands that arrive while disconnected.
        let mut remaining_sleep = reconnect_delay;
        while remaining_sleep > Duration::ZERO {
            if shutdown_requested(&mut shutdown_rx) {
                return Ok(0);
            }
            let chunk = remaining_sleep.min(Duration::from_millis(100));
            sleep(chunk).await;
            remaining_sleep -= chunk;
            let _ = drain_disconnected_commands(&mut command_rx);
        }
        reconnect_delay = (reconnect_delay * 2).min(Duration::from_millis(RECONNECT_SLEEP_MAX_MS));
    }
}

fn report_ready(ready_tx: &Option<std_mpsc::Sender<bool>>, ready: bool) {
    if let Some(ready_tx) = ready_tx {
        let _ = ready_tx.send(ready);
    }
}

fn shutdown_requested(shutdown_rx: &mut Option<mpsc::UnboundedReceiver<()>>) -> bool {
    match shutdown_rx {
        Some(rx) => match rx.try_recv() {
            Ok(()) | Err(mpsc::error::TryRecvError::Disconnected) => true,
            Err(mpsc::error::TryRecvError::Empty) => false,
        },
        None => false,
    }
}

async fn wait_for_shutdown(shutdown_rx: &mut Option<mpsc::UnboundedReceiver<()>>) {
    match shutdown_rx {
        Some(rx) => {
            let _ = rx.recv().await;
        }
        None => pending::<()>().await,
    }
}
