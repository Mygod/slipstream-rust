use slipstream_dns::{build_qname, encode_query, QueryParams, CLASS_IN, RR_TXT};
use slipstream_ffi::{
    configure_quic,
    picoquic::{
        get_bytes_in_transit, get_cwin, get_rtt, picoquic_close, picoquic_cnx_t,
        picoquic_connection_id_t, picoquic_create, picoquic_create_client_cnx,
        picoquic_current_time, picoquic_disable_keep_alive, picoquic_enable_keep_alive,
        picoquic_get_next_wake_delay, picoquic_prepare_next_packet_ex, picoquic_set_callback,
        slipstream_has_ready_stream, slipstream_is_flow_blocked, PICOQUIC_CONNECTION_ID_MAX_SIZE,
        PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX, PICOQUIC_PACKET_LOOP_SEND_MAX,
    },
    socket_addr_to_storage, ClientConfig, QuicGuard,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};
use tokio::sync::{mpsc, Notify};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::dns::{
    add_paths, expire_inflight_polls, handle_dns_response, maybe_report_debug,
    normalize_dual_stack_addr, resolve_resolvers, send_poll_queries,
    sockaddr_storage_to_socket_addr, DebugMetrics, DnsResponseContext,
};
use crate::pacing::{cwnd_target_polls, inflight_packet_estimate, PacingPollBudget};
use crate::pinning::configure_pinned_certificate;
use crate::streams::{
    client_callback, drain_commands, drain_stream_data, handle_command, spawn_acceptor, ClientState,
};

// Protocol defaults; see docs/config.md for details.
const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const SLIPSTREAM_SNI: &str = "test.example.com";
const DNS_WAKE_DELAY_MAX_US: i64 = 10_000_000;
const DNS_POLL_SLICE_US: u64 = 50_000;
const AUTHORITATIVE_LOOP_MULTIPLIER: usize = 4;

#[derive(Debug)]
pub struct ClientError {
    message: String,
}

impl ClientError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ClientError {}

pub async fn run_client(config: &ClientConfig<'_>) -> Result<i32, ClientError> {
    let domain_len = config.domain.len();
    let mtu = compute_mtu(domain_len)?;
    let mut pacing_budget = PacingPollBudget::new(mtu);
    let mut resolvers = resolve_resolvers(config.resolvers)?;
    if resolvers.is_empty() {
        return Err(ClientError::new("At least one resolver is required"));
    }

    let udp = bind_udp_socket().await?;
    let mut local_addr_storage = socket_addr_to_storage(udp.local_addr().map_err(map_io)?);

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let debug_streams = config.debug_streams;
    let listener = TokioTcpListener::bind(("0.0.0.0", config.tcp_listen_port))
        .await
        .map_err(map_io)?;
    spawn_acceptor(listener, command_tx.clone());
    info!("Listening on TCP port {}", config.tcp_listen_port);

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ClientError::new("ALPN contains an unexpected null byte"))?;
    let sni = CString::new(SLIPSTREAM_SNI)
        .map_err(|_| ClientError::new("SNI contains an unexpected null byte"))?;
    let cc_algo = CString::new(config.congestion_control)
        .map_err(|_| ClientError::new("Congestion control contains an unexpected null byte"))?;

    let mut state = Box::new(ClientState::new(
        command_tx,
        data_notify.clone(),
        config.authoritative,
        debug_streams,
    ));
    let state_ptr: *mut ClientState = &mut *state;
    let _state = state;

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
        return Err(ClientError::new("Could not create QUIC context"));
    }
    let _quic_guard = QuicGuard::new(quic);
    unsafe {
        configure_quic(quic, cc_algo.as_ptr(), mtu);
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

    unsafe {
        picoquic_set_callback(cnx, Some(client_callback), state_ptr as *mut _);
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
    let mut pending_polls: usize = 0;
    let mut inflight_poll_ids: HashMap<u16, u64> = HashMap::new();
    let mut debug = DebugMetrics::new(config.debug_poll);
    let mut recv_buf = vec![0u8; 4096];
    let mut send_buf = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];
    let packet_loop_send_max = if config.authoritative {
        PICOQUIC_PACKET_LOOP_SEND_MAX * AUTHORITATIVE_LOOP_MULTIPLIER
    } else {
        PICOQUIC_PACKET_LOOP_SEND_MAX
    };
    let packet_loop_recv_max = if config.authoritative {
        PICOQUIC_PACKET_LOOP_RECV_MAX * AUTHORITATIVE_LOOP_MULTIPLIER
    } else {
        PICOQUIC_PACKET_LOOP_RECV_MAX
    };

    loop {
        let current_time = unsafe { picoquic_current_time() };
        drain_commands(cnx, state_ptr, &mut command_rx);
        drain_stream_data(cnx, state_ptr);
        let closing = unsafe { (*state_ptr).is_closing() };
        if closing {
            break;
        }

        let ready = unsafe { (*state_ptr).is_ready() };
        if ready {
            add_paths(cnx, &mut resolvers)?;
        }

        if config.authoritative {
            expire_inflight_polls(&mut inflight_poll_ids, current_time);
        }

        let delay_us =
            unsafe { picoquic_get_next_wake_delay(quic, current_time, DNS_WAKE_DELAY_MAX_US) };
        let delay_us = if delay_us < 0 { 0 } else { delay_us as u64 };
        let pacing_snapshot = if config.authoritative {
            Some(pacing_budget.target_inflight(cnx, delay_us.max(1)))
        } else {
            None
        };
        let streams_len_for_sleep = unsafe { (*state_ptr).streams_len() };
        let inflight_polls_for_sleep = inflight_poll_ids.len();
        let inflight_packets_for_sleep = if config.authoritative {
            inflight_packet_estimate(cnx, mtu)
        } else {
            0
        };
        let poll_deficit_for_sleep = if config.authoritative {
            pacing_snapshot
                .as_ref()
                .map(|snapshot| {
                    snapshot
                        .target_inflight
                        .saturating_sub(inflight_packets_for_sleep)
                })
                .unwrap_or(0)
        } else {
            pending_polls
        };
        let has_work = if config.authoritative {
            poll_deficit_for_sleep > 0 || streams_len_for_sleep > 0 || inflight_polls_for_sleep > 0
        } else {
            poll_deficit_for_sleep > 0 || streams_len_for_sleep > 0
        };
        // Avoid a tight poll loop when idle, but keep the short slice during active transfers.
        let timeout_us = if has_work {
            delay_us.clamp(1, DNS_POLL_SLICE_US)
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
            _ = data_notify.notified() => {}
            recv = udp.recv_from(&mut recv_buf) => {
                match recv {
                    Ok((size, peer)) => {
                        let mut response_ctx = DnsResponseContext {
                            quic,
                            local_addr_storage: &local_addr_storage,
                            pending_polls: &mut pending_polls,
                            inflight_poll_ids: &mut inflight_poll_ids,
                            debug: &mut debug,
                            authoritative: config.authoritative,
                        };
                        handle_dns_response(&recv_buf[..size], peer, &mut response_ctx)?;
                        for _ in 1..packet_loop_recv_max {
                            match udp.try_recv_from(&mut recv_buf) {
                                Ok((size, peer)) => {
                                    handle_dns_response(&recv_buf[..size], peer, &mut response_ctx)?;
                                }
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                                Err(err) => return Err(map_io(err)),
                            }
                        }
                    }
                    Err(err) => {
                        if err.kind() != std::io::ErrorKind::WouldBlock
                            && err.kind() != std::io::ErrorKind::TimedOut
                            && err.kind() != std::io::ErrorKind::Interrupted
                        {
                            return Err(map_io(err));
                        }
                    }
                }
            }
            _ = sleep(timeout) => {}
        }

        drain_commands(cnx, state_ptr, &mut command_rx);
        drain_stream_data(cnx, state_ptr);

        for _ in 0..packet_loop_send_max {
            let current_time = unsafe { picoquic_current_time() };
            let mut send_length: libc::size_t = 0;
            let mut addr_to: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
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
                debug.zero_send_loops = debug.zero_send_loops.saturating_add(1);
                let streams_len = unsafe { (*state_ptr).streams_len() };
                if streams_len > 0 {
                    debug.zero_send_with_streams = debug.zero_send_with_streams.saturating_add(1);
                    let flow_blocked = unsafe { slipstream_is_flow_blocked(cnx) } != 0;
                    if flow_blocked && !config.authoritative {
                        pending_polls = pending_polls.max(1);
                    }
                }
                break;
            }

            if addr_to.ss_family == 0 {
                break;
            }
            debug.send_packets = debug.send_packets.saturating_add(1);
            debug.send_bytes = debug.send_bytes.saturating_add(send_length as u64);

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
            dns_id = dns_id.wrapping_add(1);
            let packet = encode_query(&params).map_err(|err| ClientError::new(err.to_string()))?;

            let dest = sockaddr_storage_to_socket_addr(&addr_to)?;
            let dest = normalize_dual_stack_addr(dest);
            local_addr_storage = addr_from;
            udp.send_to(&packet, dest).await.map_err(map_io)?;
        }

        let inflight_polls = inflight_poll_ids.len();
        let mut inflight_packets = if config.authoritative {
            inflight_packet_estimate(cnx, mtu)
        } else {
            0
        };
        if config.authoritative {
            let pacing_target = pacing_snapshot
                .map(|snapshot| snapshot.target_inflight)
                .unwrap_or_else(|| cwnd_target_polls(cnx, mtu));
            let mut poll_deficit = pacing_target.saturating_sub(inflight_packets);
            let has_ready_stream = unsafe { slipstream_has_ready_stream(cnx) != 0 };
            let flow_blocked = unsafe { slipstream_is_flow_blocked(cnx) != 0 };
            if has_ready_stream && !flow_blocked {
                poll_deficit = 0;
            }
            if poll_deficit > 0 && debug.enabled {
                let (cwnd, in_transit, rtt) =
                    unsafe { (get_cwin(cnx), get_bytes_in_transit(cnx), get_rtt(cnx)) };
                debug!(
                    "cc_state: cwnd={} in_transit={} rtt_us={} flow_blocked={} deficit={}",
                    cwnd, in_transit, rtt, flow_blocked, poll_deficit
                );
            }
            if poll_deficit > 0 {
                send_poll_queries(
                    cnx,
                    &udp,
                    config,
                    &mut local_addr_storage,
                    &mut dns_id,
                    &mut poll_deficit,
                    &mut inflight_poll_ids,
                    &mut send_buf,
                    &mut debug,
                )
                .await?;
            }
            inflight_packets = inflight_packet_estimate(cnx, mtu);
        } else if pending_polls > 0 {
            send_poll_queries(
                cnx,
                &udp,
                config,
                &mut local_addr_storage,
                &mut dns_id,
                &mut pending_polls,
                &mut inflight_poll_ids,
                &mut send_buf,
                &mut debug,
            )
            .await?;
        }

        let report_time = unsafe { picoquic_current_time() };
        let streams_len = unsafe { (*state_ptr).streams_len() };
        let (enqueued_bytes, last_enqueue_at) = unsafe { (*state_ptr).debug_snapshot() };
        debug.enqueued_bytes = enqueued_bytes;
        debug.last_enqueue_at = last_enqueue_at;
        let pending_for_debug = if config.authoritative {
            pacing_snapshot
                .map(|snapshot| snapshot.target_inflight.saturating_sub(inflight_packets))
                .unwrap_or(0)
        } else {
            pending_polls
        };
        maybe_report_debug(
            &mut debug,
            report_time,
            streams_len,
            pending_for_debug,
            inflight_polls,
            pacing_snapshot,
        );
    }

    unsafe {
        picoquic_close(cnx, 0);
    }

    Ok(0)
}

fn compute_mtu(domain_len: usize) -> Result<u32, ClientError> {
    if domain_len >= 240 {
        return Err(ClientError::new(
            "Domain name is too long for DNS transport",
        ));
    }
    let mtu = ((240.0 - domain_len as f64) / 1.6) as u32;
    if mtu == 0 {
        return Err(ClientError::new(
            "MTU computed to zero; check domain length",
        ));
    }
    Ok(mtu)
}

async fn bind_udp_socket() -> Result<TokioUdpSocket, ClientError> {
    let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
    TokioUdpSocket::bind(bind_addr).await.map_err(map_io)
}

fn map_io(err: std::io::Error) -> ClientError {
    ClientError::new(err.to_string())
}
