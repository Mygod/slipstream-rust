use slipstream_core::{
    resolve_host_port,
    tcp::{stream_read_limit_chunks, stream_write_buffer_bytes, tcp_send_buffer_bytes},
    HostPort,
};
use slipstream_dns::{build_qname, decode_response, encode_query, QueryParams, CLASS_IN, RR_TXT};
use slipstream_ffi::{
    configure_quic,
    picoquic::{
        get_bytes_in_transit, get_cwin, get_pacing_rate, get_rtt, picoquic_add_to_stream,
        picoquic_call_back_event_t, picoquic_close, picoquic_cnx_t, picoquic_connection_id_t,
        picoquic_create, picoquic_create_client_cnx, picoquic_current_time,
        picoquic_disable_keep_alive, picoquic_enable_keep_alive, picoquic_get_next_local_stream_id,
        picoquic_get_next_wake_delay, picoquic_get_path_addr, picoquic_incoming_packet_ex,
        picoquic_mark_active_stream, picoquic_prepare_next_packet_ex, picoquic_prepare_packet_ex,
        picoquic_probe_new_path_ex, picoquic_provide_stream_data_buffer, picoquic_quic_t,
        picoquic_reset_stream, picoquic_set_callback, picoquic_set_max_data_control,
        picoquic_stream_data_consumed, slipstream_disable_ack_delay, slipstream_has_ready_stream,
        slipstream_is_flow_blocked, slipstream_request_poll, PICOQUIC_CONNECTION_ID_MAX_SIZE,
        PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX, PICOQUIC_PACKET_LOOP_SEND_MAX,
    },
    socket_addr_to_storage, ClientConfig, QuicGuard, SLIPSTREAM_FILE_CANCEL_ERROR,
    SLIPSTREAM_INTERNAL_ERROR,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
};
use tokio::sync::{mpsc, Notify};
use tokio::time::sleep;

const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const SLIPSTREAM_SNI: &str = "test.example.com";
const DNS_WAKE_DELAY_MAX_US: i64 = 10_000_000;
const DNS_POLL_SLICE_US: u64 = 50_000;
const PATH_PROBE_INITIAL_DELAY_US: u64 = 250_000;
const PATH_PROBE_MAX_DELAY_US: u64 = 10_000_000;
const DEBUG_REPORT_INTERVAL_US: u64 = 1_000_000;
const STREAM_READ_CHUNK_BYTES: usize = 4096;
const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
const CLIENT_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;
const MAX_POLL_BURST: usize = PICOQUIC_PACKET_LOOP_RECV_MAX;
const AUTHORITATIVE_LOOP_MULTIPLIER: usize = 4;
const AUTHORITATIVE_MAX_DATA_MULTIPLIER: usize = 4;
const AUTHORITATIVE_POLL_TIMEOUT_US: u64 = 5_000_000; // 5s idle poll cutoff.
                                                      // Pacing gain tuning for the poll-based pacing loop.
const PACING_GAIN_BASE: f64 = 1.0;
const PACING_GAIN_PROBE: f64 = 1.25;
const PACING_GAIN_EPSILON: f64 = 0.05;

#[derive(Debug)]
pub struct ClientError {
    message: String,
}

impl ClientError {
    fn new(message: impl Into<String>) -> Self {
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

#[derive(Clone)]
struct ResolverAddr {
    addr: SocketAddr,
    storage: libc::sockaddr_storage,
    added: bool,
    probe_attempts: u32,
    next_probe_at: u64,
}

struct ClientState {
    ready: bool,
    closing: bool,
    streams: HashMap<u64, ClientStream>,
    command_tx: mpsc::UnboundedSender<Command>,
    data_notify: Arc<Notify>,
    authoritative: bool,
    debug_streams: bool,
    debug_enqueued_bytes: u64,
    debug_last_enqueue_at: u64,
}

struct ClientStream {
    write_tx: mpsc::UnboundedSender<StreamWrite>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    queued_bytes: usize,
    rx_bytes: u64,
    tx_bytes: u64,
    consumed_offset: u64,
    fin_offset: Option<u64>,
    fin_enqueued: bool,
}

enum StreamWrite {
    Data(Vec<u8>),
    Fin,
}

struct DebugMetrics {
    enabled: bool,
    last_report_at: u64,
    dns_responses: u64,
    zero_send_loops: u64,
    zero_send_with_streams: u64,
    enqueued_bytes: u64,
    send_packets: u64,
    send_bytes: u64,
    polls_sent: u64,
    last_enqueue_at: u64,
    last_report_dns: u64,
    last_report_zero: u64,
    last_report_zero_streams: u64,
    last_report_enqueued: u64,
    last_report_send_packets: u64,
    last_report_send_bytes: u64,
    last_report_polls: u64,
}

impl DebugMetrics {
    fn new(enabled: bool) -> Self {
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

#[derive(Clone, Copy, Debug, Default)]
struct PacingBudgetSnapshot {
    pacing_rate: u64,
    qps: f64,
    gain: f64,
    target_inflight: usize,
}

struct PacingPollBudget {
    payload_bytes: f64,
    mtu: u32,
    last_pacing_rate: u64,
}

impl PacingPollBudget {
    fn new(mtu: u32) -> Self {
        debug_assert!(mtu > 0, "PacingPollBudget::new expects MTU > 0");
        Self {
            payload_bytes: mtu.max(1) as f64,
            mtu,
            last_pacing_rate: 0,
        }
    }

    fn target_inflight(
        &mut self,
        cnx: *mut picoquic_cnx_t,
        rtt_proxy_us: u64,
    ) -> PacingBudgetSnapshot {
        let pacing_rate = unsafe { get_pacing_rate(cnx) };
        let rtt_seconds = (self.derive_rtt_us(cnx, rtt_proxy_us) as f64) / 1_000_000.0;
        if pacing_rate == 0 {
            let target_inflight = cwnd_target_polls(cnx, self.mtu);
            let qps = target_inflight as f64 / rtt_seconds;
            self.last_pacing_rate = 0;
            return PacingBudgetSnapshot {
                pacing_rate,
                qps,
                gain: PACING_GAIN_BASE,
                target_inflight,
            };
        }

        let gain = self.next_gain(pacing_rate);
        let qps = (pacing_rate as f64 / self.payload_bytes) * gain;
        let target_inflight = (qps * rtt_seconds).ceil().min(usize::MAX as f64) as usize;

        PacingBudgetSnapshot {
            pacing_rate,
            qps,
            gain,
            target_inflight,
        }
    }

    fn derive_rtt_us(&self, cnx: *mut picoquic_cnx_t, rtt_proxy_us: u64) -> u64 {
        let smoothed = unsafe { get_rtt(cnx) };
        let candidate = if smoothed > 0 { smoothed } else { rtt_proxy_us };
        // Clamp to 1us to avoid divide-by-zero when RTT is unknown.
        candidate.max(1)
    }

    fn next_gain(&mut self, pacing_rate: u64) -> f64 {
        let gain =
            if pacing_rate as f64 > (self.last_pacing_rate as f64) * (1.0 + PACING_GAIN_EPSILON) {
                PACING_GAIN_PROBE
            } else {
                PACING_GAIN_BASE
            };
        self.last_pacing_rate = pacing_rate;
        gain
    }
}

enum Command {
    NewStream(TokioTcpStream),
    StreamData { stream_id: u64, data: Vec<u8> },
    StreamClosed { stream_id: u64 },
    StreamReadError { stream_id: u64 },
    StreamWriteError { stream_id: u64 },
    StreamWriteDrained { stream_id: u64, bytes: usize },
}

pub async fn run_client(config: &ClientConfig<'_>) -> Result<i32, ClientError> {
    let domain_len = config.domain.len();
    let mtu = compute_mtu(domain_len)?;
    let mut pacing_budget = PacingPollBudget::new(mtu);
    let mut resolvers = resolve_resolvers(config.resolvers)?;
    if resolvers.is_empty() {
        return Err(ClientError::new("At least one resolver is required"));
    }

    let udp = bind_udp_socket(&resolvers[0].addr).await?;
    let mut local_addr_storage = socket_addr_to_storage(udp.local_addr().map_err(map_io)?);

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let debug_streams = config.debug_streams;
    let listener = TokioTcpListener::bind(("0.0.0.0", config.tcp_listen_port))
        .await
        .map_err(map_io)?;
    spawn_acceptor(listener, command_tx.clone());
    eprintln!("Listening on TCP port {}", config.tcp_listen_port);

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ClientError::new("ALPN contains an unexpected null byte"))?;
    let sni = CString::new(SLIPSTREAM_SNI)
        .map_err(|_| ClientError::new("SNI contains an unexpected null byte"))?;
    let cc_algo = CString::new(config.congestion_control)
        .map_err(|_| ClientError::new("Congestion control contains an unexpected null byte"))?;

    let mut state = Box::new(ClientState {
        ready: false,
        closing: false,
        streams: HashMap::new(),
        command_tx: command_tx.clone(),
        data_notify: data_notify.clone(),
        authoritative: config.authoritative,
        debug_streams,
        debug_enqueued_bytes: 0,
        debug_last_enqueue_at: 0,
    });
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
    if config.authoritative {
        let max_data =
            stream_write_buffer_bytes().saturating_mul(AUTHORITATIVE_MAX_DATA_MULTIPLIER);
        unsafe {
            picoquic_set_max_data_control(quic, max_data as u64);
        }
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
        eprintln!("Warning: GSO is not implemented in the Rust client loop yet.");
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
        let closing = unsafe { (*state_ptr).closing };
        if closing {
            break;
        }

        let ready = unsafe { (*state_ptr).ready };
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
        let streams_len_for_sleep = unsafe { (*state_ptr).streams.len() };
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
                let streams_len = unsafe { (*state_ptr).streams.len() };
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
            local_addr_storage = addr_from;
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
                eprintln!(
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
        let streams_len = unsafe { (*state_ptr).streams.len() };
        let (enqueued_bytes, last_enqueue_at) = unsafe {
            let state = &*state_ptr;
            (state.debug_enqueued_bytes, state.debug_last_enqueue_at)
        };
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

unsafe extern "C" fn client_callback(
    cnx: *mut picoquic_cnx_t,
    stream_id: u64,
    bytes: *mut u8,
    length: libc::size_t,
    fin_or_event: picoquic_call_back_event_t,
    callback_ctx: *mut std::ffi::c_void,
    _stream_ctx: *mut std::ffi::c_void,
) -> libc::c_int {
    if callback_ctx.is_null() {
        return 0;
    }
    let state = &mut *(callback_ctx as *mut ClientState);

    match fin_or_event {
        picoquic_call_back_event_t::picoquic_callback_ready => {
            state.ready = true;
            if state.authoritative {
                unsafe {
                    slipstream_disable_ack_delay(cnx);
                }
            }
            eprintln!("Connection ready");
        }
        picoquic_call_back_event_t::picoquic_callback_stream_data
        | picoquic_call_back_event_t::picoquic_callback_stream_fin => {
            let fin = matches!(
                fin_or_event,
                picoquic_call_back_event_t::picoquic_callback_stream_fin
            );
            let data = if length > 0 && !bytes.is_null() {
                unsafe { std::slice::from_raw_parts(bytes as *const u8, length) }
            } else {
                &[]
            };
            handle_stream_data(cnx, state, stream_id, fin, data);
        }
        picoquic_call_back_event_t::picoquic_callback_stream_reset
        | picoquic_call_back_event_t::picoquic_callback_stop_sending => {
            let reason = match fin_or_event {
                picoquic_call_back_event_t::picoquic_callback_stream_reset => "stream_reset",
                picoquic_call_back_event_t::picoquic_callback_stop_sending => "stop_sending",
                _ => "unknown",
            };
            if let Some(stream) = state.streams.remove(&stream_id) {
                eprintln!(
                    "stream {}: reset event={} rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?} fin_enqueued={}",
                    stream_id,
                    reason,
                    stream.rx_bytes,
                    stream.tx_bytes,
                    stream.queued_bytes,
                    stream.consumed_offset,
                    stream.fin_offset,
                    stream.fin_enqueued
                );
            } else {
                eprintln!(
                    "stream {}: reset event={} (unknown stream)",
                    stream_id, reason
                );
            }
            let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        picoquic_call_back_event_t::picoquic_callback_close
        | picoquic_call_back_event_t::picoquic_callback_application_close
        | picoquic_call_back_event_t::picoquic_callback_stateless_reset => {
            state.closing = true;
            eprintln!("Connection closed");
        }
        picoquic_call_back_event_t::picoquic_callback_prepare_to_send => {
            if !bytes.is_null() {
                let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, 0);
            }
        }
        _ => {}
    }

    0
}

fn handle_stream_data(
    cnx: *mut picoquic_cnx_t,
    state: &mut ClientState,
    stream_id: u64,
    fin: bool,
    data: &[u8],
) {
    let debug_streams = state.debug_streams;
    let mut reset_stream = false;
    let mut remove_stream = false;

    {
        let Some(stream) = state.streams.get_mut(&stream_id) else {
            eprintln!(
                "stream {}: data for unknown stream len={} fin={}",
                stream_id,
                data.len(),
                fin
            );
            unsafe {
                let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
            }
            return;
        };

        if !data.is_empty() {
            // Backpressure is enforced via connection-level max_data, not per-stream buffer caps.
            stream.rx_bytes = stream.rx_bytes.saturating_add(data.len() as u64);
            if stream
                .write_tx
                .send(StreamWrite::Data(data.to_vec()))
                .is_err()
            {
                eprintln!(
                    "stream {}: tcp write channel closed queued={} rx_bytes={} tx_bytes={}",
                    stream_id, stream.queued_bytes, stream.rx_bytes, stream.tx_bytes
                );
                reset_stream = true;
            } else {
                stream.queued_bytes = stream.queued_bytes.saturating_add(data.len());
            }
        }

        if fin {
            if stream.fin_offset.is_none() {
                stream.fin_offset = Some(stream.rx_bytes);
            }
            stream.data_rx = None;
            if !stream.fin_enqueued {
                if stream.write_tx.send(StreamWrite::Fin).is_err() {
                    eprintln!(
                        "stream {}: tcp write channel closed on fin queued={} rx_bytes={} tx_bytes={}",
                        stream_id,
                        stream.queued_bytes,
                        stream.rx_bytes,
                        stream.tx_bytes
                    );
                    reset_stream = true;
                } else {
                    stream.fin_enqueued = true;
                }
            }
        }

        if !reset_stream && stream.fin_enqueued && stream.queued_bytes == 0 {
            remove_stream = true;
        }
    }

    if reset_stream {
        if debug_streams {
            eprintln!("stream {}: resetting", stream_id);
        }
        unsafe {
            let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        state.streams.remove(&stream_id);
    } else if remove_stream {
        if debug_streams {
            eprintln!("stream {}: finished", stream_id);
        }
        state.streams.remove(&stream_id);
    }
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

fn expire_inflight_polls(inflight_poll_ids: &mut HashMap<u16, u64>, now: u64) {
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

fn cwnd_target_polls(cnx: *mut picoquic_cnx_t, mtu: u32) -> usize {
    debug_assert!(mtu > 0, "mtu must be > 0");
    let mtu = mtu as u64;
    if mtu == 0 {
        return 0;
    }
    let cwnd = unsafe { get_cwin(cnx) };
    let target = cwnd.saturating_add(mtu - 1) / mtu;
    usize::try_from(target).unwrap_or(usize::MAX)
}

fn inflight_packet_estimate(cnx: *mut picoquic_cnx_t, mtu: u32) -> usize {
    debug_assert!(mtu > 0, "mtu must be > 0");
    let mtu = mtu as u64;
    if mtu == 0 {
        return 0;
    }
    let inflight = unsafe { get_bytes_in_transit(cnx) };
    let packets = inflight.saturating_add(mtu - 1) / mtu;
    if packets > usize::MAX as u64 {
        usize::MAX
    } else {
        packets as usize
    }
}

fn resolve_resolvers(resolvers: &[HostPort]) -> Result<Vec<ResolverAddr>, ClientError> {
    let mut resolved = Vec::with_capacity(resolvers.len());
    for resolver in resolvers {
        let addr = resolve_host_port(resolver).map_err(|err| ClientError::new(err.to_string()))?;
        resolved.push(ResolverAddr {
            addr,
            storage: socket_addr_to_storage(addr),
            added: false,
            probe_attempts: 0,
            next_probe_at: 0,
        });
    }
    Ok(resolved)
}

async fn bind_udp_socket(addr: &SocketAddr) -> Result<TokioUdpSocket, ClientError> {
    let bind_addr = match addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    TokioUdpSocket::bind(bind_addr).await.map_err(map_io)
}

fn spawn_acceptor(listener: TokioTcpListener, command_tx: mpsc::UnboundedSender<Command>) {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    if command_tx.send(Command::NewStream(stream)).is_err() {
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
}

fn drain_commands(
    cnx: *mut picoquic_cnx_t,
    state_ptr: *mut ClientState,
    command_rx: &mut mpsc::UnboundedReceiver<Command>,
) {
    while let Ok(command) = command_rx.try_recv() {
        handle_command(cnx, state_ptr, command);
    }
}

fn drain_stream_data(cnx: *mut picoquic_cnx_t, state_ptr: *mut ClientState) {
    let mut pending = Vec::new();
    let mut closed_streams = Vec::new();
    {
        let state = unsafe { &mut *state_ptr };
        slipstream_core::drain_stream_data!(state.streams, data_rx, pending, closed_streams);
    }
    for (stream_id, data) in pending {
        handle_command(cnx, state_ptr, Command::StreamData { stream_id, data });
    }
    for stream_id in closed_streams {
        handle_command(cnx, state_ptr, Command::StreamClosed { stream_id });
    }
}

fn handle_command(cnx: *mut picoquic_cnx_t, state_ptr: *mut ClientState, command: Command) {
    let state = unsafe { &mut *state_ptr };
    match command {
        Command::NewStream(stream) => {
            let _ = stream.set_nodelay(true);
            let read_limit = stream_read_limit_chunks(
                &stream,
                DEFAULT_TCP_RCVBUF_BYTES,
                STREAM_READ_CHUNK_BYTES,
            );
            let (data_tx, data_rx) = mpsc::channel(read_limit);
            let data_notify = state.data_notify.clone();
            let stream_id = unsafe { picoquic_get_next_local_stream_id(cnx, 0) };
            let send_buffer_bytes = tcp_send_buffer_bytes(&stream)
                .filter(|bytes| *bytes > 0)
                .unwrap_or(CLIENT_WRITE_COALESCE_DEFAULT_BYTES);
            let (read_half, write_half) = stream.into_split();
            let (write_tx, write_rx) = mpsc::unbounded_channel();
            let command_tx = state.command_tx.clone();
            spawn_client_reader(
                stream_id,
                read_half,
                command_tx.clone(),
                data_tx,
                data_notify,
            );
            spawn_client_writer(
                stream_id,
                write_half,
                write_rx,
                command_tx,
                send_buffer_bytes,
            );
            state.streams.insert(
                stream_id,
                ClientStream {
                    write_tx,
                    data_rx: Some(data_rx),
                    queued_bytes: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    consumed_offset: 0,
                    fin_offset: None,
                    fin_enqueued: false,
                },
            );
            let _ = unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
            if state.debug_streams {
                eprintln!("stream {}: accepted", stream_id);
            } else {
                eprintln!("Accepted TCP stream {}", stream_id);
            }
        }
        Command::StreamData { stream_id, data } => {
            let ret =
                unsafe { picoquic_add_to_stream(cnx, stream_id, data.as_ptr(), data.len(), 0) };
            if ret < 0 {
                eprintln!(
                    "stream {}: add_to_stream failed ret={} chunk_len={}",
                    stream_id,
                    ret,
                    data.len()
                );
                let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                state.streams.remove(&stream_id);
            } else if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.tx_bytes = stream.tx_bytes.saturating_add(data.len() as u64);
                let now = unsafe { picoquic_current_time() };
                state.debug_enqueued_bytes =
                    state.debug_enqueued_bytes.saturating_add(data.len() as u64);
                state.debug_last_enqueue_at = now;
            }
        }
        Command::StreamClosed { stream_id } => {
            let ret = unsafe { picoquic_add_to_stream(cnx, stream_id, std::ptr::null(), 0, 1) };
            if ret < 0 {
                eprintln!(
                    "stream {}: add_to_stream(fin) failed ret={}",
                    stream_id, ret
                );
            }
        }
        Command::StreamReadError { stream_id } => {
            if let Some(stream) = state.streams.remove(&stream_id) {
                eprintln!(
                    "stream {}: tcp read error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.rx_bytes,
                    stream.tx_bytes,
                    stream.queued_bytes,
                    stream.consumed_offset,
                    stream.fin_offset
                );
            } else {
                eprintln!("stream {}: tcp read error (unknown stream)", stream_id);
            }
            let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
        }
        Command::StreamWriteError { stream_id } => {
            if let Some(stream) = state.streams.remove(&stream_id) {
                eprintln!(
                    "stream {}: tcp write error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.rx_bytes,
                    stream.tx_bytes,
                    stream.queued_bytes,
                    stream.consumed_offset,
                    stream.fin_offset
                );
            } else {
                eprintln!("stream {}: tcp write error (unknown stream)", stream_id);
            }
            let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
        }
        Command::StreamWriteDrained { stream_id, bytes } => {
            let mut remove_stream = false;
            let mut reset_stream = false;
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.queued_bytes = stream.queued_bytes.saturating_sub(bytes);
                stream.consumed_offset = stream.consumed_offset.saturating_add(bytes as u64);
                if let Some(fin_offset) = stream.fin_offset {
                    if stream.consumed_offset > fin_offset {
                        stream.consumed_offset = fin_offset;
                    }
                }
                let ret = unsafe {
                    picoquic_stream_data_consumed(cnx, stream_id, stream.consumed_offset)
                };
                if ret < 0 {
                    eprintln!(
                        "stream {}: stream_data_consumed failed ret={} consumed_offset={}",
                        stream_id, ret, stream.consumed_offset
                    );
                    reset_stream = true;
                } else if stream.fin_enqueued && stream.queued_bytes == 0 {
                    remove_stream = true;
                }
            }
            if reset_stream {
                let _ =
                    unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR) };
                state.streams.remove(&stream_id);
            } else if remove_stream {
                state.streams.remove(&stream_id);
            }
        }
    }
}

fn spawn_client_reader(
    stream_id: u64,
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    command_tx: mpsc::UnboundedSender<Command>,
    data_tx: mpsc::Sender<Vec<u8>>,
    data_notify: Arc<Notify>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; STREAM_READ_CHUNK_BYTES];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    if data_tx.send(data).await.is_err() {
                        break;
                    }
                    data_notify.notify_one();
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(_) => {
                    let _ = command_tx.send(Command::StreamReadError { stream_id });
                    break;
                }
            }
        }
        drop(data_tx);
        data_notify.notify_one();
    });
}

fn spawn_client_writer(
    stream_id: u64,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    command_tx: mpsc::UnboundedSender<Command>,
    coalesce_max_bytes: usize,
) {
    tokio::spawn(async move {
        let coalesce_max_bytes = coalesce_max_bytes.max(1);
        while let Some(msg) = write_rx.recv().await {
            match msg {
                StreamWrite::Data(data) => {
                    let mut buffer = data;
                    let mut saw_fin = false;
                    while buffer.len() < coalesce_max_bytes {
                        match write_rx.try_recv() {
                            Ok(StreamWrite::Data(more)) => {
                                buffer.extend_from_slice(&more);
                                if buffer.len() >= coalesce_max_bytes {
                                    break;
                                }
                            }
                            Ok(StreamWrite::Fin) => {
                                saw_fin = true;
                                break;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                saw_fin = true;
                                break;
                            }
                        }
                    }
                    let len = buffer.len();
                    if write_half.write_all(&buffer).await.is_err() {
                        let _ = command_tx.send(Command::StreamWriteError { stream_id });
                        return;
                    }
                    let _ = command_tx.send(Command::StreamWriteDrained {
                        stream_id,
                        bytes: len,
                    });
                    if saw_fin {
                        let _ = write_half.shutdown().await;
                        return;
                    }
                }
                StreamWrite::Fin => {
                    let _ = write_half.shutdown().await;
                    return;
                }
            }
        }
        let _ = write_half.shutdown().await;
    });
}

struct DnsResponseContext<'a> {
    quic: *mut picoquic_quic_t,
    local_addr_storage: &'a libc::sockaddr_storage,
    pending_polls: &'a mut usize,
    inflight_poll_ids: &'a mut HashMap<u16, u64>,
    debug: &'a mut DebugMetrics,
    authoritative: bool,
}

fn handle_dns_response(
    buf: &[u8],
    peer: SocketAddr,
    ctx: &mut DnsResponseContext<'_>,
) -> Result<(), ClientError> {
    if let Some(response_id) = dns_response_id(buf) {
        ctx.debug.dns_responses = ctx.debug.dns_responses.saturating_add(1);
        if ctx.authoritative {
            ctx.inflight_poll_ids.remove(&response_id);
        }
    }

    if let Some(payload) = decode_response(buf) {
        let mut peer_storage = socket_addr_to_storage(peer);
        let mut local_storage = unsafe { std::ptr::read(ctx.local_addr_storage) };
        let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
        let mut first_path: libc::c_int = 0;
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
        if !ctx.authoritative {
            *ctx.pending_polls = ctx.pending_polls.saturating_add(1).min(MAX_POLL_BURST);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_poll_queries(
    cnx: *mut picoquic_cnx_t,
    udp: &TokioUdpSocket,
    config: &ClientConfig<'_>,
    local_addr_storage: &mut libc::sockaddr_storage,
    dns_id: &mut u16,
    pending_polls: &mut usize,
    inflight_poll_ids: &mut HashMap<u16, u64>,
    send_buf: &mut [u8],
    debug: &mut DebugMetrics,
) -> Result<(), ClientError> {
    let mut remaining = *pending_polls;
    *pending_polls = 0;

    while remaining > 0 {
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
                -1,
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
            *pending_polls = remaining;
            break;
        }

        remaining -= 1;
        *local_addr_storage = addr_from;
        debug.send_packets = debug.send_packets.saturating_add(1);
        debug.send_bytes = debug.send_bytes.saturating_add(send_length as u64);
        debug.polls_sent = debug.polls_sent.saturating_add(1);

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
        udp.send_to(&packet, dest).await.map_err(map_io)?;
        if config.authoritative {
            inflight_poll_ids.insert(poll_id, current_time);
        }
    }

    Ok(())
}

fn maybe_report_debug(
    debug: &mut DebugMetrics,
    now: u64,
    streams_len: usize,
    pending_polls: usize,
    inflight_polls: usize,
    pacing_snapshot: Option<PacingBudgetSnapshot>,
) {
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
    eprintln!(
        "debug: dns+={} send_pkts+={} send_bytes+={} polls+={} zero_send+={} zero_send_streams+={} streams={} enqueued+={} last_enqueue_ms={} pending_polls={} inflight_polls={}{}",
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

fn add_paths(cnx: *mut picoquic_cnx_t, resolvers: &mut [ResolverAddr]) -> Result<(), ClientError> {
    if resolvers.len() <= 1 {
        return Ok(());
    }

    let mut local_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let ret = unsafe { picoquic_get_path_addr(cnx, 0, 1, &mut local_storage) };
    if ret != 0 {
        return Ok(());
    }
    let now = unsafe { picoquic_current_time() };

    for resolver in resolvers.iter_mut().skip(1) {
        if resolver.added {
            continue;
        }
        if resolver.next_probe_at > now {
            continue;
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
            eprintln!("Added path {}", resolver.addr);
            continue;
        }
        resolver.probe_attempts = resolver.probe_attempts.saturating_add(1);
        let delay = path_probe_backoff(resolver.probe_attempts);
        resolver.next_probe_at = now.saturating_add(delay);
        eprintln!(
            "Failed adding path {} (attempt {}), retrying in {}ms",
            resolver.addr,
            resolver.probe_attempts,
            delay / 1000
        );
    }

    Ok(())
}

fn path_probe_backoff(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(6);
    let delay = PATH_PROBE_INITIAL_DELAY_US.saturating_mul(1u64 << shift);
    delay.min(PATH_PROBE_MAX_DELAY_US)
}

fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> Result<SocketAddr, ClientError> {
    slipstream_ffi::sockaddr_storage_to_socket_addr(storage).map_err(ClientError::new)
}

fn map_io(err: std::io::Error) -> ClientError {
    ClientError::new(err.to_string())
}
