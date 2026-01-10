use slipstream_core::{
    resolve_host_port,
    tcp::{stream_read_limit_chunks, tcp_send_buffer_bytes},
    HostPort,
};
use slipstream_dns::{
    decode_query, encode_response, DecodeQueryError, Question, Rcode, ResponseParams,
};
use slipstream_ffi::picoquic::{
    picoquic_call_back_event_t, picoquic_close, picoquic_close_immediate, picoquic_cnx_t,
    picoquic_create, picoquic_current_time, picoquic_get_first_cnx, picoquic_get_next_cnx,
    picoquic_incoming_packet_ex, picoquic_mark_active_stream, picoquic_prepare_packet_ex,
    picoquic_provide_stream_data_buffer, picoquic_quic_t, picoquic_reset_stream,
    picoquic_stream_data_consumed, slipstream_disable_ack_delay, slipstream_server_cc_algorithm,
    PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX,
};
use slipstream_ffi::{
    configure_quic_with_custom, socket_addr_to_storage, QuicGuard, SLIPSTREAM_FILE_CANCEL_ERROR,
    SLIPSTREAM_INTERNAL_ERROR,
};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;

const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const DNS_MAX_QUERY_SIZE: usize = 512;
const IDLE_SLEEP_MS: u64 = 10;
const QUIC_MTU: u32 = 900;
const STREAM_READ_CHUNK_BYTES: usize = 4096;
const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
const TARGET_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;

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
    pub dns_listen_port: u16,
    pub dns_listen_ipv6: bool,
    pub target_address: HostPort,
    pub cert: String,
    pub key: String,
    pub domain: String,
    pub debug_streams: bool,
    pub debug_commands: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct StreamKey {
    cnx: usize,
    stream_id: u64,
}

enum StreamWrite {
    Data(Vec<u8>),
    Fin,
}

#[allow(clippy::enum_variant_names)]
enum Command {
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

struct ServerState {
    target_addr: SocketAddr,
    streams: HashMap<StreamKey, ServerStream>,
    command_tx: mpsc::UnboundedSender<Command>,
    debug_streams: bool,
    debug_commands: bool,
    command_counts: CommandCounts,
    last_command_report: Instant,
}

#[derive(Default)]
struct CommandCounts {
    stream_connected: u64,
    stream_connect_error: u64,
    stream_closed: u64,
    stream_readable: u64,
    stream_read_error: u64,
    stream_write_error: u64,
    stream_write_drained: u64,
}

impl CommandCounts {
    fn bump(&mut self, command: &Command) {
        match command {
            Command::StreamConnected { .. } => self.stream_connected += 1,
            Command::StreamConnectError { .. } => self.stream_connect_error += 1,
            Command::StreamClosed { .. } => self.stream_closed += 1,
            Command::StreamReadable { .. } => self.stream_readable += 1,
            Command::StreamReadError { .. } => self.stream_read_error += 1,
            Command::StreamWriteError { .. } => self.stream_write_error += 1,
            Command::StreamWriteDrained { .. } => self.stream_write_drained += 1,
        }
    }

    fn total(&self) -> u64 {
        self.stream_connected
            + self.stream_connect_error
            + self.stream_closed
            + self.stream_readable
            + self.stream_read_error
            + self.stream_write_error
            + self.stream_write_drained
    }

    fn reset(&mut self) {
        *self = CommandCounts::default();
    }
}

struct ServerStream {
    write_tx: Option<mpsc::UnboundedSender<StreamWrite>>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    send_pending: Option<Arc<AtomicBool>>,
    send_stash: Option<Vec<u8>>,
    queued_bytes: usize,
    shutdown_tx: watch::Sender<bool>,
    rx_bytes: u64,
    consumed_offset: u64,
    fin_offset: Option<u64>,
    tx_bytes: u64,
    target_fin_pending: bool,
    close_after_flush: bool,
    pending_data: VecDeque<Vec<u8>>,
    pending_fin: bool,
    fin_enqueued: bool,
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
    let mut state = Box::new(ServerState {
        target_addr,
        streams: HashMap::new(),
        command_tx,
        debug_streams,
        debug_commands,
        command_counts: CommandCounts::default(),
        last_command_report: Instant::now(),
    });
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

    let udp = bind_udp_socket(config.dns_listen_port, config.dns_listen_ipv6).await?;
    let local_addr_storage = socket_addr_to_storage(udp.local_addr().map_err(map_io)?);

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
                let (size, peer) = recv.map_err(map_io)?;
                let loop_time = unsafe { picoquic_current_time() };
                if let Some(slot) = decode_slot(
                    &recv_buf[..size],
                    peer,
                    &config.domain,
                    quic,
                    loop_time,
                    &local_addr_storage,
                    config.dns_listen_ipv6,
                )? {
                    slots.push(slot);
                }
                for _ in 1..PICOQUIC_PACKET_LOOP_RECV_MAX {
                    match udp.try_recv_from(&mut recv_buf) {
                        Ok((size, peer)) => {
                            if let Some(slot) = decode_slot(
                                &recv_buf[..size],
                                peer,
                                &config.domain,
                                quic,
                                loop_time,
                                &local_addr_storage,
                                config.dns_listen_ipv6,
                            )? {
                                slots.push(slot);
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(err) => return Err(map_io(err)),
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
            udp.send_to(&response, slot.peer).await.map_err(map_io)?;
        }
    }

    Ok(0)
}

fn decode_slot(
    packet: &[u8],
    peer: SocketAddr,
    domain: &str,
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &libc::sockaddr_storage,
    listen_ipv6: bool,
) -> Result<Option<Slot>, ServerError> {
    match decode_query(packet, domain) {
        Ok(query) => {
            let mut peer_storage = dummy_sockaddr_storage(listen_ipv6);
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

unsafe extern "C" fn server_callback(
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
    let state = &mut *(callback_ctx as *mut ServerState);

    match fin_or_event {
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
            let key = StreamKey {
                cnx: cnx as usize,
                stream_id,
            };
            if let Some(stream) = shutdown_stream(state, key) {
                eprintln!(
                    "stream {:?}: reset event={} tx_bytes={} rx_bytes={} consumed_offset={} queued={} pending_chunks={} pending_fin={} fin_enqueued={} fin_offset={:?} target_fin_pending={} close_after_flush={}",
                    key.stream_id,
                    reason,
                    stream.tx_bytes,
                    stream.rx_bytes,
                    stream.consumed_offset,
                    stream.queued_bytes,
                    stream.pending_data.len(),
                    stream.pending_fin,
                    stream.fin_enqueued,
                    stream.fin_offset,
                    stream.target_fin_pending,
                    stream.close_after_flush
                );
            } else {
                eprintln!(
                    "stream {:?}: reset event={} (unknown stream)",
                    stream_id, reason
                );
            }
            let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        picoquic_call_back_event_t::picoquic_callback_close
        | picoquic_call_back_event_t::picoquic_callback_application_close
        | picoquic_call_back_event_t::picoquic_callback_stateless_reset => {
            remove_connection_streams(state, cnx as usize);
            let _ = picoquic_close(cnx, 0);
        }
        picoquic_call_back_event_t::picoquic_callback_prepare_to_send => {
            if bytes.is_null() {
                return 0;
            }
            let key = StreamKey {
                cnx: cnx as usize,
                stream_id,
            };
            let mut remove_stream = false;
            if let Some(stream) = state.streams.get_mut(&key) {
                let pending_flag = stream
                    .send_pending
                    .as_ref()
                    .map(|flag| flag.load(Ordering::SeqCst))
                    .unwrap_or(false);
                let has_stash = stream
                    .send_stash
                    .as_ref()
                    .is_some_and(|data| !data.is_empty());
                let has_pending = pending_flag || has_stash;

                if length == 0 {
                    let still_active = if has_pending || stream.target_fin_pending {
                        1
                    } else {
                        0
                    };
                    if still_active == 0 {
                        if let Some(flag) = stream.send_pending.as_ref() {
                            flag.store(false, Ordering::SeqCst);
                        }
                    }
                    let _ =
                        picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, still_active);
                    return 0;
                }

                let mut send_data: Option<Vec<u8>> = None;
                if let Some(mut stash) = stream.send_stash.take() {
                    if stash.len() > length {
                        let remainder = stash.split_off(length);
                        stream.send_stash = Some(remainder);
                    }
                    send_data = Some(stash);
                } else if let Some(rx) = stream.data_rx.as_mut() {
                    match rx.try_recv() {
                        Ok(mut data) => {
                            if data.len() > length {
                                let remainder = data.split_off(length);
                                stream.send_stash = Some(remainder);
                            }
                            send_data = Some(data);
                        }
                        Err(mpsc::error::TryRecvError::Empty) => {}
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            stream.data_rx = None;
                            stream.target_fin_pending = true;
                            stream.close_after_flush = true;
                        }
                    }
                }

                if let Some(data) = send_data {
                    let send_len = data.len();
                    let buffer =
                        picoquic_provide_stream_data_buffer(bytes as *mut _, send_len, 0, 1);
                    if buffer.is_null() {
                        if let Some(stream) = shutdown_stream(state, key) {
                            eprintln!(
                                "stream {:?}: provide_stream_data_buffer returned null send_len={} queued={} pending_chunks={} tx_bytes={}",
                                key.stream_id,
                                send_len,
                                stream.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                        } else {
                            eprintln!(
                                "stream {:?}: provide_stream_data_buffer returned null send_len={}",
                                key.stream_id, send_len
                            );
                        }
                        let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                        return 0;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, data.len());
                    }
                    stream.tx_bytes = stream.tx_bytes.saturating_add(data.len() as u64);
                } else if stream.target_fin_pending {
                    stream.target_fin_pending = false;
                    if stream.close_after_flush {
                        remove_stream = true;
                    }
                    if let Some(flag) = stream.send_pending.as_ref() {
                        flag.store(false, Ordering::SeqCst);
                    }
                    let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 1, 0);
                } else {
                    if let Some(flag) = stream.send_pending.as_ref() {
                        flag.store(false, Ordering::SeqCst);
                    }
                    let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, 0);
                }
            } else {
                let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, 0);
            }

            if remove_stream {
                shutdown_stream(state, key);
            }
        }
        _ => {}
    }

    0
}

fn handle_stream_data(
    cnx: *mut picoquic_cnx_t,
    state: &mut ServerState,
    stream_id: u64,
    fin: bool,
    data: &[u8],
) {
    let key = StreamKey {
        cnx: cnx as usize,
        stream_id,
    };
    let debug_streams = state.debug_streams;
    let mut reset_stream = false;

    {
        let stream = state.streams.entry(key).or_insert_with(|| {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            if debug_streams {
                eprintln!("stream {:?}: connecting", key.stream_id);
            }
            spawn_target_connector(
                key,
                state.target_addr,
                state.command_tx.clone(),
                debug_streams,
                shutdown_rx,
            );
            ServerStream {
                write_tx: None,
                data_rx: None,
                send_pending: None,
                send_stash: None,
                queued_bytes: 0,
                shutdown_tx,
                rx_bytes: 0,
                consumed_offset: 0,
                fin_offset: None,
                tx_bytes: 0,
                target_fin_pending: false,
                close_after_flush: false,
                pending_data: VecDeque::new(),
                pending_fin: false,
                fin_enqueued: false,
            }
        });

        if !data.is_empty() {
            // Backpressure is enforced via connection-level max_data, not per-stream buffer caps.
            stream.rx_bytes = stream.rx_bytes.saturating_add(data.len() as u64);
            if let Some(write_tx) = stream.write_tx.as_ref() {
                if write_tx.send(StreamWrite::Data(data.to_vec())).is_err() {
                    reset_stream = true;
                } else {
                    stream.queued_bytes = stream.queued_bytes.saturating_add(data.len());
                }
            } else {
                stream.pending_data.push_back(data.to_vec());
                stream.queued_bytes = stream.queued_bytes.saturating_add(data.len());
            }
        }

        if fin {
            if stream.fin_offset.is_none() {
                stream.fin_offset = Some(stream.rx_bytes);
            }
            if !stream.fin_enqueued {
                if stream.write_tx.is_some() && stream.pending_data.is_empty() {
                    if let Some(write_tx) = stream.write_tx.as_ref() {
                        if write_tx.send(StreamWrite::Fin).is_err() {
                            reset_stream = true;
                        } else {
                            stream.fin_enqueued = true;
                            stream.pending_fin = false;
                        }
                    }
                } else {
                    stream.pending_fin = true;
                }
            }
        }
    }

    if reset_stream {
        if debug_streams {
            eprintln!("stream {:?}: resetting", stream_id);
        }
        shutdown_stream(state, key);
        unsafe {
            let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
        }
    }
}

fn remove_connection_streams(state: &mut ServerState, cnx: usize) {
    let keys: Vec<StreamKey> = state
        .streams
        .keys()
        .filter(|key| key.cnx == cnx)
        .cloned()
        .collect();
    for key in keys {
        shutdown_stream(state, key);
    }
}

fn shutdown_stream(state: &mut ServerState, key: StreamKey) -> Option<ServerStream> {
    if let Some(stream) = state.streams.remove(&key) {
        let _ = stream.shutdown_tx.send(true);
        return Some(stream);
    }
    None
}

fn spawn_target_connector(
    key: StreamKey,
    target_addr: SocketAddr,
    command_tx: mpsc::UnboundedSender<Command>,
    debug_streams: bool,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        if *shutdown_rx.borrow() {
            return;
        }
        let connect = TokioTcpStream::connect(target_addr);
        let stream = tokio::select! {
            _ = shutdown_rx.changed() => {
                return;
            }
            result = connect => result,
        };
        if *shutdown_rx.borrow() {
            return;
        }
        match stream {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let read_limit = stream_read_limit_chunks(
                    &stream,
                    DEFAULT_TCP_RCVBUF_BYTES,
                    STREAM_READ_CHUNK_BYTES,
                );
                let (data_tx, data_rx) = mpsc::channel(read_limit);
                let send_buffer_bytes = tcp_send_buffer_bytes(&stream)
                    .filter(|bytes| *bytes > 0)
                    .unwrap_or(TARGET_WRITE_COALESCE_DEFAULT_BYTES);
                let (read_half, write_half) = stream.into_split();
                let (write_tx, write_rx) = mpsc::unbounded_channel();
                let send_pending = Arc::new(AtomicBool::new(false));
                spawn_target_reader(
                    key,
                    read_half,
                    data_tx,
                    command_tx.clone(),
                    send_pending.clone(),
                    debug_streams,
                    shutdown_rx.clone(),
                );
                spawn_target_writer(
                    key,
                    write_half,
                    write_rx,
                    command_tx.clone(),
                    shutdown_rx,
                    send_buffer_bytes,
                );
                let _ = command_tx.send(Command::StreamConnected {
                    cnx_id: key.cnx,
                    stream_id: key.stream_id,
                    write_tx,
                    data_rx,
                    send_pending,
                });
            }
            Err(err) => {
                eprintln!(
                    "stream {:?}: target connect failed err={} kind={:?}",
                    key.stream_id,
                    err,
                    err.kind()
                );
                let _ = command_tx.send(Command::StreamConnectError {
                    cnx_id: key.cnx,
                    stream_id: key.stream_id,
                });
            }
        }
    });
}

fn spawn_target_reader(
    key: StreamKey,
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    data_tx: mpsc::Sender<Vec<u8>>,
    command_tx: mpsc::UnboundedSender<Command>,
    send_pending: Arc<AtomicBool>,
    debug_streams: bool,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; STREAM_READ_CHUNK_BYTES];
        let mut total = 0u64;
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                read = read_half.read(&mut buf) => {
                    match read {
                        Ok(0) => {
                            if debug_streams {
                                eprintln!(
                                    "stream {:?}: target eof read_bytes={}",
                                    key.stream_id, total
                                );
                            }
                            let _ = command_tx.send(Command::StreamClosed {
                                cnx_id: key.cnx,
                                stream_id: key.stream_id,
                            });
                            break;
                        }
                        Ok(n) => {
                            total = total.saturating_add(n as u64);
                            let data = buf[..n].to_vec();
                            if data_tx.send(data).await.is_err() {
                                break;
                            }
                            if !send_pending.swap(true, Ordering::SeqCst) {
                                let _ = command_tx.send(Command::StreamReadable {
                                    cnx_id: key.cnx,
                                    stream_id: key.stream_id,
                                });
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(err) => {
                            if debug_streams {
                                eprintln!(
                                    "stream {:?}: target read error after {} bytes (kind={:?} err={})",
                                    key.stream_id,
                                    total,
                                    err.kind(),
                                    err
                                );
                            }
                            let _ = command_tx.send(Command::StreamReadError {
                                cnx_id: key.cnx,
                                stream_id: key.stream_id,
                            });
                            break;
                        }
                    }
                }
            }
        }
        drop(data_tx);
    });
}

fn spawn_target_writer(
    key: StreamKey,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    command_tx: mpsc::UnboundedSender<Command>,
    mut shutdown_rx: watch::Receiver<bool>,
    coalesce_max_bytes: usize,
) {
    tokio::spawn(async move {
        let coalesce_max_bytes = coalesce_max_bytes.max(1);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                msg = write_rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
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
                                let _ = command_tx.send(Command::StreamWriteError {
                                    cnx_id: key.cnx,
                                    stream_id: key.stream_id,
                                });
                                return;
                            }
                            let _ = command_tx.send(Command::StreamWriteDrained {
                                cnx_id: key.cnx,
                                stream_id: key.stream_id,
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
            }
        }
        let _ = write_half.shutdown().await;
    });
}

fn drain_commands(state_ptr: *mut ServerState, command_rx: &mut mpsc::UnboundedReceiver<Command>) {
    while let Ok(command) = command_rx.try_recv() {
        handle_command(state_ptr, command);
    }
}

fn handle_command(state_ptr: *mut ServerState, command: Command) {
    let state = unsafe { &mut *state_ptr };
    if state.debug_commands {
        state.command_counts.bump(&command);
    }
    match command {
        Command::StreamConnected {
            cnx_id,
            stream_id,
            write_tx,
            data_rx,
            send_pending,
        } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            let mut reset_stream = false;
            {
                let Some(stream) = state.streams.get_mut(&key) else {
                    return;
                };
                if state.debug_streams {
                    eprintln!("stream {:?}: target connected", stream_id);
                }
                stream.write_tx = Some(write_tx);
                stream.data_rx = Some(data_rx);
                stream.send_pending = Some(send_pending);
                if let Some(write_tx) = stream.write_tx.as_ref() {
                    while let Some(chunk) = stream.pending_data.pop_front() {
                        if write_tx.send(StreamWrite::Data(chunk)).is_err() {
                            eprintln!(
                                "stream {:?}: pending write flush failed queued={} pending_chunks={} tx_bytes={}",
                                stream_id,
                                stream.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                            reset_stream = true;
                            break;
                        }
                    }
                    if !reset_stream && stream.pending_fin && !stream.fin_enqueued {
                        if write_tx.send(StreamWrite::Fin).is_err() {
                            eprintln!(
                                "stream {:?}: pending fin flush failed queued={} pending_chunks={} tx_bytes={}",
                                stream_id,
                                stream.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                            reset_stream = true;
                        } else {
                            stream.fin_enqueued = true;
                            stream.pending_fin = false;
                        }
                    }
                }
            }
            if reset_stream {
                let cnx = cnx_id as *mut picoquic_cnx_t;
                shutdown_stream(state, key);
                let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
            }
        }
        Command::StreamConnectError { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if shutdown_stream(state, key).is_some() {
                let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                eprintln!("stream {:?}: target connect failed", stream_id);
            }
        }
        Command::StreamClosed { cnx_id, stream_id } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if let Some(stream) = state.streams.get_mut(&key) {
                stream.target_fin_pending = true;
                stream.close_after_flush = true;
                if state.debug_streams {
                    eprintln!(
                        "stream {:?}: closed by target tx_bytes={}",
                        stream_id, stream.tx_bytes
                    );
                }
                if let Some(pending) = stream.send_pending.as_ref() {
                    let was_pending = pending.swap(true, Ordering::SeqCst);
                    if !was_pending {
                        let cnx = cnx_id as *mut picoquic_cnx_t;
                        let ret = unsafe {
                            picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut())
                        };
                        if ret != 0 && state.debug_streams {
                            eprintln!(
                                "stream {:?}: mark_active_stream fin failed ret={}",
                                stream_id, ret
                            );
                        }
                    }
                }
            }
        }
        Command::StreamReadable { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let ret =
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
            if ret != 0 && state.debug_streams {
                eprintln!(
                    "stream {:?}: mark_active_stream readable failed ret={}",
                    stream_id, ret
                );
            }
        }
        Command::StreamReadError { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if let Some(stream) = shutdown_stream(state, key) {
                eprintln!(
                    "stream {:?}: target read error tx_bytes={} rx_bytes={} consumed_offset={} queued={} fin_offset={:?}",
                    stream_id,
                    stream.tx_bytes,
                    stream.rx_bytes,
                    stream.consumed_offset,
                    stream.queued_bytes,
                    stream.fin_offset
                );
                let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
            }
        }
        Command::StreamWriteError { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if let Some(stream) = shutdown_stream(state, key) {
                eprintln!(
                    "stream {:?}: target write failed tx_bytes={} rx_bytes={} consumed_offset={} queued={} fin_offset={:?}",
                    stream_id,
                    stream.tx_bytes,
                    stream.rx_bytes,
                    stream.consumed_offset,
                    stream.queued_bytes,
                    stream.fin_offset
                );
                let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
            }
        }
        Command::StreamWriteDrained {
            cnx_id,
            stream_id,
            bytes,
        } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            let mut reset_stream = false;
            if let Some(stream) = state.streams.get_mut(&key) {
                stream.queued_bytes = stream.queued_bytes.saturating_sub(bytes);
                stream.consumed_offset = stream.consumed_offset.saturating_add(bytes as u64);
                if let Some(fin_offset) = stream.fin_offset {
                    if stream.consumed_offset > fin_offset {
                        stream.consumed_offset = fin_offset;
                    }
                }
                let ret = unsafe {
                    picoquic_stream_data_consumed(
                        cnx_id as *mut picoquic_cnx_t,
                        stream_id,
                        stream.consumed_offset,
                    )
                };
                if ret < 0 {
                    eprintln!(
                        "stream {:?}: stream_data_consumed failed ret={} consumed_offset={}",
                        stream_id, ret, stream.consumed_offset
                    );
                    reset_stream = true;
                }
            }
            if reset_stream {
                shutdown_stream(state, key);
                let _ = unsafe {
                    picoquic_reset_stream(
                        cnx_id as *mut picoquic_cnx_t,
                        stream_id,
                        SLIPSTREAM_INTERNAL_ERROR,
                    )
                };
            }
        }
    }
}

fn maybe_report_command_stats(state_ptr: *mut ServerState) {
    let state = unsafe { &mut *state_ptr };
    if !state.debug_commands {
        return;
    }
    let now = Instant::now();
    if now.duration_since(state.last_command_report) < Duration::from_secs(1) {
        return;
    }
    let total = state.command_counts.total();
    if total > 0 {
        eprintln!(
            "debug: commands total={} connected={} connect_err={} closed={} readable={} read_err={} write_err={} write_drained={}",
            total,
            state.command_counts.stream_connected,
            state.command_counts.stream_connect_error,
            state.command_counts.stream_closed,
            state.command_counts.stream_readable,
            state.command_counts.stream_read_error,
            state.command_counts.stream_write_error,
            state.command_counts.stream_write_drained
        );
    }
    state.command_counts.reset();
    state.last_command_report = now;
}
fn handle_shutdown(quic: *mut picoquic_quic_t, state: &mut ServerState) -> bool {
    let mut cnx = unsafe { picoquic_get_first_cnx(quic) };
    while !cnx.is_null() {
        let next = unsafe { picoquic_get_next_cnx(cnx) };
        unsafe { picoquic_close_immediate(cnx) };
        remove_connection_streams(state, cnx as usize);
        cnx = next;
    }
    state.streams.clear();
    true
}

async fn bind_udp_socket(port: u16, ipv6: bool) -> Result<TokioUdpSocket, ServerError> {
    let addr = if ipv6 {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
    } else {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
    };
    TokioUdpSocket::bind(addr).await.map_err(map_io)
}

fn dummy_sockaddr_storage(ipv6: bool) -> libc::sockaddr_storage {
    if ipv6 {
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
    } else {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 12345u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes(Ipv4Addr::new(192, 0, 2, 1).octets()),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, sockaddr);
        }
        storage
    }
}

fn map_io(err: std::io::Error) -> ServerError {
    ServerError::new(err.to_string())
}
