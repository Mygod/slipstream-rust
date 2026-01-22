use crate::server::{Command, StreamKey, StreamWrite};
use crate::target::spawn_target_connector;
use slipstream_ffi::picoquic::{
    picoquic_call_back_event_t, picoquic_close, picoquic_close_immediate, picoquic_cnx_t,
    picoquic_get_first_cnx, picoquic_get_next_cnx, picoquic_mark_active_stream,
    picoquic_provide_stream_data_buffer, picoquic_quic_t, picoquic_reset_stream,
    picoquic_stream_data_consumed,
};
use slipstream_ffi::{SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, warn};

pub(crate) struct ServerState {
    target_addr: SocketAddr,
    streams: HashMap<StreamKey, ServerStream>,
    command_tx: mpsc::UnboundedSender<Command>,
    debug_streams: bool,
    debug_commands: bool,
    command_counts: CommandCounts,
    last_command_report: Instant,
}

impl ServerState {
    pub(crate) fn new(
        target_addr: SocketAddr,
        command_tx: mpsc::UnboundedSender<Command>,
        debug_streams: bool,
        debug_commands: bool,
    ) -> Self {
        Self {
            target_addr,
            streams: HashMap::new(),
            command_tx,
            debug_streams,
            debug_commands,
            command_counts: CommandCounts::default(),
            last_command_report: Instant::now(),
        }
    }
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

pub(crate) unsafe extern "C" fn server_callback(
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
                warn!(
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
                warn!(
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
                            error!(
                                "stream {:?}: provide_stream_data_buffer returned null send_len={} queued={} pending_chunks={} tx_bytes={}",
                                key.stream_id,
                                send_len,
                                stream.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                        } else {
                            error!(
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
                debug!("stream {:?}: connecting", key.stream_id);
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
            debug!("stream {:?}: resetting", stream_id);
        }
        shutdown_stream(state, key);
        unsafe {
            let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
        }
    }
}

pub(crate) fn remove_connection_streams(state: &mut ServerState, cnx: usize) {
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

pub(crate) fn drain_commands(
    state_ptr: *mut ServerState,
    command_rx: &mut mpsc::UnboundedReceiver<Command>,
) {
    while let Ok(command) = command_rx.try_recv() {
        handle_command(state_ptr, command);
    }
}

pub(crate) fn handle_command(state_ptr: *mut ServerState, command: Command) {
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
                    debug!("stream {:?}: target connected", stream_id);
                }
                stream.write_tx = Some(write_tx);
                stream.data_rx = Some(data_rx);
                stream.send_pending = Some(send_pending);
                if let Some(write_tx) = stream.write_tx.as_ref() {
                    while let Some(chunk) = stream.pending_data.pop_front() {
                        if write_tx.send(StreamWrite::Data(chunk)).is_err() {
                            warn!(
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
                            warn!(
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
                warn!("stream {:?}: target connect failed", stream_id);
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
                    debug!(
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
                            debug!(
                                "stream {:?}: mark_active_stream fin failed ret={}",
                                stream_id, ret
                            );
                        }
                    }
                }
            }
        }
        Command::StreamReadable { cnx_id, stream_id } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if !state.streams.contains_key(&key) {
                return;
            }
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let ret =
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
            if ret != 0 && state.debug_streams {
                debug!(
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
                warn!(
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
                warn!(
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
                    warn!(
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

pub(crate) fn maybe_report_command_stats(state_ptr: *mut ServerState) {
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
        debug!(
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

pub(crate) fn handle_shutdown(quic: *mut picoquic_quic_t, state: &mut ServerState) -> bool {
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
