use slipstream_core::auth::{
    build_auth_request, parse_auth_response, AuthStatus, AUTH_RESPONSE_SIZE, AUTH_STREAM_ID,
};
use slipstream_core::tcp::{stream_read_limit_chunks, tcp_send_buffer_bytes};
use slipstream_ffi::picoquic::{
    picoquic_add_to_stream, picoquic_call_back_event_t, picoquic_cnx_t, picoquic_current_time,
    picoquic_get_close_reasons, picoquic_get_cnx_state, picoquic_get_next_local_stream_id,
    picoquic_mark_active_stream, picoquic_provide_stream_data_buffer, picoquic_reset_stream,
    picoquic_stream_data_consumed,
};
use slipstream_ffi::{SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, error, info, warn};

const STREAM_READ_CHUNK_BYTES: usize = 4096;
const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
const CLIENT_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;

/// Client authentication state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthState {
    /// No authentication configured
    NotRequired,
    /// Auth request sent, waiting for response
    Pending,
    /// Authentication successful
    Authenticated,
    /// Authentication failed
    Failed,
}

pub(crate) struct ClientState {
    ready: bool,
    closing: bool,
    streams: HashMap<u64, ClientStream>,
    command_tx: mpsc::UnboundedSender<Command>,
    data_notify: Arc<Notify>,
    path_events: Vec<PathEvent>,
    debug_streams: bool,
    debug_enqueued_bytes: u64,
    debug_last_enqueue_at: u64,
    // Authentication fields
    auth_state: AuthState,
    auth_token: Option<String>,
    auth_response_buffer: Vec<u8>,
    pending_tcp_streams: Vec<TokioTcpStream>,
}

impl ClientState {
    pub(crate) fn new(
        command_tx: mpsc::UnboundedSender<Command>,
        data_notify: Arc<Notify>,
        debug_streams: bool,
        auth_token: Option<String>,
    ) -> Self {
        let auth_state = if auth_token.is_some() {
            AuthState::Pending
        } else {
            AuthState::NotRequired
        };
        Self {
            ready: false,
            closing: false,
            streams: HashMap::new(),
            command_tx,
            data_notify,
            path_events: Vec::new(),
            debug_streams,
            debug_enqueued_bytes: 0,
            debug_last_enqueue_at: 0,
            auth_state,
            auth_token,
            auth_response_buffer: Vec::new(),
            pending_tcp_streams: Vec::new(),
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.closing
    }

    pub(crate) fn streams_len(&self) -> usize {
        self.streams.len()
    }

    pub(crate) fn debug_snapshot(&self) -> (u64, u64) {
        (self.debug_enqueued_bytes, self.debug_last_enqueue_at)
    }

    pub(crate) fn take_path_events(&mut self) -> Vec<PathEvent> {
        std::mem::take(&mut self.path_events)
    }

    pub(crate) fn reset_for_reconnect(&mut self) {
        let debug_streams = self.debug_streams;
        for (stream_id, mut stream) in self.streams.drain() {
            if let Some(read_abort_tx) = stream.read_abort_tx.take() {
                let _ = read_abort_tx.send(());
            }
            let _ = stream.write_tx.send(StreamWrite::Fin);
            if debug_streams {
                debug!("stream {}: closing due to reconnect", stream_id);
            }
        }
        self.ready = false;
        self.closing = false;
        self.path_events.clear();
        self.debug_enqueued_bytes = 0;
        self.debug_last_enqueue_at = 0;
        // Reset auth state for reconnection
        self.auth_state = if self.auth_token.is_some() {
            AuthState::Pending
        } else {
            AuthState::NotRequired
        };
        self.auth_response_buffer.clear();
        self.pending_tcp_streams.clear();
    }
}

struct ClientStream {
    write_tx: mpsc::UnboundedSender<StreamWrite>,
    read_abort_tx: Option<oneshot::Sender<()>>,
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

pub(crate) enum Command {
    NewStream(TokioTcpStream),
    StreamData { stream_id: u64, data: Vec<u8> },
    StreamClosed { stream_id: u64 },
    StreamReadError { stream_id: u64 },
    StreamWriteError { stream_id: u64 },
    StreamWriteDrained { stream_id: u64, bytes: usize },
}

pub(crate) enum PathEvent {
    Available(u64),
    Deleted(u64),
}

fn close_event_label(event: picoquic_call_back_event_t) -> &'static str {
    match event {
        picoquic_call_back_event_t::picoquic_callback_close => "close",
        picoquic_call_back_event_t::picoquic_callback_application_close => "application_close",
        picoquic_call_back_event_t::picoquic_callback_stateless_reset => "stateless_reset",
        _ => "unknown",
    }
}

pub(crate) unsafe extern "C" fn client_callback(
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
            info!("Connection ready");
            // Send authentication request if token is configured
            if let Some(token) = &state.auth_token {
                let auth_request = build_auth_request(token);
                let ret = picoquic_add_to_stream(
                    cnx,
                    AUTH_STREAM_ID,
                    auth_request.as_ptr(),
                    auth_request.len(),
                    1, // set fin flag
                );
                if ret < 0 {
                    error!("Failed to send auth request: ret={}", ret);
                    state.auth_state = AuthState::Failed;
                }
                // auth_state is already Pending from constructor
            } else {
                // Reserve stream 0 even without auth so data streams start from stream 4
                // This ensures stream 0 is never used for regular data
                let _ = picoquic_add_to_stream(
                    cnx,
                    AUTH_STREAM_ID,
                    std::ptr::null(),
                    0,
                    1, // set fin flag to close the stream immediately
                );
            }
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
            // Check if this is stream 0 (auth stream)
            if stream_id == AUTH_STREAM_ID {
                handle_auth_response(cnx, state, data, fin);
            } else {
                handle_stream_data(cnx, state, stream_id, fin, data);
            }
        }
        picoquic_call_back_event_t::picoquic_callback_stream_reset
        | picoquic_call_back_event_t::picoquic_callback_stop_sending => {
            let reason = match fin_or_event {
                picoquic_call_back_event_t::picoquic_callback_stream_reset => "stream_reset",
                picoquic_call_back_event_t::picoquic_callback_stop_sending => "stop_sending",
                _ => "unknown",
            };
            // Check if this is a reset on the auth stream while waiting for auth response
            if stream_id == AUTH_STREAM_ID && state.auth_state == AuthState::Pending {
                // Server doesn't support auth - fall back to no auth
                info!(
                    "Auth stream reset: server may not support authentication, continuing without auth"
                );
                state.auth_state = AuthState::Authenticated;
                state.auth_response_buffer.clear();
                // Process any pending TCP streams
                let pending = std::mem::take(&mut state.pending_tcp_streams);
                for stream in pending {
                    let _ = state.command_tx.send(Command::NewStream(stream));
                }
                state.data_notify.notify_one();
                return 0;
            }
            if let Some(stream) = state.streams.remove(&stream_id) {
                warn!(
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
                warn!(
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
            let mut local_reason = 0u64;
            let mut remote_reason = 0u64;
            let mut local_app_reason = 0u64;
            let mut remote_app_reason = 0u64;
            let cnx_state = unsafe { picoquic_get_cnx_state(cnx) };
            unsafe {
                picoquic_get_close_reasons(
                    cnx,
                    &mut local_reason,
                    &mut remote_reason,
                    &mut local_app_reason,
                    &mut remote_app_reason,
                );
            }
            warn!(
                "Connection closed event={} state={:?} local_error=0x{:x} remote_error=0x{:x} local_app=0x{:x} remote_app=0x{:x} ready={}",
                close_event_label(fin_or_event),
                cnx_state,
                local_reason,
                remote_reason,
                local_app_reason,
                remote_app_reason,
                state.ready
            );
        }
        picoquic_call_back_event_t::picoquic_callback_prepare_to_send => {
            if !bytes.is_null() {
                let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, 0);
            }
        }
        picoquic_call_back_event_t::picoquic_callback_path_available => {
            state.path_events.push(PathEvent::Available(stream_id));
        }
        picoquic_call_back_event_t::picoquic_callback_path_deleted => {
            state.path_events.push(PathEvent::Deleted(stream_id));
        }
        _ => {}
    }

    0
}

fn handle_auth_response(
    _cnx: *mut picoquic_cnx_t,
    state: &mut ClientState,
    data: &[u8],
    fin: bool,
) {
    // If we're not expecting an auth response, ignore it
    if state.auth_state != AuthState::Pending {
        return;
    }

    // Accumulate data until we have enough
    state.auth_response_buffer.extend_from_slice(data);

    // Check if we have a complete auth response
    if state.auth_response_buffer.len() >= AUTH_RESPONSE_SIZE {
        let response_data = &state.auth_response_buffer[..AUTH_RESPONSE_SIZE];
        if let Some(status) = parse_auth_response(response_data) {
            match status {
                AuthStatus::Success => {
                    info!("Authentication successful");
                    state.auth_state = AuthState::Authenticated;
                    // Process any pending TCP streams
                    let pending = std::mem::take(&mut state.pending_tcp_streams);
                    for stream in pending {
                        let _ = state.command_tx.send(Command::NewStream(stream));
                    }
                    state.data_notify.notify_one();
                }
                AuthStatus::Invalid => {
                    error!("Authentication failed: invalid token");
                    state.auth_state = AuthState::Failed;
                    state.pending_tcp_streams.clear();
                    state.closing = true;
                }
                AuthStatus::Required => {
                    error!("Authentication failed: server requires authentication");
                    state.auth_state = AuthState::Failed;
                    state.pending_tcp_streams.clear();
                    state.closing = true;
                }
            }
        } else {
            warn!("Received malformed auth response");
            state.auth_state = AuthState::Failed;
            state.pending_tcp_streams.clear();
            state.closing = true;
        }
        state.auth_response_buffer.clear();
    } else if fin {
        // Server closed stream 0 before sending complete response
        warn!(
            "Auth stream closed before complete response (received {} bytes)",
            state.auth_response_buffer.len()
        );
        state.auth_state = AuthState::Failed;
        state.pending_tcp_streams.clear();
        state.auth_response_buffer.clear();
        state.closing = true;
    }
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
            warn!(
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
                warn!(
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
                    warn!(
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
            debug!("stream {}: resetting", stream_id);
        }
        unsafe {
            let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        state.streams.remove(&stream_id);
    } else if remove_stream {
        if debug_streams {
            debug!("stream {}: finished", stream_id);
        }
        state.streams.remove(&stream_id);
    }
}

pub(crate) fn spawn_acceptor(
    listener: TokioTcpListener,
    command_tx: mpsc::UnboundedSender<Command>,
) {
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

pub(crate) fn drain_commands(
    cnx: *mut picoquic_cnx_t,
    state_ptr: *mut ClientState,
    command_rx: &mut mpsc::UnboundedReceiver<Command>,
) {
    while let Ok(command) = command_rx.try_recv() {
        handle_command(cnx, state_ptr, command);
    }
}

pub(crate) fn drain_stream_data(cnx: *mut picoquic_cnx_t, state_ptr: *mut ClientState) {
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

pub(crate) fn handle_command(
    cnx: *mut picoquic_cnx_t,
    state_ptr: *mut ClientState,
    command: Command,
) {
    let state = unsafe { &mut *state_ptr };
    match command {
        Command::NewStream(stream) => {
            // Check authentication state before accepting new streams
            match state.auth_state {
                AuthState::Pending => {
                    // Queue the stream until authentication completes
                    state.pending_tcp_streams.push(stream);
                    if state.debug_streams {
                        debug!("TCP stream queued pending authentication");
                    }
                    return;
                }
                AuthState::Failed => {
                    // Reject streams when auth has failed
                    warn!("TCP stream rejected: authentication failed");
                    // Drop the stream to close it
                    drop(stream);
                    return;
                }
                AuthState::NotRequired | AuthState::Authenticated => {
                    // Continue with normal stream handling
                }
            }

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
            let (read_abort_tx, read_abort_rx) = oneshot::channel();
            spawn_client_reader(
                stream_id,
                read_half,
                read_abort_rx,
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
                    read_abort_tx: Some(read_abort_tx),
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
                debug!("stream {}: accepted", stream_id);
            } else {
                info!("Accepted TCP stream {}", stream_id);
            }
        }
        Command::StreamData { stream_id, data } => {
            let ret =
                unsafe { picoquic_add_to_stream(cnx, stream_id, data.as_ptr(), data.len(), 0) };
            if ret < 0 {
                warn!(
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
                warn!(
                    "stream {}: add_to_stream(fin) failed ret={}",
                    stream_id, ret
                );
            }
        }
        Command::StreamReadError { stream_id } => {
            if let Some(stream) = state.streams.remove(&stream_id) {
                warn!(
                    "stream {}: tcp read error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.rx_bytes,
                    stream.tx_bytes,
                    stream.queued_bytes,
                    stream.consumed_offset,
                    stream.fin_offset
                );
            } else {
                warn!("stream {}: tcp read error (unknown stream)", stream_id);
            }
            let _ = unsafe { picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
        }
        Command::StreamWriteError { stream_id } => {
            if let Some(stream) = state.streams.remove(&stream_id) {
                warn!(
                    "stream {}: tcp write error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.rx_bytes,
                    stream.tx_bytes,
                    stream.queued_bytes,
                    stream.consumed_offset,
                    stream.fin_offset
                );
            } else {
                warn!("stream {}: tcp write error (unknown stream)", stream_id);
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
                    warn!(
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
    mut read_abort_rx: oneshot::Receiver<()>,
    command_tx: mpsc::UnboundedSender<Command>,
    data_tx: mpsc::Sender<Vec<u8>>,
    data_notify: Arc<Notify>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; STREAM_READ_CHUNK_BYTES];
        loop {
            tokio::select! {
                _ = &mut read_abort_rx => {
                    break;
                }
                read_result = read_half.read(&mut buf) => {
                    match read_result {
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
