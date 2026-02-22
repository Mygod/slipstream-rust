use slipstream_core::flow_control::{
    conn_reserve_bytes, consume_error_log_message, consume_stream_data, handle_stream_receive,
    overflow_log_message, promote_error_log_message, promote_streams, reserve_target_offset,
    FlowControlState, HasFlowControlState, PromoteEntry, StreamReceiveConfig, StreamReceiveOps,
};
use slipstream_core::invariants::InvariantReporter;
use slipstream_core::tcp::{stream_read_limit_chunks, tcp_send_buffer_bytes};
use slipstream_ffi::picoquic::{
    picoquic_add_to_stream, picoquic_call_back_event_t, picoquic_cnx_t, picoquic_current_time,
    picoquic_get_close_reasons, picoquic_get_cnx_state, picoquic_get_next_local_stream_id,
    picoquic_mark_active_stream, picoquic_provide_stream_data_buffer, picoquic_reset_stream,
    picoquic_stop_sending, picoquic_stream_data_consumed,
};
use slipstream_ffi::{abort_stream_bidi, SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, error, info, warn};

const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
const CLIENT_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;
static INVARIANT_REPORTER: InvariantReporter = InvariantReporter::new(1_000_000);

pub(crate) struct ClientState {
    ready: bool,
    closing: bool,
    connection_generation: usize,
    streams: HashMap<u64, ClientStream>,
    multi_stream_mode: bool,
    command_tx: mpsc::UnboundedSender<Command>,
    data_notify: Arc<Notify>,
    path_events: Vec<PathEvent>,
    debug_streams: bool,
    acceptor: acceptor::ClientAcceptor,
    debug_enqueued_bytes: u64,
    debug_last_enqueue_at: u64,
    acceptor_limit_logged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamSendState {
    Open,
    Closing,
    FinQueued,
}

impl StreamSendState {
    fn is_closed(self) -> bool {
        matches!(self, StreamSendState::FinQueued)
    }

    fn can_queue_fin(self) -> bool {
        matches!(self, StreamSendState::Open | StreamSendState::Closing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamRecvState {
    Open,
    FinReceived,
}

impl StreamRecvState {
    fn is_closed(self) -> bool {
        matches!(self, StreamRecvState::FinReceived)
    }
}

#[derive(Default)]
pub(crate) struct ClientStreamMetrics {
    pub(crate) streams_with_rx_queued: usize,
    pub(crate) queued_bytes_total: u64,
    pub(crate) streams_with_recv_fin: usize,
    pub(crate) streams_with_send_fin: usize,
    pub(crate) streams_discarding: usize,
    pub(crate) streams_with_unconsumed_rx: usize,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ClientBacklogSummary {
    pub(crate) stream_id: u64,
    pub(crate) queued_bytes: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) consumed_offset: u64,
    pub(crate) fin_offset: Option<u64>,
    pub(crate) recv_state: StreamRecvState,
    pub(crate) send_state: StreamSendState,
    pub(crate) stop_sending_sent: bool,
    pub(crate) discarding: bool,
    pub(crate) has_data_rx: bool,
    pub(crate) tx_bytes: u64,
}

pub(crate) mod acceptor;
mod io_tasks;

use io_tasks::{spawn_client_reader, spawn_client_writer, StreamWrite, STREAM_READ_CHUNK_BYTES};

impl ClientState {
    pub(crate) fn new(
        command_tx: mpsc::UnboundedSender<Command>,
        data_notify: Arc<Notify>,
        debug_streams: bool,
        acceptor: acceptor::ClientAcceptor,
    ) -> Self {
        Self {
            ready: false,
            closing: false,
            connection_generation: 0,
            streams: HashMap::new(),
            multi_stream_mode: false,
            command_tx,
            data_notify,
            path_events: Vec::new(),
            debug_streams,
            acceptor,
            debug_enqueued_bytes: 0,
            debug_last_enqueue_at: 0,
            acceptor_limit_logged: false,
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

    pub(crate) fn update_acceptor_limit(&mut self, cnx: *mut picoquic_cnx_t) {
        let max_streams = self.acceptor.update_limit(cnx);
        if !self.acceptor_limit_logged && max_streams > 0 {
            self.acceptor_limit_logged = true;
            info!("acceptor: initial_max_streams_bidir_remote={}", max_streams);
        }
    }

    pub(crate) fn debug_snapshot(&self) -> (u64, u64) {
        (self.debug_enqueued_bytes, self.debug_last_enqueue_at)
    }

    pub(crate) fn stream_debug_metrics(&self) -> ClientStreamMetrics {
        let mut metrics = ClientStreamMetrics::default();
        for stream in self.streams.values() {
            let queued = stream.flow.queued_bytes as u64;
            let unconsumed = stream
                .flow
                .rx_bytes
                .saturating_sub(stream.flow.consumed_offset);
            metrics.queued_bytes_total = metrics.queued_bytes_total.saturating_add(queued);
            if queued > 0 {
                metrics.streams_with_rx_queued = metrics.streams_with_rx_queued.saturating_add(1);
            }
            if stream.recv_state == StreamRecvState::FinReceived {
                metrics.streams_with_recv_fin = metrics.streams_with_recv_fin.saturating_add(1);
            }
            if stream.send_state == StreamSendState::FinQueued {
                metrics.streams_with_send_fin = metrics.streams_with_send_fin.saturating_add(1);
            }
            if stream.flow.discarding {
                metrics.streams_discarding = metrics.streams_discarding.saturating_add(1);
            }
            if unconsumed > 0 {
                metrics.streams_with_unconsumed_rx =
                    metrics.streams_with_unconsumed_rx.saturating_add(1);
            }
        }
        metrics
    }

    pub(crate) fn stream_backlog_summaries(&self, limit: usize) -> Vec<ClientBacklogSummary> {
        let mut summaries = Vec::new();
        for (stream_id, stream) in self.streams.iter() {
            let queued_bytes = stream.flow.queued_bytes as u64;
            let has_data_rx = stream.data_rx.is_some();
            let unconsumed = stream
                .flow
                .rx_bytes
                .saturating_sub(stream.flow.consumed_offset);
            if queued_bytes > 0
                || stream.recv_state != StreamRecvState::Open
                || stream.send_state != StreamSendState::Open
                || stream.flow.discarding
                || unconsumed > 0
            {
                summaries.push(ClientBacklogSummary {
                    stream_id: *stream_id,
                    queued_bytes,
                    rx_bytes: stream.flow.rx_bytes,
                    consumed_offset: stream.flow.consumed_offset,
                    fin_offset: stream.flow.fin_offset,
                    recv_state: stream.recv_state,
                    send_state: stream.send_state,
                    stop_sending_sent: stream.flow.stop_sending_sent,
                    discarding: stream.flow.discarding,
                    has_data_rx,
                    tx_bytes: stream.tx_bytes,
                });
                if summaries.len() >= limit {
                    break;
                }
            }
        }
        summaries
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
        self.connection_generation = self.connection_generation.wrapping_add(1);
        self.multi_stream_mode = false;
        self.path_events.clear();
        self.acceptor.reset();
        self.debug_enqueued_bytes = 0;
        self.debug_last_enqueue_at = 0;
        self.acceptor_limit_logged = false;
    }
}

fn report_invariant<F>(message: F)
where
    F: FnOnce() -> String,
{
    let now = unsafe { picoquic_current_time() };
    INVARIANT_REPORTER.report(now, message, |msg| error!("{}", msg));
}

fn check_stream_invariants(state: &ClientState, stream_id: u64, context: &str) {
    let Some(stream) = state.streams.get(&stream_id) else {
        return;
    };
    if stream.send_state != StreamSendState::Open && stream.data_rx.is_some() {
        report_invariant(|| {
            format!(
                "client invariant violated: send_state closed with data_rx stream={} context={} send_state={:?} queued={} discarding={} tx_bytes={}",
                stream_id,
                context,
                stream.send_state,
                stream.flow.queued_bytes,
                stream.flow.discarding,
                stream.tx_bytes
            )
        });
    }
    if stream.send_state == StreamSendState::Open && stream.data_rx.is_none() {
        report_invariant(|| {
            format!(
                "client invariant violated: send_state open without data_rx stream={} context={} send_state={:?} recv_state={:?} queued={} discarding={} tx_bytes={}",
                stream_id,
                context,
                stream.send_state,
                stream.recv_state,
                stream.flow.queued_bytes,
                stream.flow.discarding,
                stream.tx_bytes
            )
        });
    }
    if stream.recv_state == StreamRecvState::FinReceived && stream.flow.fin_offset.is_none() {
        report_invariant(|| {
            format!(
                "client invariant violated: recv_state fin without fin_offset stream={} context={} recv_state={:?} rx_bytes={} queued={} tx_bytes={}",
                stream_id,
                context,
                stream.recv_state,
                stream.flow.rx_bytes,
                stream.flow.queued_bytes,
                stream.tx_bytes
            )
        });
    }
}

fn command_generation_matches(
    state: &ClientState,
    stream_id: u64,
    generation: usize,
    label: &str,
) -> bool {
    if generation == state.connection_generation {
        return true;
    }
    debug!(
        "stream {}: ignoring stale {} generation={} current_generation={}",
        stream_id, label, generation, state.connection_generation
    );
    false
}

struct ClientStream {
    write_tx: mpsc::UnboundedSender<StreamWrite>,
    read_abort_tx: Option<oneshot::Sender<()>>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    tx_bytes: u64,
    recv_state: StreamRecvState,
    send_state: StreamSendState,
    flow: FlowControlState,
}

impl HasFlowControlState for ClientStream {
    fn flow_control(&self) -> &FlowControlState {
        &self.flow
    }

    fn flow_control_mut(&mut self) -> &mut FlowControlState {
        &mut self.flow
    }
}

pub(crate) enum Command {
    NewStream {
        stream: TokioTcpStream,
        reservation: acceptor::AcceptorReservation,
    },
    StreamData {
        stream_id: u64,
        data: Vec<u8>,
    },
    StreamClosed {
        stream_id: u64,
    },
    StreamReadError {
        stream_id: u64,
        generation: usize,
    },
    StreamWriteError {
        stream_id: u64,
        generation: usize,
    },
    StreamWriteDrained {
        stream_id: u64,
        bytes: usize,
        generation: usize,
    },
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
            state.update_acceptor_limit(cnx);
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
                warn!(
                    "stream {}: reset event={} rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?} recv_state={:?} send_state={:?}",
                    stream_id,
                    reason,
                    stream.flow.rx_bytes,
                    stream.tx_bytes,
                    stream.flow.queued_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.fin_offset,
                    stream.recv_state,
                    stream.send_state
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
    let multi_stream = state.multi_stream_mode;
    let reserve_bytes = if multi_stream {
        0
    } else {
        conn_reserve_bytes()
    };

    {
        let Some(stream) = state.streams.get_mut(&stream_id) else {
            warn!(
                "stream {}: data for unknown stream len={} fin={}",
                stream_id,
                data.len(),
                fin
            );
            unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR) };
            return;
        };

        if handle_stream_receive(
            stream,
            data.len(),
            StreamReceiveConfig::new(multi_stream, reserve_bytes),
            StreamReceiveOps {
                enqueue: |stream: &mut ClientStream| {
                    if stream
                        .write_tx
                        .send(StreamWrite::Data(data.to_vec()))
                        .is_err()
                    {
                        warn!(
                            "stream {}: tcp write channel closed queued={} rx_bytes={} tx_bytes={}",
                            stream_id,
                            stream.flow.queued_bytes,
                            stream.flow.rx_bytes,
                            stream.tx_bytes
                        );
                        Err(())
                    } else {
                        Ok(())
                    }
                },
                on_overflow: |stream: &mut ClientStream| {
                    let (drain_tx, _drain_rx) = mpsc::unbounded_channel();
                    stream.write_tx = drain_tx;
                },
                consume: |new_offset| unsafe {
                    picoquic_stream_data_consumed(cnx, stream_id, new_offset)
                },
                stop_sending: || {
                    let _ =
                        unsafe { picoquic_stop_sending(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                },
                log_overflow: |queued, incoming, max| {
                    warn!("{}", overflow_log_message(stream_id, queued, incoming, max));
                },
                on_consume_error: |ret, current, target| {
                    warn!(
                        "{}",
                        consume_error_log_message(stream_id, "", ret, current, target)
                    );
                },
            },
        ) {
            reset_stream = true;
        }

        if fin {
            if stream.flow.discarding {
                remove_stream = true;
            } else {
                if stream.flow.fin_offset.is_none() {
                    stream.flow.fin_offset = Some(stream.flow.rx_bytes);
                }
                if stream.recv_state == StreamRecvState::Open {
                    if stream.write_tx.send(StreamWrite::Fin).is_err() {
                        warn!(
                            "stream {}: tcp write channel closed on fin queued={} rx_bytes={} tx_bytes={}",
                            stream_id,
                            stream.flow.queued_bytes,
                            stream.flow.rx_bytes,
                            stream.tx_bytes
                        );
                        reset_stream = true;
                    } else {
                        stream.recv_state = StreamRecvState::FinReceived;
                    }
                }
            }
        }

        if !reset_stream
            && !stream.flow.discarding
            && stream.recv_state.is_closed()
            && stream.send_state.is_closed()
            && stream.flow.queued_bytes == 0
        {
            remove_stream = true;
        }
    }

    if reset_stream {
        if debug_streams {
            debug!("stream {}: resetting", stream_id);
        }
        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR) };
        state.streams.remove(&stream_id);
    } else if remove_stream {
        if debug_streams {
            debug!("stream {}: finished", stream_id);
        }
        state.streams.remove(&stream_id);
    }

    check_stream_invariants(state, stream_id, "handle_stream_data");
}

#[cfg(test)]
mod test_hooks {
    use slipstream_core::test_support::FailureCounter;

    pub(super) const FORCED_ADD_TO_STREAM_ERROR: i32 = -1;
    pub(super) const FORCED_MARK_ACTIVE_STREAM_ERROR: i32 = 0x400 + 36;
    pub(super) static ADD_TO_STREAM_FAILS_LEFT: FailureCounter = FailureCounter::new();
    pub(super) static MARK_ACTIVE_STREAM_FAILS_LEFT: FailureCounter = FailureCounter::new();

    pub(super) fn set_add_to_stream_failures(count: usize) {
        ADD_TO_STREAM_FAILS_LEFT.set(count);
    }

    pub(super) fn set_mark_active_stream_failures(count: usize) {
        MARK_ACTIVE_STREAM_FAILS_LEFT.set(count);
    }

    pub(super) fn take_add_to_stream_failure() -> bool {
        ADD_TO_STREAM_FAILS_LEFT.take()
    }

    pub(super) fn take_mark_active_stream_failure() -> bool {
        MARK_ACTIVE_STREAM_FAILS_LEFT.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slipstream_core::test_support::ResetOnDrop;
    use std::sync::Arc;
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::sync::{mpsc, oneshot, Notify};
    use tokio::time::{sleep, timeout, Duration};

    #[test]
    fn add_to_stream_fin_failure_removes_stream() {
        let _guard = ResetOnDrop::new(|| test_hooks::set_add_to_stream_failures(0));
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());
        let acceptor = acceptor::ClientAcceptor::new();
        let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
        let stream_id = 4;
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();

        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: None,
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::Open,
                flow: FlowControlState::default(),
            },
        );

        test_hooks::set_add_to_stream_failures(1);

        handle_command(
            std::ptr::null_mut(),
            &mut state as *mut _,
            Command::StreamClosed { stream_id },
        );

        assert!(
            !state.streams.contains_key(&stream_id),
            "stream state should be removed when add_to_stream(fin) fails"
        );
    }

    #[test]
    fn remote_fin_keeps_local_read_open() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());
        let acceptor = acceptor::ClientAcceptor::new();
        let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
        let stream_id = 4;
        let (write_tx, mut write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();
        let (_data_tx, data_rx) = mpsc::channel(1);

        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: Some(data_rx),
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::Open,
                flow: FlowControlState::default(),
            },
        );

        handle_stream_data(std::ptr::null_mut(), &mut state, stream_id, true, &[]);

        let stream = state
            .streams
            .get(&stream_id)
            .expect("stream should remain after remote fin");
        assert_eq!(stream.recv_state, StreamRecvState::FinReceived);
        assert_eq!(stream.send_state, StreamSendState::Open);
        assert!(
            stream.data_rx.is_some(),
            "local TCP read side should stay open after remote fin"
        );
        assert!(
            matches!(write_rx.try_recv(), Ok(StreamWrite::Fin)),
            "expected a TCP fin to be enqueued"
        );
    }

    #[test]
    fn stream_removal_requires_both_halves_closed() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());
        let acceptor = acceptor::ClientAcceptor::new();
        let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
        let stream_id = 4;
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();
        let (_data_tx, data_rx) = mpsc::channel(1);

        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: Some(data_rx),
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::Open,
                flow: FlowControlState::default(),
            },
        );

        handle_stream_data(std::ptr::null_mut(), &mut state, stream_id, true, &[]);
        assert!(
            state.streams.contains_key(&stream_id),
            "stream should remain when only recv side is closed"
        );

        if let Some(stream) = state.streams.get_mut(&stream_id) {
            stream.send_state = StreamSendState::FinQueued;
        }
        handle_command(
            std::ptr::null_mut(),
            &mut state as *mut _,
            Command::StreamWriteDrained {
                stream_id,
                bytes: 0,
                generation: 0,
            },
        );
        assert!(
            !state.streams.contains_key(&stream_id),
            "stream should be removed once both halves are closed"
        );
    }

    #[test]
    fn local_fin_does_not_remove_until_recv_fin() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());
        let acceptor = acceptor::ClientAcceptor::new();
        let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
        let stream_id = 4;
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();

        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: None,
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::FinQueued,
                flow: FlowControlState::default(),
            },
        );

        handle_command(
            std::ptr::null_mut(),
            &mut state as *mut _,
            Command::StreamWriteDrained {
                stream_id,
                bytes: 0,
                generation: 0,
            },
        );

        assert!(
            state.streams.contains_key(&stream_id),
            "stream should remain when only send side is closed"
        );
    }

    #[test]
    fn mark_active_stream_failure_removes_stream() {
        let _guard = ResetOnDrop::new(|| test_hooks::set_mark_active_stream_failures(0));
        let _limit_guard = ResetOnDrop::new(|| acceptor::ClientAcceptor::set_test_limit(0));
        acceptor::ClientAcceptor::set_test_limit(1);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("build tokio runtime");
        rt.block_on(async {
            let listener = TokioTcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind listener");
            let addr = listener.local_addr().expect("listener addr");
            let accept = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                stream
            });
            let _client = TokioTcpStream::connect(addr).await.expect("connect");
            let stream = accept.await.expect("accept join");

            let (command_tx, _command_rx) = mpsc::unbounded_channel();
            let data_notify = Arc::new(Notify::new());
            let acceptor = acceptor::ClientAcceptor::new();
            let reservation = acceptor.reserve_for_test().await;
            let mut state = ClientState::new(command_tx, data_notify, false, acceptor);

            test_hooks::set_mark_active_stream_failures(1);

            handle_command(
                std::ptr::null_mut(),
                &mut state as *mut _,
                Command::NewStream {
                    stream,
                    reservation,
                },
            );

            assert!(
                state.streams.is_empty(),
                "stream state should be removed when mark_active_stream fails"
            );
        });
    }

    #[test]
    fn stale_task_command_is_ignored_after_reconnect() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());
        let acceptor = acceptor::ClientAcceptor::new();
        let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
        let stream_id = 4;
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (read_abort_tx, _read_abort_rx) = oneshot::channel();

        state.streams.insert(
            stream_id,
            ClientStream {
                write_tx,
                read_abort_tx: Some(read_abort_tx),
                data_rx: None,
                tx_bytes: 0,
                recv_state: StreamRecvState::Open,
                send_state: StreamSendState::Open,
                flow: FlowControlState::default(),
            },
        );
        state.connection_generation = 1;

        handle_command(
            std::ptr::null_mut(),
            &mut state as *mut _,
            Command::StreamReadError {
                stream_id,
                generation: 0,
            },
        );

        assert!(
            state.streams.contains_key(&stream_id),
            "stale task command from old generation must not mutate current stream state"
        );
    }

    #[test]
    fn acceptor_backpressure_blocks_new_connections() {
        let _guard = ResetOnDrop::new(|| acceptor::ClientAcceptor::set_test_limit(0));
        acceptor::ClientAcceptor::set_test_limit(1);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("build tokio runtime");
        rt.block_on(async {
            let listener = TokioTcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind listener");
            let addr = listener.local_addr().expect("listener addr");
            let (command_tx, mut command_rx) = mpsc::unbounded_channel();
            let acceptor = acceptor::ClientAcceptor::new();
            acceptor.spawn(listener, command_tx);

            let mut clients = Vec::new();
            for _ in 0..3 {
                clients.push(TokioTcpStream::connect(addr).await.expect("connect"));
            }

            sleep(Duration::from_millis(50)).await;

            let _first = timeout(Duration::from_secs(1), command_rx.recv())
                .await
                .expect("first accept")
                .expect("first command");
            let second = timeout(Duration::from_millis(200), command_rx.recv()).await;

            assert!(
                second.is_err(),
                "expected acceptor backpressure to block additional accepts while at limit"
            );

            drop(clients);
        });
    }
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
        for stream_id in &closed_streams {
            if let Some(stream) = state.streams.get_mut(stream_id) {
                if stream.send_state == StreamSendState::Open {
                    stream.send_state = StreamSendState::Closing;
                }
            }
        }
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
        Command::NewStream {
            stream,
            reservation,
        } => {
            if !reservation.is_fresh() {
                drop(stream);
                return;
            }
            let _ = stream.set_nodelay(true);
            #[cfg(test)]
            let forced_failure = test_hooks::take_mark_active_stream_failure();
            #[cfg(not(test))]
            let forced_failure = false;
            #[cfg(test)]
            let stream_id = if forced_failure {
                4
            } else {
                assert!(
                    !cnx.is_null(),
                    "picoquic connection must be non-null when not forcing failures in tests"
                );
                unsafe { picoquic_get_next_local_stream_id(cnx, 0) }
            };
            #[cfg(not(test))]
            let stream_id = unsafe { picoquic_get_next_local_stream_id(cnx, 0) };
            #[cfg(test)]
            let ret = if forced_failure {
                test_hooks::FORCED_MARK_ACTIVE_STREAM_ERROR
            } else {
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) }
            };
            #[cfg(not(test))]
            let ret =
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
            if ret != 0 {
                warn!(
                    "stream {}: mark_active_stream failed ret={}",
                    stream_id, ret
                );
                if !forced_failure {
                    unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                }
                return;
            }
            if !reservation.commit() {
                warn!(
                    "stream {}: acceptor generation changed during activation",
                    stream_id
                );
                if !forced_failure {
                    unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                }
                return;
            }
            let read_limit = stream_read_limit_chunks(
                &stream,
                DEFAULT_TCP_RCVBUF_BYTES,
                STREAM_READ_CHUNK_BYTES,
            );
            let (data_tx, data_rx) = mpsc::channel(read_limit);
            let data_notify = state.data_notify.clone();
            let send_buffer_bytes = tcp_send_buffer_bytes(&stream)
                .filter(|bytes| *bytes > 0)
                .unwrap_or(CLIENT_WRITE_COALESCE_DEFAULT_BYTES);
            let (read_half, write_half) = stream.into_split();
            let (write_tx, write_rx) = mpsc::unbounded_channel();
            let command_tx = state.command_tx.clone();
            let (read_abort_tx, read_abort_rx) = oneshot::channel();
            let generation = state.connection_generation;
            state.streams.insert(
                stream_id,
                ClientStream {
                    write_tx,
                    read_abort_tx: Some(read_abort_tx),
                    data_rx: Some(data_rx),
                    tx_bytes: 0,
                    recv_state: StreamRecvState::Open,
                    send_state: StreamSendState::Open,
                    flow: FlowControlState::default(),
                },
            );
            spawn_client_reader(
                stream_id,
                read_half,
                read_abort_rx,
                generation,
                command_tx.clone(),
                data_tx,
                data_notify,
            );
            spawn_client_writer(
                stream_id,
                write_half,
                write_rx,
                generation,
                command_tx,
                send_buffer_bytes,
            );
            if !state.multi_stream_mode && state.streams.len() > 1 {
                state.multi_stream_mode = true;
                promote_streams(
                    state
                        .streams
                        .iter_mut()
                        .map(|(stream_id, stream)| PromoteEntry {
                            stream_id: *stream_id,
                            rx_bytes: stream.flow.rx_bytes,
                            consumed_offset: &mut stream.flow.consumed_offset,
                            discarding: stream.flow.discarding,
                        }),
                    |stream_id, new_offset| unsafe {
                        picoquic_stream_data_consumed(cnx, stream_id, new_offset)
                    },
                    |stream_id, ret, consumed_offset, rx_bytes| {
                        warn!(
                            "{}",
                            promote_error_log_message(stream_id, ret, consumed_offset, rx_bytes)
                        );
                    },
                );
            }
            if state.debug_streams {
                debug!("stream {}: accepted", stream_id);
            } else {
                debug!("Accepted TCP stream {}", stream_id);
            }
            check_stream_invariants(state, stream_id, "NewStream");
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
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                state.streams.remove(&stream_id);
            } else if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.tx_bytes = stream.tx_bytes.saturating_add(data.len() as u64);
                let now = unsafe { picoquic_current_time() };
                state.debug_enqueued_bytes =
                    state.debug_enqueued_bytes.saturating_add(data.len() as u64);
                state.debug_last_enqueue_at = now;
            }
            check_stream_invariants(state, stream_id, "StreamData");
        }
        Command::StreamClosed { stream_id } => {
            let should_send_fin = state
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream.send_state.can_queue_fin());
            if !should_send_fin {
                return;
            }
            #[cfg(test)]
            let forced_failure = test_hooks::take_add_to_stream_failure();
            #[cfg(not(test))]
            let forced_failure = false;
            #[cfg(test)]
            let ret = if forced_failure {
                test_hooks::FORCED_ADD_TO_STREAM_ERROR
            } else {
                assert!(
                    !cnx.is_null(),
                    "picoquic connection must be non-null when not forcing failures in tests"
                );
                unsafe { picoquic_add_to_stream(cnx, stream_id, std::ptr::null(), 0, 1) }
            };
            #[cfg(not(test))]
            let ret = unsafe { picoquic_add_to_stream(cnx, stream_id, std::ptr::null(), 0, 1) };
            if ret < 0 {
                warn!(
                    "stream {}: add_to_stream(fin) failed ret={}",
                    stream_id, ret
                );
                if !forced_failure {
                    unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                }
                state.streams.remove(&stream_id);
            } else if let Some(stream) = state.streams.get_mut(&stream_id) {
                stream.send_state = StreamSendState::FinQueued;
                if stream.recv_state.is_closed() && stream.flow.queued_bytes == 0 {
                    state.streams.remove(&stream_id);
                }
            }
            check_stream_invariants(state, stream_id, "StreamClosed");
        }
        Command::StreamReadError {
            stream_id,
            generation,
        } => {
            if !command_generation_matches(state, stream_id, generation, "StreamReadError") {
                return;
            }
            if let Some(stream) = state.streams.remove(&stream_id) {
                warn!(
                    "stream {}: tcp read error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.flow.rx_bytes,
                    stream.tx_bytes,
                    stream.flow.queued_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.fin_offset
                );
            } else {
                warn!("stream {}: tcp read error (unknown stream)", stream_id);
            }
            unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
        }
        Command::StreamWriteError {
            stream_id,
            generation,
        } => {
            if !command_generation_matches(state, stream_id, generation, "StreamWriteError") {
                return;
            }
            if let Some(stream) = state.streams.remove(&stream_id) {
                warn!(
                    "stream {}: tcp write error rx_bytes={} tx_bytes={} queued={} consumed_offset={} fin_offset={:?}",
                    stream_id,
                    stream.flow.rx_bytes,
                    stream.tx_bytes,
                    stream.flow.queued_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.fin_offset
                );
            } else {
                warn!("stream {}: tcp write error (unknown stream)", stream_id);
            }
            unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
        }
        Command::StreamWriteDrained {
            stream_id,
            bytes,
            generation,
        } => {
            if !command_generation_matches(state, stream_id, generation, "StreamWriteDrained") {
                return;
            }
            let mut remove_stream = false;
            if let Some(stream) = state.streams.get_mut(&stream_id) {
                if stream.flow.discarding {
                    return;
                }
                stream.flow.queued_bytes = stream.flow.queued_bytes.saturating_sub(bytes);
                if !state.multi_stream_mode {
                    let new_offset = reserve_target_offset(
                        stream.flow.rx_bytes,
                        stream.flow.queued_bytes,
                        stream.flow.fin_offset,
                        conn_reserve_bytes(),
                    );
                    if !consume_stream_data(
                        &mut stream.flow.consumed_offset,
                        new_offset,
                        |new_offset| unsafe {
                            picoquic_stream_data_consumed(cnx, stream_id, new_offset)
                        },
                        |ret, current, target| {
                            warn!(
                                "{}",
                                consume_error_log_message(stream_id, "", ret, current, target)
                            );
                        },
                    ) {
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                        state.streams.remove(&stream_id);
                        return;
                    }
                }
                if stream.recv_state.is_closed()
                    && stream.send_state.is_closed()
                    && stream.flow.queued_bytes == 0
                {
                    remove_stream = true;
                }
            }
            if remove_stream {
                state.streams.remove(&stream_id);
            }
            check_stream_invariants(state, stream_id, "StreamWriteDrained");
        }
    }
}
