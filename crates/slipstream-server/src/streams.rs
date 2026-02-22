mod command_dispatch;
mod metrics;

use crate::server::{Command, StreamKey, StreamWrite};
use crate::target::spawn_target_connector;
use slipstream_core::flow_control::{
    conn_reserve_bytes, consume_error_log_message, handle_stream_receive, overflow_log_message,
    promote_error_log_message, promote_streams, FlowControlState, HasFlowControlState,
    PromoteEntry, StreamReceiveConfig, StreamReceiveOps,
};
use slipstream_core::invariants::InvariantReporter;
#[cfg(test)]
use slipstream_core::test_support::FailureCounter;
use slipstream_ffi::picoquic::{
    picoquic_call_back_event_t, picoquic_close, picoquic_close_immediate, picoquic_cnx_t,
    picoquic_current_time, picoquic_get_first_cnx, picoquic_get_next_cnx,
    picoquic_provide_stream_data_buffer, picoquic_quic_t, picoquic_reset_stream,
    picoquic_stop_sending, picoquic_stream_data_consumed,
};
use slipstream_ffi::{abort_stream_bidi, SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, warn};

pub(crate) use self::command_dispatch::{
    drain_commands, handle_command, maybe_report_command_stats,
};
use self::metrics::CommandCounts;
pub(crate) use self::metrics::{BacklogStreamSummary, ServerStreamMetrics};

static INVARIANT_REPORTER: InvariantReporter = InvariantReporter::new(1_000_000);

pub(crate) struct ServerState {
    target_addr: SocketAddr,
    streams: HashMap<StreamKey, ServerStream>,
    multi_streams: HashSet<usize>,
    command_tx: mpsc::UnboundedSender<Command>,
    debug_streams: bool,
    debug_commands: bool,
    command_counts: CommandCounts,
    last_command_report: Instant,
    last_mark_active_fail_log_at: u64,
    #[cfg(test)]
    mark_active_stream_failures: FailureCounter,
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
            multi_streams: HashSet::new(),
            command_tx,
            debug_streams,
            debug_commands,
            command_counts: CommandCounts::default(),
            last_command_report: Instant::now(),
            last_mark_active_fail_log_at: 0,
            #[cfg(test)]
            mark_active_stream_failures: FailureCounter::new(),
        }
    }

    pub(crate) fn stream_debug_metrics(&self, cnx_id: usize) -> ServerStreamMetrics {
        metrics::stream_debug_metrics(self, cnx_id)
    }

    pub(crate) fn stream_send_backlog_summaries(
        &self,
        cnx_id: usize,
        limit: usize,
    ) -> Vec<BacklogStreamSummary> {
        metrics::stream_send_backlog_summaries(self, cnx_id, limit)
    }
}

#[cfg(test)]
mod test_helpers {
    use super::ServerState;

    pub(super) fn set_mark_active_stream_failures(state: &mut ServerState, count: usize) {
        state.mark_active_stream_failures.set(count);
    }

    pub(super) fn take_mark_active_stream_failure(state: &ServerState) -> bool {
        state.mark_active_stream_failures.take()
    }
}

fn check_stream_invariants(state: &ServerState, key: StreamKey, context: &str) {
    metrics::check_stream_invariants(state, key, context);
}

struct ServerStream {
    write_tx: Option<mpsc::UnboundedSender<StreamWrite>>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    send_pending: Option<Arc<AtomicBool>>,
    send_stash: Option<Vec<u8>>,
    shutdown_tx: watch::Sender<bool>,
    tx_bytes: u64,
    target_fin_pending: bool,
    close_after_flush: bool,
    pending_data: VecDeque<Vec<u8>>,
    pending_fin: bool,
    fin_enqueued: bool,
    flow: FlowControlState,
}

impl HasFlowControlState for ServerStream {
    fn flow_control(&self) -> &FlowControlState {
        &self.flow
    }

    fn flow_control_mut(&mut self) -> &mut FlowControlState {
        &mut self.flow
    }
}

fn mark_multi_stream(state: &mut ServerState, cnx_id: usize) -> bool {
    if state.multi_streams.contains(&cnx_id) {
        return false;
    }
    let count = state.streams.keys().filter(|key| key.cnx == cnx_id).count();
    if count > 1 {
        state.multi_streams.insert(cnx_id);
        true
    } else {
        false
    }
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
                    stream.flow.rx_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.queued_bytes,
                    stream.pending_data.len(),
                    stream.pending_fin,
                    stream.fin_enqueued,
                    stream.flow.fin_offset,
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
                    if pending_flag && !has_stash && !stream.target_fin_pending {
                        let rx_empty = stream
                            .data_rx
                            .as_ref()
                            .map(|rx| rx.is_empty())
                            .unwrap_or(true);
                        if rx_empty {
                            let send_stash_bytes = stream
                                .send_stash
                                .as_ref()
                                .map(|data| data.len())
                                .unwrap_or(0);
                            let queued_bytes = stream.flow.queued_bytes;
                            let pending_chunks = stream.pending_data.len();
                            let tx_bytes = stream.tx_bytes;
                            let target_fin_pending = stream.target_fin_pending;
                            let close_after_flush = stream.close_after_flush;
                            let now = unsafe { picoquic_current_time() };
                            INVARIANT_REPORTER.report(
                                now,
                                || {
                                    format!(
                                        "cnx {} stream {:?}: zero-length send callback saw pending flag with empty queue send_pending={} send_stash_bytes={} target_fin_pending={} close_after_flush={} queued={} pending_chunks={} tx_bytes={}",
                                        key.cnx,
                                        key.stream_id,
                                        pending_flag,
                                        send_stash_bytes,
                                        target_fin_pending,
                                        close_after_flush,
                                        queued_bytes,
                                        pending_chunks,
                                        tx_bytes
                                    )
                                },
                                |msg| warn!("{}", msg),
                            );
                        }
                    }
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
                                stream.flow.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                        } else {
                            error!(
                                "stream {:?}: provide_stream_data_buffer returned null send_len={}",
                                key.stream_id, send_len
                            );
                        }
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
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
    let mut remove_stream = false;

    if !state.streams.contains_key(&key) {
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
        state.streams.insert(
            key,
            ServerStream {
                write_tx: None,
                data_rx: None,
                send_pending: None,
                send_stash: None,
                shutdown_tx,
                tx_bytes: 0,
                target_fin_pending: false,
                close_after_flush: false,
                pending_data: VecDeque::new(),
                pending_fin: false,
                fin_enqueued: false,
                flow: FlowControlState::default(),
            },
        );
    }

    if mark_multi_stream(state, key.cnx) {
        promote_streams(
            state
                .streams
                .iter_mut()
                .filter(|(entry_key, _)| entry_key.cnx == key.cnx)
                .map(|(entry_key, stream)| PromoteEntry {
                    stream_id: entry_key.stream_id,
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
    let multi_stream = state.multi_streams.contains(&key.cnx);
    let reserve_bytes = if multi_stream {
        0
    } else {
        conn_reserve_bytes()
    };

    {
        let stream = match state.streams.get_mut(&key) {
            Some(stream) => stream,
            None => return,
        };

        if handle_stream_receive(
            stream,
            data.len(),
            StreamReceiveConfig::new(multi_stream, reserve_bytes),
            StreamReceiveOps {
                enqueue: |stream: &mut ServerStream| {
                    if let Some(write_tx) = stream.write_tx.as_ref() {
                        if write_tx.send(StreamWrite::Data(data.to_vec())).is_err() {
                            return Err(());
                        }
                    } else {
                        stream.pending_data.push_back(data.to_vec());
                    }
                    Ok(())
                },
                on_overflow: |stream: &mut ServerStream| {
                    stream.pending_data.clear();
                    stream.pending_fin = false;
                    stream.fin_enqueued = false;
                    stream.data_rx = None;
                    stream.write_tx = None;
                    stream.send_pending = None;
                    stream.send_stash = None;
                    stream.target_fin_pending = false;
                    stream.close_after_flush = false;
                    let _ = stream.shutdown_tx.send(true);
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
                if !reset_stream {
                    remove_stream = true;
                }
            } else {
                if stream.flow.fin_offset.is_none() {
                    stream.flow.fin_offset = Some(stream.flow.rx_bytes);
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
    }

    if remove_stream {
        shutdown_stream(state, key);
        return;
    }

    if reset_stream {
        if debug_streams {
            debug!("stream {:?}: resetting", stream_id);
        }
        if !state
            .streams
            .get(&key)
            .map(|stream| stream.flow.discarding)
            .unwrap_or(false)
        {
            shutdown_stream(state, key);
        }
        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
    }

    check_stream_invariants(state, key, "handle_stream_data");
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
    state.multi_streams.remove(&cnx);
}

fn shutdown_stream(state: &mut ServerState, key: StreamKey) -> Option<ServerStream> {
    if let Some(stream) = state.streams.remove(&key) {
        let _ = stream.shutdown_tx.send(true);
        return Some(stream);
    }
    None
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
    state.multi_streams.clear();
    true
}

#[cfg(test)]
mod test_hooks {
    pub(super) const FORCED_MARK_ACTIVE_STREAM_ERROR: i32 = 0x400 + 36;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tokio::sync::{mpsc, watch};

    #[test]
    fn mark_active_stream_failure_should_remove_stream() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let target_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut state = ServerState::new(target_addr, command_tx, false, false);
        let key = StreamKey {
            cnx: 0x1,
            stream_id: 4,
        };
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        state.streams.insert(
            key,
            ServerStream {
                write_tx: None,
                data_rx: None,
                send_pending: Some(Arc::new(AtomicBool::new(false))),
                send_stash: None,
                shutdown_tx,
                tx_bytes: 0,
                target_fin_pending: false,
                close_after_flush: false,
                pending_data: VecDeque::new(),
                pending_fin: false,
                fin_enqueued: false,
                flow: FlowControlState::default(),
            },
        );

        test_helpers::set_mark_active_stream_failures(&mut state, 1);

        handle_command(
            &mut state as *mut _,
            Command::StreamClosed {
                cnx_id: key.cnx,
                stream_id: key.stream_id,
            },
        );

        assert!(
            !state.streams.contains_key(&key),
            "stream state should be removed when mark_active_stream fails"
        );
    }

    #[test]
    fn mark_active_stream_readable_failure_should_not_leave_send_pending_stuck() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let target_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut state = ServerState::new(target_addr, command_tx, false, false);
        let key = StreamKey {
            cnx: 0x1,
            stream_id: 4,
        };
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let send_pending = Arc::new(AtomicBool::new(true));
        let send_pending_handle = Arc::clone(&send_pending);

        state.streams.insert(
            key,
            ServerStream {
                write_tx: None,
                data_rx: None,
                send_pending: Some(send_pending_handle),
                send_stash: None,
                shutdown_tx,
                tx_bytes: 0,
                target_fin_pending: false,
                close_after_flush: false,
                pending_data: VecDeque::new(),
                pending_fin: false,
                fin_enqueued: false,
                flow: FlowControlState::default(),
            },
        );

        test_helpers::set_mark_active_stream_failures(&mut state, 1);

        handle_command(
            &mut state as *mut _,
            Command::StreamReadable {
                cnx_id: key.cnx,
                stream_id: key.stream_id,
            },
        );

        assert!(
            !state.streams.contains_key(&key),
            "stream state should be removed when mark_active_stream fails"
        );
        assert_eq!(
            Arc::strong_count(&send_pending),
            1,
            "send_pending should be dropped when the stream is removed"
        );
    }
}
