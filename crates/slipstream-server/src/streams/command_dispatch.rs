use super::{check_stream_invariants, shutdown_stream, BacklogStreamSummary, ServerState};
#[cfg(test)]
use super::{test_helpers, test_hooks};
use crate::server::{Command, StreamKey, StreamWrite};
use slipstream_core::flow_control::{
    conn_reserve_bytes, consume_error_log_message, consume_stream_data, reserve_target_offset,
};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_current_time, picoquic_mark_active_stream,
    picoquic_stream_data_consumed,
};
use slipstream_ffi::{abort_stream_bidi, SLIPSTREAM_INTERNAL_ERROR};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, warn};

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
                if stream.flow.discarding {
                    stream.pending_data.clear();
                    stream.pending_fin = false;
                    stream.fin_enqueued = false;
                    let _ = stream.shutdown_tx.send(true);
                    return;
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
                                stream.flow.queued_bytes,
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
                                stream.flow.queued_bytes,
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
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
            }
            check_stream_invariants(state, key, "StreamConnected");
        }
        Command::StreamConnectError { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if shutdown_stream(state, key).is_some() {
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                warn!("stream {:?}: target connect failed", stream_id);
            }
        }
        Command::StreamClosed { cnx_id, stream_id } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            let mut remove_stream = false;
            if state.streams.contains_key(&key) {
                #[cfg(test)]
                let forced_failure = test_helpers::take_mark_active_stream_failure(state);
                #[cfg(not(test))]
                let forced_failure = false;

                let Some(stream) = state.streams.get_mut(&key) else {
                    return;
                };
                stream.target_fin_pending = true;
                stream.close_after_flush = true;
                if state.debug_streams {
                    debug!(
                        "stream {:?}: closed by target tx_bytes={}",
                        stream_id, stream.tx_bytes
                    );
                }
                if let Some(pending) = stream.send_pending.as_ref() {
                    pending.store(true, Ordering::SeqCst);
                }
                let cnx = cnx_id as *mut picoquic_cnx_t;
                #[cfg(test)]
                let ret = if forced_failure {
                    test_hooks::FORCED_MARK_ACTIVE_STREAM_ERROR
                } else {
                    assert!(
                        cnx_id >= 0x1000,
                        "mark_active_stream called with synthetic cnx_id; set test failure counter"
                    );
                    unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) }
                };
                #[cfg(not(test))]
                let ret =
                    unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
                if ret != 0 {
                    const MARK_ACTIVE_FAIL_LOG_INTERVAL_US: u64 = 1_000_000;
                    let now = unsafe { picoquic_current_time() };
                    if now.saturating_sub(state.last_mark_active_fail_log_at)
                        >= MARK_ACTIVE_FAIL_LOG_INTERVAL_US
                    {
                        let send_pending = stream
                            .send_pending
                            .as_ref()
                            .map(|pending| pending.load(Ordering::SeqCst))
                            .unwrap_or(false);
                        let send_stash_bytes = stream
                            .send_stash
                            .as_ref()
                            .map(|stash| stash.len())
                            .unwrap_or(0);
                        let backlog = BacklogStreamSummary {
                            stream_id,
                            send_pending,
                            send_stash_bytes,
                            target_fin_pending: stream.target_fin_pending,
                            close_after_flush: stream.close_after_flush,
                            pending_fin: stream.pending_fin,
                            fin_enqueued: stream.fin_enqueued,
                            queued_bytes: stream.flow.queued_bytes as u64,
                            pending_chunks: stream.pending_data.len(),
                        };
                        warn!(
                            "stream {:?}: mark_active_stream fin failed ret={} backlog={:?}",
                            stream_id, ret, backlog
                        );
                        state.last_mark_active_fail_log_at = now;
                    }
                    if !forced_failure {
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                    }
                    remove_stream = true;
                }
            }
            if remove_stream {
                shutdown_stream(state, key);
            }
            check_stream_invariants(state, key, "StreamClosed");
        }
        Command::StreamReadable { cnx_id, stream_id } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if !state.streams.contains_key(&key) {
                return;
            }
            #[cfg(test)]
            let forced_failure = test_helpers::take_mark_active_stream_failure(state);
            #[cfg(not(test))]
            let forced_failure = false;
            let cnx = cnx_id as *mut picoquic_cnx_t;
            #[cfg(test)]
            let ret = if forced_failure {
                test_hooks::FORCED_MARK_ACTIVE_STREAM_ERROR
            } else {
                assert!(
                    cnx_id >= 0x1000,
                    "mark_active_stream called with synthetic cnx_id; set test failure counter"
                );
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) }
            };
            #[cfg(not(test))]
            let ret =
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
            if ret != 0 {
                if let Some(stream) = shutdown_stream(state, key) {
                    warn!(
                        "stream {:?}: mark_active_stream readable failed ret={} tx_bytes={} rx_bytes={} consumed_offset={} queued={} fin_offset={:?}",
                        stream_id,
                        ret,
                        stream.tx_bytes,
                        stream.flow.rx_bytes,
                        stream.flow.consumed_offset,
                        stream.flow.queued_bytes,
                        stream.flow.fin_offset
                    );
                    if !forced_failure {
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                    }
                } else if state.debug_streams {
                    debug!(
                        "stream {:?}: mark_active_stream readable failed ret={}",
                        stream_id, ret
                    );
                }
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
                    stream.flow.rx_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.queued_bytes,
                    stream.flow.fin_offset
                );
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
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
                    stream.flow.rx_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.queued_bytes,
                    stream.flow.fin_offset
                );
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
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
                if stream.flow.discarding {
                    return;
                }
                stream.flow.queued_bytes = stream.flow.queued_bytes.saturating_sub(bytes);
                if !state.multi_streams.contains(&cnx_id) {
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
                            picoquic_stream_data_consumed(
                                cnx_id as *mut picoquic_cnx_t,
                                stream_id,
                                new_offset,
                            )
                        },
                        |ret, current, target| {
                            warn!(
                                "{}",
                                consume_error_log_message(stream_id, "", ret, current, target)
                            );
                        },
                    ) {
                        reset_stream = true;
                    }
                }
            }
            if reset_stream {
                shutdown_stream(state, key);
                unsafe {
                    abort_stream_bidi(
                        cnx_id as *mut picoquic_cnx_t,
                        stream_id,
                        SLIPSTREAM_INTERNAL_ERROR,
                    )
                };
            }
            check_stream_invariants(state, key, "StreamWriteDrained");
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
