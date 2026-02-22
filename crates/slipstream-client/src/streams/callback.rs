use super::invariants::check_stream_invariants;
use super::io_tasks::StreamWrite;
use super::state::{ClientState, ClientStream, PathEvent, StreamRecvState};
use slipstream_core::flow_control::{
    conn_reserve_bytes, consume_error_log_message, handle_stream_receive, overflow_log_message,
    StreamReceiveConfig, StreamReceiveOps,
};
use slipstream_ffi::picoquic::{
    picoquic_call_back_event_t, picoquic_cnx_t, picoquic_get_close_reasons, picoquic_get_cnx_state,
    picoquic_provide_stream_data_buffer, picoquic_reset_stream, picoquic_stop_sending,
    picoquic_stream_data_consumed,
};
use slipstream_ffi::{abort_stream_bidi, SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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

pub(super) fn handle_stream_data(
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
