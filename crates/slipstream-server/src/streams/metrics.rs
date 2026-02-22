use crate::server::{Command, StreamKey};
use slipstream_ffi::picoquic::picoquic_current_time;
use std::sync::atomic::Ordering;
use tracing::error;

use super::{ServerState, INVARIANT_REPORTER};

#[derive(Default)]
pub(crate) struct ServerStreamMetrics {
    pub(crate) streams_total: usize,
    pub(crate) streams_with_write_tx: usize,
    pub(crate) streams_with_data_rx: usize,
    pub(crate) streams_with_pending_data: usize,
    pub(crate) pending_chunks_total: usize,
    pub(crate) pending_bytes_total: u64,
    pub(crate) queued_bytes_total: u64,
    pub(crate) streams_with_pending_fin: usize,
    pub(crate) streams_with_fin_enqueued: usize,
    pub(crate) streams_with_target_fin_pending: usize,
    pub(crate) streams_with_send_pending: usize,
    pub(crate) streams_with_send_stash: usize,
    pub(crate) send_stash_bytes_total: u64,
    pub(crate) streams_discarding: usize,
    pub(crate) streams_close_after_flush: usize,
    pub(crate) multi_stream: bool,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct BacklogStreamSummary {
    pub(crate) stream_id: u64,
    pub(crate) send_pending: bool,
    pub(crate) send_stash_bytes: usize,
    pub(crate) target_fin_pending: bool,
    pub(crate) close_after_flush: bool,
    pub(crate) pending_fin: bool,
    pub(crate) fin_enqueued: bool,
    pub(crate) queued_bytes: u64,
    pub(crate) pending_chunks: usize,
}

impl ServerStreamMetrics {
    pub(crate) fn has_send_backlog(&self) -> bool {
        self.streams_with_send_pending > 0
            || self.streams_with_send_stash > 0
            || self.streams_with_target_fin_pending > 0
    }
}

pub(super) fn stream_debug_metrics(state: &ServerState, cnx_id: usize) -> ServerStreamMetrics {
    let mut metrics = ServerStreamMetrics {
        multi_stream: state.multi_streams.contains(&cnx_id),
        ..ServerStreamMetrics::default()
    };
    for (key, stream) in state.streams.iter() {
        if key.cnx != cnx_id {
            continue;
        }
        metrics.streams_total = metrics.streams_total.saturating_add(1);
        if stream.write_tx.is_some() {
            metrics.streams_with_write_tx = metrics.streams_with_write_tx.saturating_add(1);
        }
        if stream.data_rx.is_some() {
            metrics.streams_with_data_rx = metrics.streams_with_data_rx.saturating_add(1);
        }
        let queued = stream.flow.queued_bytes as u64;
        metrics.queued_bytes_total = metrics.queued_bytes_total.saturating_add(queued);
        if !stream.pending_data.is_empty() {
            metrics.streams_with_pending_data = metrics.streams_with_pending_data.saturating_add(1);
            metrics.pending_chunks_total = metrics
                .pending_chunks_total
                .saturating_add(stream.pending_data.len());
            let pending_bytes: u64 = stream
                .pending_data
                .iter()
                .map(|chunk| chunk.len() as u64)
                .sum();
            metrics.pending_bytes_total = metrics.pending_bytes_total.saturating_add(pending_bytes);
        }
        if stream.pending_fin {
            metrics.streams_with_pending_fin = metrics.streams_with_pending_fin.saturating_add(1);
        }
        if stream.fin_enqueued {
            metrics.streams_with_fin_enqueued = metrics.streams_with_fin_enqueued.saturating_add(1);
        }
        if stream.target_fin_pending {
            metrics.streams_with_target_fin_pending =
                metrics.streams_with_target_fin_pending.saturating_add(1);
        }
        if let Some(flag) = stream.send_pending.as_ref() {
            if flag.load(Ordering::SeqCst) {
                metrics.streams_with_send_pending =
                    metrics.streams_with_send_pending.saturating_add(1);
            }
        }
        if let Some(stash) = stream.send_stash.as_ref() {
            if !stash.is_empty() {
                metrics.streams_with_send_stash = metrics.streams_with_send_stash.saturating_add(1);
                metrics.send_stash_bytes_total = metrics
                    .send_stash_bytes_total
                    .saturating_add(stash.len() as u64);
            }
        }
        if stream.flow.discarding {
            metrics.streams_discarding = metrics.streams_discarding.saturating_add(1);
        }
        if stream.close_after_flush {
            metrics.streams_close_after_flush = metrics.streams_close_after_flush.saturating_add(1);
        }
    }
    metrics
}

pub(super) fn stream_send_backlog_summaries(
    state: &ServerState,
    cnx_id: usize,
    limit: usize,
) -> Vec<BacklogStreamSummary> {
    let mut summaries = Vec::new();
    for (key, stream) in state.streams.iter() {
        if key.cnx != cnx_id {
            continue;
        }
        let send_pending = stream
            .send_pending
            .as_ref()
            .map(|flag| flag.load(Ordering::SeqCst))
            .unwrap_or(false);
        let send_stash_bytes = stream
            .send_stash
            .as_ref()
            .map(|data| data.len())
            .unwrap_or(0);
        if send_pending || send_stash_bytes > 0 || stream.target_fin_pending {
            summaries.push(BacklogStreamSummary {
                stream_id: key.stream_id,
                send_pending,
                send_stash_bytes,
                target_fin_pending: stream.target_fin_pending,
                close_after_flush: stream.close_after_flush,
                pending_fin: stream.pending_fin,
                fin_enqueued: stream.fin_enqueued,
                queued_bytes: stream.flow.queued_bytes as u64,
                pending_chunks: stream.pending_data.len(),
            });
            if summaries.len() >= limit {
                break;
            }
        }
    }
    summaries
}

fn report_invariant<F>(message: F)
where
    F: FnOnce() -> String,
{
    let now = unsafe { picoquic_current_time() };
    INVARIANT_REPORTER.report(now, message, |msg| error!("{}", msg));
}

pub(super) fn check_stream_invariants(state: &ServerState, key: StreamKey, context: &str) {
    let Some(stream) = state.streams.get(&key) else {
        return;
    };
    if stream.close_after_flush && !stream.target_fin_pending {
        report_invariant(|| {
            format!(
                "server invariant violated: close_after_flush without target_fin_pending stream={} context={} queued={} pending_fin={} fin_enqueued={} target_fin_pending={} close_after_flush={}",
                key.stream_id,
                context,
                stream.flow.queued_bytes,
                stream.pending_fin,
                stream.fin_enqueued,
                stream.target_fin_pending,
                stream.close_after_flush
            )
        });
    }
    if stream.pending_fin && stream.fin_enqueued {
        report_invariant(|| {
            format!(
                "server invariant violated: pending_fin with fin_enqueued stream={} context={} queued={} pending_chunks={} target_fin_pending={} close_after_flush={}",
                key.stream_id,
                context,
                stream.flow.queued_bytes,
                stream.pending_data.len(),
                stream.target_fin_pending,
                stream.close_after_flush
            )
        });
    }
    if stream.write_tx.is_some() != stream.send_pending.is_some() {
        report_invariant(|| {
            format!(
                "server invariant violated: write_tx/send_pending mismatch stream={} context={} write_tx={} send_pending={} data_rx={}",
                key.stream_id,
                context,
                stream.write_tx.is_some(),
                stream.send_pending.is_some(),
                stream.data_rx.is_some()
            )
        });
    }
}

#[derive(Default)]
pub(super) struct CommandCounts {
    pub(super) stream_connected: u64,
    pub(super) stream_connect_error: u64,
    pub(super) stream_closed: u64,
    pub(super) stream_readable: u64,
    pub(super) stream_read_error: u64,
    pub(super) stream_write_error: u64,
    pub(super) stream_write_drained: u64,
}

impl CommandCounts {
    pub(super) fn bump(&mut self, command: &Command) {
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

    pub(super) fn total(&self) -> u64 {
        self.stream_connected
            + self.stream_connect_error
            + self.stream_closed
            + self.stream_readable
            + self.stream_read_error
            + self.stream_write_error
            + self.stream_write_drained
    }

    pub(super) fn reset(&mut self) {
        *self = CommandCounts::default();
    }
}
