use super::state::{ClientState, StreamRecvState, StreamSendState};
use slipstream_core::invariants::InvariantReporter;
use slipstream_ffi::picoquic::picoquic_current_time;
use tracing::error;

static INVARIANT_REPORTER: InvariantReporter = InvariantReporter::new(1_000_000);

fn report_invariant<F>(message: F)
where
    F: FnOnce() -> String,
{
    let now = unsafe { picoquic_current_time() };
    INVARIANT_REPORTER.report(now, message, |msg| error!("{}", msg));
}

pub(super) fn check_stream_invariants(state: &ClientState, stream_id: u64, context: &str) {
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
