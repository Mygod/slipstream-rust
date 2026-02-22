use super::acceptor;
use super::io_tasks::StreamWrite;
use slipstream_core::flow_control::{FlowControlState, HasFlowControlState};
use slipstream_ffi::picoquic::picoquic_cnx_t;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info};

pub(super) const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
pub(super) const CLIENT_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;

pub(crate) struct ClientState {
    pub(super) ready: bool,
    pub(super) closing: bool,
    pub(super) connection_generation: usize,
    pub(super) streams: HashMap<u64, ClientStream>,
    pub(super) multi_stream_mode: bool,
    pub(super) command_tx: mpsc::UnboundedSender<Command>,
    pub(super) data_notify: Arc<Notify>,
    pub(super) path_events: Vec<PathEvent>,
    pub(super) debug_streams: bool,
    pub(super) acceptor: acceptor::ClientAcceptor,
    pub(super) debug_enqueued_bytes: u64,
    pub(super) debug_last_enqueue_at: u64,
    pub(super) acceptor_limit_logged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamSendState {
    Open,
    Closing,
    FinQueued,
}

impl StreamSendState {
    pub(super) fn is_closed(self) -> bool {
        matches!(self, StreamSendState::FinQueued)
    }

    pub(super) fn can_queue_fin(self) -> bool {
        matches!(self, StreamSendState::Open | StreamSendState::Closing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamRecvState {
    Open,
    FinReceived,
}

impl StreamRecvState {
    pub(super) fn is_closed(self) -> bool {
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

pub(super) struct ClientStream {
    pub(super) write_tx: mpsc::UnboundedSender<StreamWrite>,
    pub(super) read_abort_tx: Option<oneshot::Sender<()>>,
    pub(super) data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub(super) tx_bytes: u64,
    pub(super) recv_state: StreamRecvState,
    pub(super) send_state: StreamSendState,
    pub(super) flow: FlowControlState,
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
