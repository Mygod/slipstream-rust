use super::Command;
use slipstream_ffi::picoquic::{picoquic_cnx_t, slipstream_get_max_streams_bidir_remote};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::{mpsc, Notify};
use tokio::time::{sleep, Duration};
use tracing::warn;

#[derive(Clone)]
/// Gate local TCP accepts on remote QUIC MAX_STREAMS credit.
///
/// Credit is monotonic per connection: it only increases when the peer
/// sends MAX_STREAMS, and resets on reconnect. Generation checks ensure
/// stale accepts never leak across reconnect boundaries.
pub(crate) struct ClientAcceptor {
    limiter: Arc<AcceptorLimiter>,
}

impl ClientAcceptor {
    pub(crate) fn new() -> Self {
        let limit = initial_acceptor_limit();
        Self {
            limiter: Arc::new(AcceptorLimiter::new(limit)),
        }
    }

    pub(crate) fn spawn(
        &self,
        listener: TokioTcpListener,
        command_tx: mpsc::UnboundedSender<Command>,
    ) {
        TcpAcceptor::new(listener, command_tx, Arc::clone(&self.limiter)).spawn();
    }

    pub(crate) fn update_limit(&self, cnx: *mut picoquic_cnx_t) -> usize {
        let max_streams = unsafe { slipstream_get_max_streams_bidir_remote(cnx) };
        let max_streams = usize::try_from(max_streams).unwrap_or(usize::MAX);
        self.limiter.set_max(max_streams);
        max_streams
    }

    pub(crate) fn reset(&self) {
        self.limiter.reset();
    }

    #[cfg(test)]
    pub(crate) fn set_test_limit(limit: usize) {
        TEST_ACCEPTOR_LIMIT.store(limit, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) async fn reserve_for_test(&self) -> AcceptorReservation {
        self.limiter.reserve().await
    }
}

pub(super) fn initial_acceptor_limit() -> usize {
    initial_acceptor_limit_override().unwrap_or(0)
}

#[cfg(test)]
static TEST_ACCEPTOR_LIMIT: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
fn initial_acceptor_limit_override() -> Option<usize> {
    let limit = TEST_ACCEPTOR_LIMIT.load(Ordering::SeqCst);
    if limit == 0 {
        None
    } else {
        Some(limit)
    }
}

#[cfg(not(test))]
fn initial_acceptor_limit_override() -> Option<usize> {
    None
}

struct AcceptorLimiter {
    max: AtomicUsize,
    used: AtomicUsize,
    generation: AtomicUsize,
    notify: Notify,
}

impl AcceptorLimiter {
    fn new(limit: usize) -> Self {
        Self {
            max: AtomicUsize::new(limit),
            used: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }

    fn set_max(&self, limit: usize) {
        self.max.store(limit, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn generation(&self) -> usize {
        self.generation.load(Ordering::SeqCst)
    }

    fn reset(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.max.store(0, Ordering::SeqCst);
        self.used.store(0, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn reserve(self: &Arc<Self>) -> AcceptorReservation {
        loop {
            let max = self.max.load(Ordering::SeqCst);
            let used = self.used.load(Ordering::SeqCst);
            if used < max {
                let generation = self.generation.load(Ordering::SeqCst);
                if self
                    .used
                    .compare_exchange(used, used + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    let current_generation = self.generation.load(Ordering::SeqCst);
                    if current_generation != generation {
                        self.rollback_used();
                        continue;
                    }
                    return AcceptorReservation {
                        limiter: Arc::clone(self),
                        generation: current_generation,
                        committed: false,
                    };
                }
                continue;
            }
            self.notify.notified().await;
        }
    }

    fn release_reservation(&self, generation: usize) {
        if generation != self.generation.load(Ordering::SeqCst) {
            return;
        }
        loop {
            let used = self.used.load(Ordering::SeqCst);
            if used == 0 {
                return;
            }
            if self
                .used
                .compare_exchange(used, used - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.notify.notify_one();
                return;
            }
        }
    }

    fn rollback_used(&self) {
        loop {
            let used = self.used.load(Ordering::SeqCst);
            if used == 0 {
                return;
            }
            if self
                .used
                .compare_exchange(used, used - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.notify.notify_one();
                return;
            }
        }
    }
}

pub(crate) struct AcceptorReservation {
    limiter: Arc<AcceptorLimiter>,
    generation: usize,
    committed: bool,
}

impl AcceptorReservation {
    pub(crate) fn is_fresh(&self) -> bool {
        self.limiter.generation() == self.generation
    }

    pub(crate) fn commit(mut self) -> bool {
        if !self.is_fresh() {
            return false;
        }
        self.committed = true;
        true
    }
}

impl Drop for AcceptorReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.limiter.release_reservation(self.generation);
        }
    }
}

struct AcceptorGate {
    limiter: Arc<AcceptorLimiter>,
}

impl AcceptorGate {
    fn new(limiter: Arc<AcceptorLimiter>) -> Self {
        Self { limiter }
    }

    async fn accept_and_dispatch(
        &self,
        listener: &TokioTcpListener,
        command_tx: &mpsc::UnboundedSender<Command>,
    ) -> bool {
        let reservation = self.limiter.reserve().await;
        match listener.accept().await {
            Ok((stream, _)) => {
                if !reservation.is_fresh() {
                    drop(stream);
                    return true;
                };
                if command_tx
                    .send(Command::NewStream {
                        stream,
                        reservation,
                    })
                    .is_err()
                {
                    return false;
                }
                true
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                drop(reservation);
                true
            }
            Err(err) => {
                drop(reservation);
                warn!(
                    "acceptor: accept failed kind={:?} err={}; keeping acceptor alive",
                    err.kind(),
                    err
                );
                sleep(Duration::from_millis(50)).await;
                true
            }
        }
    }
}

struct TcpAcceptor {
    listener: TokioTcpListener,
    command_tx: mpsc::UnboundedSender<Command>,
    gate: AcceptorGate,
}

impl TcpAcceptor {
    fn new(
        listener: TokioTcpListener,
        command_tx: mpsc::UnboundedSender<Command>,
        acceptor_backpressure: Arc<AcceptorLimiter>,
    ) -> Self {
        Self {
            listener,
            command_tx,
            gate: AcceptorGate::new(acceptor_backpressure),
        }
    }

    async fn run(self) {
        loop {
            if !self
                .gate
                .accept_and_dispatch(&self.listener, &self.command_tx)
                .await
            {
                break;
            }
        }
    }

    fn spawn(self) {
        tokio::spawn(self.run());
    }
}

#[cfg(test)]
mod tests {
    use super::AcceptorLimiter;
    use std::sync::Arc;
    use tokio::time::{timeout, Duration};

    #[test]
    fn acceptor_unblocks_after_stream_limit_increase() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build tokio runtime");
        rt.block_on(async {
            let limiter = Arc::new(AcceptorLimiter::new(1024));

            for _ in 0..1024 {
                let reservation = limiter.reserve().await;
                assert!(reservation.commit(), "reservation commit should succeed");
            }

            let blocked = timeout(Duration::from_millis(50), limiter.reserve()).await;
            assert!(
                blocked.is_err(),
                "expected acceptor to block once stream credit is exhausted"
            );

            // Simulate a peer MAX_STREAMS update after previous streams close.
            limiter.set_max(1025);

            let reservation = timeout(Duration::from_secs(1), limiter.reserve())
                .await
                .expect("reservation should unblock after limit increase");
            assert!(
                reservation.commit(),
                "reservation should commit after limit increase"
            );
        });
    }
}
