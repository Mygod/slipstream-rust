use super::{DnsPeerState, FallbackManager, FALLBACK_CLEANUP_INTERVAL, FALLBACK_IDLE_TIMEOUT};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket as TokioUdpSocket;

impl FallbackManager {
    pub(crate) fn new(
        main_socket: Arc<TokioUdpSocket>,
        fallback_addr: SocketAddr,
        map_ipv4_peers: bool,
    ) -> Self {
        tracing::info!("non-DNS packets will be forwarded to {}", fallback_addr);
        Self {
            fallback_addr,
            main_socket,
            map_ipv4_peers,
            dns_peers: std::collections::HashMap::new(),
            sessions: std::collections::HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    pub(crate) fn cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) < FALLBACK_CLEANUP_INTERVAL {
            return;
        }
        self.last_cleanup = now;

        self.dns_peers
            .retain(|_, state| now.duration_since(state.last_seen) <= FALLBACK_IDLE_TIMEOUT);

        let mut expired = Vec::new();
        for (peer, session) in &self.sessions {
            let last_seen = match session.last_seen.lock() {
                Ok(last_seen) => *last_seen,
                Err(_) => {
                    tracing::warn!(
                        "fallback session for {} has poisoned mutex, marking for cleanup",
                        peer
                    );
                    expired.push(*peer);
                    continue;
                }
            };
            if now.duration_since(last_seen) > FALLBACK_IDLE_TIMEOUT {
                expired.push(*peer);
            }
        }

        for peer in expired {
            self.end_session(peer);
        }
    }

    fn end_session(&mut self, peer: SocketAddr) {
        if let Some(session) = self.sessions.remove(&peer) {
            let _ = session.shutdown_tx.send(true);
            tracing::debug!("ending fallback session for {}", peer);
        }
    }

    pub(super) fn mark_dns(&mut self, peer: SocketAddr) {
        let now = Instant::now();
        self.dns_peers
            .entry(peer)
            .and_modify(|state| {
                state.last_seen = now;
                state.non_dns_streak = 0;
            })
            .or_insert(DnsPeerState {
                last_seen: now,
                non_dns_streak: 0,
            });
    }

    pub(super) fn is_active_fallback_peer(&mut self, peer: SocketAddr) -> bool {
        let mut should_end = false;
        let last_seen = match self.sessions.get(&peer) {
            Some(session) => match session.last_seen.lock() {
                Ok(last_seen) => *last_seen,
                Err(_) => {
                    tracing::warn!(
                        "fallback session for {} has poisoned mutex, marking for cleanup",
                        peer
                    );
                    should_end = true;
                    Instant::now()
                }
            },
            None => return false,
        };

        if should_end {
            self.end_session(peer);
            return false;
        }

        let now = Instant::now();
        if now.duration_since(last_seen) > FALLBACK_IDLE_TIMEOUT {
            self.end_session(peer);
            return false;
        }

        true
    }
}
