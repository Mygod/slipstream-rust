use super::{FallbackManager, FallbackSession, MAX_UDP_PACKET_SIZE, NON_DNS_STREAK_THRESHOLD};
use crate::server::{map_io, ServerError};
use slipstream_core::{net::is_transient_udp_error, normalize_dual_stack_addr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::watch;

impl FallbackManager {
    pub(super) async fn forward_existing(&mut self, packet: &[u8], peer: SocketAddr) {
        self.forward_packet(packet, peer).await;
    }

    pub(super) async fn handle_non_dns(&mut self, packet: &[u8], peer: SocketAddr) {
        let mut should_forward = true;
        let mut should_remove = false;
        if let Some(state) = self.dns_peers.get_mut(&peer) {
            state.non_dns_streak = state.non_dns_streak.saturating_add(1);
            if state.non_dns_streak < NON_DNS_STREAK_THRESHOLD {
                should_forward = false;
            } else {
                should_remove = true;
            }
        }
        if should_remove {
            self.dns_peers.remove(&peer);
        }
        if !should_forward {
            return;
        }
        self.forward_packet(packet, peer).await;
    }

    async fn forward_packet(&mut self, packet: &[u8], peer: SocketAddr) {
        let socket = match self.ensure_session(peer).await {
            Some(socket) => socket,
            None => return,
        };
        if let Err(err) = socket.send(packet).await {
            if !is_transient_udp_error(&err) {
                tracing::warn!(
                    "fallback write to {} for client {} failed: {}",
                    self.fallback_addr,
                    peer,
                    err
                );
            }
        }
    }

    async fn ensure_session(&mut self, peer: SocketAddr) -> Option<Arc<TokioUdpSocket>> {
        let reset_session = self
            .sessions
            .get(&peer)
            .map(|session| session.reply_task.is_finished())
            .unwrap_or(false);
        if reset_session {
            self.sessions.remove(&peer);
            tracing::debug!("fallback reply loop ended for {}; recreating session", peer);
        }
        if !self.sessions.contains_key(&peer) {
            if let Err(err) = self.create_session(peer).await {
                tracing::warn!("failed to create fallback session for {}: {}", peer, err);
                return None;
            }
        }

        let socket = if let Some(session) = self.sessions.get_mut(&peer) {
            if let Ok(mut last_seen) = session.last_seen.lock() {
                *last_seen = Instant::now();
            }
            session.socket.clone()
        } else {
            return None;
        };

        Some(socket)
    }

    async fn create_session(&mut self, peer: SocketAddr) -> Result<(), ServerError> {
        let bind_addr = fallback_bind_addr(self.fallback_addr);
        let socket = TokioUdpSocket::bind(bind_addr).await.map_err(map_io)?;
        socket.connect(self.fallback_addr).await.map_err(map_io)?;
        let socket = Arc::new(socket);
        let last_seen = Arc::new(Mutex::new(Instant::now()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_socket = socket.clone();
        let main_socket = self.main_socket.clone();
        let last_seen_update = last_seen.clone();
        let map_ipv4_peers = self.map_ipv4_peers;
        let reply_task = tokio::spawn(async move {
            forward_fallback_replies(
                proxy_socket,
                main_socket,
                peer,
                map_ipv4_peers,
                last_seen_update,
                shutdown_rx,
            )
            .await;
        });
        self.sessions.insert(
            peer,
            FallbackSession {
                socket,
                last_seen,
                shutdown_tx,
                reply_task,
            },
        );
        tracing::debug!("created fallback session for {}", peer);
        Ok(())
    }
}

fn fallback_bind_addr(fallback_addr: SocketAddr) -> SocketAddr {
    match fallback_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

async fn forward_fallback_replies(
    proxy_socket: Arc<TokioUdpSocket>,
    main_socket: Arc<TokioUdpSocket>,
    client_addr: SocketAddr,
    map_ipv4_peers: bool,
    last_seen: Arc<Mutex<Instant>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let client_send_addr = if map_ipv4_peers {
        normalize_dual_stack_addr(client_addr)
    } else {
        client_addr
    };
    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            recv = proxy_socket.recv(&mut buf) => {
                match recv {
                    Ok(size) => {
                        if let Ok(mut last_seen) = last_seen.lock() {
                            *last_seen = Instant::now();
                        }
                        if let Err(err) = main_socket.send_to(&buf[..size], client_send_addr).await {
                            if !is_transient_udp_error(&err) {
                                tracing::warn!(
                                    "fallback write to client {} failed: {}",
                                    client_addr,
                                    err
                                );
                            }
                        }
                    }
                    Err(err) => {
                        if is_transient_udp_error(&err) {
                            continue;
                        }
                        tracing::warn!(
                            "fallback read for client {} failed: {}",
                            client_addr,
                            err
                        );
                        break;
                    }
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}
