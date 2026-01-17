use crate::error::ClientError;
use crate::runtime::setup::bind_udp_socket;
use std::net::SocketAddr;

use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};


const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RECV_BUF: usize = 4096;

/// Response from a worker after completing a DNS query.
pub(crate) struct QueryResponse {
    pub(crate) data: Vec<u8>,
    pub(crate) peer: SocketAddr,
}

struct QueryRequest {
    packet: Vec<u8>,
    dest: SocketAddr,
}

/// A pool of workers that each create ephemeral UDP sockets for DNS queries.
/// This ensures each query uses a random source port assigned by the OS.
pub(crate) struct DnsQueryPool {
    request_tx: mpsc::Sender<QueryRequest>,
    response_rx: mpsc::UnboundedReceiver<QueryResponse>,
}

impl DnsQueryPool {
    /// Create a new pool with `workers` concurrent query handlers.
    pub(crate) fn new(workers: usize) -> Self {
        let (request_tx, request_rx) = mpsc::channel::<QueryRequest>(workers * 2);
        let request_rx = std::sync::Arc::new(tokio::sync::Mutex::new(request_rx));
        let (response_tx, response_rx) = mpsc::unbounded_channel();

        for worker_id in 0..workers {
            let rx = request_rx.clone();
            let tx = response_tx.clone();
            tokio::spawn(async move {
                loop {
                    let request = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    let Some(request) = request else {
                        debug!("Worker {} shutting down", worker_id);
                        break;
                    };
                    Self::handle_query(request, &tx).await;
                }
            });
        }

        Self {
            request_tx,
            response_rx,
        }
    }

    async fn handle_query(
        request: QueryRequest,
        response_tx: &mpsc::UnboundedSender<QueryResponse>,
    ) {
        // Create ephemeral socket - OS assigns random source port
        let socket = match bind_udp_socket().await {

            Ok(s) => s,
            Err(e) => {
                debug!("Failed to bind ephemeral socket: {}", e);
                return;
            }
        };


        if let Err(e) = socket.send_to(&request.packet, request.dest).await {
            debug!("Failed to send query: {}", e);
            return;
        }

        let mut buf = vec![0u8; MAX_RECV_BUF];
        let result = tokio::time::timeout(QUERY_TIMEOUT, socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((size, peer))) => {
                buf.truncate(size);
                if response_tx.send(QueryResponse { data: buf, peer }).is_err() {
                    warn!("Failed to return DNS response from worker: receiver dropped");
                }
            }
            Ok(Err(e)) => {
                debug!("Failed to receive response: {}", e);
            }
            Err(_) => {
                // Timeout - normal for DNS, don't log
            }
        }
        // Socket dropped here - OS will recycle the port
    }

    /// Send a DNS query through the pool.
    pub(crate) async fn send(&self, packet: Vec<u8>, dest: SocketAddr) -> Result<(), ClientError> {
        let request = QueryRequest { packet, dest };
        self.request_tx
            .send(request)
            .await
            .map_err(|_| ClientError::new("DNS query pool channel closed".to_string()))
    }

    /// Get mutable reference to the response receiver for tokio::select!
    pub(crate) fn response_rx_mut(&mut self) -> &mut mpsc::UnboundedReceiver<QueryResponse> {
        &mut self.response_rx
    }
}

/// Abstraction over DNS transport - either a shared socket or worker pool
pub(crate) enum DnsTransport {
    /// Single shared UDP socket (current behavior when --random-src-port 0)
    Shared {
        socket: TokioUdpSocket,
        local_addr_storage: libc::sockaddr_storage,
    },
    /// Worker pool with ephemeral sockets (when --random-src-port N > 0)
    Pool(DnsQueryPool),
}

impl DnsTransport {
    pub(crate) async fn new(workers: usize) -> Result<Self, ClientError> {
        if workers == 0 {
            let socket = match bind_udp_socket().await {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to bind ephemeral socket: {}", e);
                    return Err(e);
                }
            };

            

            let local_addr = socket
                .local_addr()
                .map_err(|e| ClientError::new(e.to_string()))?;
            let local_addr_storage = slipstream_ffi::socket_addr_to_storage(local_addr);
            Ok(DnsTransport::Shared {
                socket,
                local_addr_storage,
            })
        } else {
            Ok(DnsTransport::Pool(DnsQueryPool::new(workers)))
        }
    }

    pub(crate) async fn send(&self, packet: &[u8], dest: SocketAddr) -> Result<(), ClientError> {
        match self {
            DnsTransport::Shared { socket, .. } => {
                socket
                    .send_to(packet, dest)
                    .await
                    .map_err(|e| ClientError::new(e.to_string()))?;
                Ok(())
            }
            DnsTransport::Pool(pool) => pool.send(packet.to_vec(), dest).await,
        }
    }

    pub(crate) fn local_addr_storage(&self) -> Option<libc::sockaddr_storage> {
        match self {
            DnsTransport::Shared {
                local_addr_storage, ..
            } => Some(*local_addr_storage),
            DnsTransport::Pool(_) => None,
        }
    }
}
