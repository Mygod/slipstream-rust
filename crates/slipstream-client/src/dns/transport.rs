use crate::error::ClientError;
use slipstream_core::net::is_transient_udp_error;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpSocket, TcpStream, UdpSocket,
};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::warn;

const DNS_TCP_MAX_MESSAGE_SIZE: usize = u16::MAX as usize;
const DNS_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(3);

enum TcpReadEvent {
    Packet(Vec<u8>),
    Error(Error),
}

pub(crate) enum DnsTransport {
    Udp(UdpSocket),
    Tcp(TcpResolverTransport),
}

pub(crate) struct TcpResolverTransport {
    resolver: SocketAddr,
    local_addr: SocketAddr,
    writer: OwnedWriteHalf,
    rx: mpsc::UnboundedReceiver<TcpReadEvent>,
    reconnect_needed: bool,
}

impl DnsTransport {
    pub(crate) fn udp(socket: UdpSocket) -> Self {
        Self::Udp(socket)
    }

    pub(crate) async fn tcp(resolver: SocketAddr) -> Result<Self, ClientError> {
        TcpResolverTransport::connect(resolver).await.map(Self::Tcp)
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, Error> {
        match self {
            Self::Udp(socket) => socket.local_addr(),
            Self::Tcp(transport) => Ok(transport.local_addr),
        }
    }

    pub(crate) async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        match self {
            Self::Udp(socket) => socket.recv_from(buf).await,
            Self::Tcp(transport) => transport.recv_from(buf).await,
        }
    }

    pub(crate) fn try_recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr)>, Error> {
        match self {
            Self::Udp(socket) => match socket.try_recv_from(buf) {
                Ok((size, peer)) => Ok(Some((size, peer))),
                Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(None),
                Err(err) => Err(err),
            },
            Self::Tcp(transport) => transport.try_recv_from(buf),
        }
    }

    pub(crate) async fn send_to(&mut self, packet: &[u8], dest: SocketAddr) -> Result<(), Error> {
        match self {
            Self::Udp(socket) => socket.send_to(packet, dest).await.map(|_| ()),
            Self::Tcp(transport) => transport.send(packet, dest).await,
        }
    }

    pub(crate) fn is_transient_recv_error(&self, err: &Error) -> bool {
        match self {
            Self::Udp(_) => is_transient_udp_error(err),
            Self::Tcp(_) => matches!(
                err.kind(),
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
            ),
        }
    }
}

impl TcpResolverTransport {
    async fn connect(resolver: SocketAddr) -> Result<Self, ClientError> {
        let (stream, local_addr) = connect_tcp_resolver(resolver).await?;
        let (reader, writer) = stream.into_split();
        let rx = spawn_tcp_reader(reader);
        Ok(Self {
            resolver,
            local_addr,
            writer,
            rx,
            reconnect_needed: false,
        })
    }

    async fn reconnect(&mut self) -> Result<(), Error> {
        warn!(
            "Reconnecting DNS-over-TCP resolver transport to {}",
            self.resolver
        );
        let (stream, local_addr) = connect_tcp_resolver(self.resolver)
            .await
            .map_err(|err| Error::new(ErrorKind::ConnectionRefused, err.to_string()))?;
        let (reader, writer) = stream.into_split();
        self.local_addr = local_addr;
        self.writer = writer;
        self.rx = spawn_tcp_reader(reader);
        self.reconnect_needed = false;
        Ok(())
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        loop {
            if self.reconnect_needed {
                self.reconnect().await?;
            }
            match self.rx.recv().await {
                Some(TcpReadEvent::Packet(packet)) => {
                    let size = copy_packet(buf, &packet)?;
                    return Ok((size, self.resolver));
                }
                Some(TcpReadEvent::Error(err)) => {
                    warn!("DNS-over-TCP resolver read failed: {}", err);
                    self.reconnect_needed = true;
                }
                None => {
                    warn!("DNS-over-TCP resolver reader stopped");
                    self.reconnect_needed = true;
                }
            }
        }
    }

    fn try_recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, Error> {
        match self.rx.try_recv() {
            Ok(TcpReadEvent::Packet(packet)) => {
                let size = copy_packet(buf, &packet)?;
                Ok(Some((size, self.resolver)))
            }
            Ok(TcpReadEvent::Error(err)) => {
                warn!("DNS-over-TCP resolver read failed: {}", err);
                self.reconnect_needed = true;
                Ok(None)
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.reconnect_needed = true;
                Ok(None)
            }
        }
    }

    async fn send(&mut self, packet: &[u8], dest: SocketAddr) -> Result<(), Error> {
        if dest != self.resolver {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "DNS-over-TCP transport can only send to primary resolver {} (got {})",
                    self.resolver, dest
                ),
            ));
        }
        if self.reconnect_needed {
            self.reconnect().await?;
        }
        match self.write_packet(packet).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("DNS-over-TCP resolver write failed: {}", err);
                self.reconnect_needed = true;
                self.reconnect().await?;
                let retry = self.write_packet(packet).await;
                if retry.is_err() {
                    self.reconnect_needed = true;
                }
                retry
            }
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        match timeout(
            DNS_TCP_WRITE_TIMEOUT,
            write_tcp_dns_message(&mut self.writer, packet),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Error::new(
                ErrorKind::TimedOut,
                format!(
                    "DNS-over-TCP resolver write timed out after {}ms",
                    DNS_TCP_WRITE_TIMEOUT.as_millis()
                ),
            )),
        }
    }
}

async fn connect_tcp_resolver(
    resolver: SocketAddr,
) -> Result<(TcpStream, SocketAddr), ClientError> {
    let socket = match resolver {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|err| ClientError::new(err.to_string()))?;
    protect_tcp_socket(&socket)?;
    let stream = timeout(DNS_TCP_CONNECT_TIMEOUT, socket.connect(resolver))
        .await
        .map_err(|_| ClientError::new("DNS-over-TCP resolver connect timed out"))?
        .map_err(|err| ClientError::new(err.to_string()))?;
    stream
        .set_nodelay(true)
        .map_err(|err| ClientError::new(err.to_string()))?;
    let local_addr = stream
        .local_addr()
        .map_err(|err| ClientError::new(err.to_string()))?;
    Ok((stream, local_addr))
}

#[cfg(target_os = "android")]
fn protect_tcp_socket(socket: &TcpSocket) -> Result<(), ClientError> {
    use std::os::fd::AsRawFd;

    if crate::platform::protect_socket_fd(socket.as_raw_fd()) {
        Ok(())
    } else {
        Err(ClientError::new("Android VPN socket protection failed"))
    }
}

#[cfg(not(target_os = "android"))]
fn protect_tcp_socket(_socket: &TcpSocket) -> Result<(), ClientError> {
    Ok(())
}

fn spawn_tcp_reader(mut reader: OwnedReadHalf) -> mpsc::UnboundedReceiver<TcpReadEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            match read_tcp_dns_message(&mut reader).await {
                Ok(packet) => {
                    if tx.send(TcpReadEvent::Packet(packet)).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    let _ = tx.send(TcpReadEvent::Error(err));
                    break;
                }
            }
        }
    });
    rx
}

async fn read_tcp_dns_message(reader: &mut OwnedReadHalf) -> Result<Vec<u8>, Error> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > DNS_TCP_MAX_MESSAGE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid DNS-over-TCP message length: {}", len),
        ));
    }
    let mut packet = vec![0u8; len];
    reader.read_exact(&mut packet).await?;
    Ok(packet)
}

async fn write_tcp_dns_message(writer: &mut OwnedWriteHalf, packet: &[u8]) -> Result<(), Error> {
    if packet.len() > DNS_TCP_MAX_MESSAGE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("DNS message too large for TCP transport: {}", packet.len()),
        ));
    }
    writer
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(packet).await?;
    writer.flush().await
}

fn copy_packet(buf: &mut [u8], packet: &[u8]) -> Result<usize, Error> {
    if packet.len() > buf.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "DNS response too large for receive buffer: {} > {}",
                packet.len(),
                buf.len()
            ),
        ));
    }
    buf[..packet.len()].copy_from_slice(packet);
    Ok(packet.len())
}
