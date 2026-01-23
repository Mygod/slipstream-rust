use crate::error::ClientError;
use slipstream_core::net::{bind_first_resolved, bind_tcp_listener_addr, bind_udp_socket_addr};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::net::{lookup_host, TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};
use tracing::warn;

pub(crate) fn compute_mtu(domain_len: usize) -> Result<u32, ClientError> {
    if domain_len >= 240 {
        return Err(ClientError::new(
            "Domain name is too long for DNS transport",
        ));
    }
    let mtu = ((240.0 - domain_len as f64) / 1.6) as u32;
    if mtu == 0 {
        return Err(ClientError::new(
            "MTU computed to zero; check domain length",
        ));
    }
    Ok(mtu)
}

pub(crate) async fn bind_udp_socket() -> Result<TokioUdpSocket, ClientError> {
    // Try IPv6 dual-stack first (works on most systems), fall back to IPv4
    let bind_addr_v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
    match bind_udp_socket_addr(bind_addr_v6, "UDP socket") {
        Ok(socket) => Ok(socket),
        Err(err) => {
            // Fall back to IPv4 if IPv6 is not available (common on Windows)
            warn!(
                "Failed to bind UDP socket on IPv6 {}: {}. Falling back to IPv4",
                bind_addr_v6, err
            );
            let bind_addr_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
            bind_udp_socket_addr(bind_addr_v4, "UDP socket").map_err(map_io)
        }
    }
}

pub(crate) async fn bind_tcp_listener(
    host: &str,
    port: u16,
) -> Result<TokioTcpListener, ClientError> {
    bind_first_resolved(host, port, bind_tcp_listener_addr, "TCP listener")
        .await
        .map_err(map_io)
}

pub(crate) fn map_io(err: std::io::Error) -> ClientError {
    ClientError::new(err.to_string())
}
