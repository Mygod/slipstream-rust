use crate::error::ClientError;
use slipstream_core::net::{
    bind_first_resolved_with_ipv4_fallback, bind_tcp_listener_addr, bind_udp_socket_addr,
};
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};

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
    bind_first_resolved_with_ipv4_fallback(
        "::",
        0,
        |addr| bind_udp_socket_addr(addr, "UDP socket"),
        "UDP socket",
    )
    .await
    .map(|(socket, _)| socket)
    .map_err(map_io)
}

pub(crate) async fn bind_tcp_listener(
    host: &str,
    port: u16,
) -> Result<(TokioTcpListener, String), std::io::Error> {
    bind_first_resolved_with_ipv4_fallback(host, port, bind_tcp_listener_addr, "TCP listener").await
}

pub(crate) fn map_io(err: std::io::Error) -> ClientError {
    ClientError::new(err.to_string())
}
