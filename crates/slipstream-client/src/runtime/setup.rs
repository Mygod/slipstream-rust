use crate::error::ClientError;
use slipstream_core::net::{
    bind_first_resolved_with_ipv4_fallback, bind_tcp_listener_addr, bind_udp_socket_addr,
};
use slipstream_dns::max_payload_len_for_domain;
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};

pub(crate) fn compute_mtu(domain: &str) -> Result<u32, ClientError> {
    let mtu =
        max_payload_len_for_domain(domain).map_err(|err| ClientError::new(err.to_string()))? as u32;
    if mtu == 0 {
        return Err(ClientError::new(
            "MTU computed to zero; check domain length",
        ));
    }
    Ok(mtu)
}

pub(crate) async fn bind_udp_socket() -> Result<TokioUdpSocket, ClientError> {
    let socket = bind_first_resolved_with_ipv4_fallback(
        "::",
        0,
        |addr| bind_udp_socket_addr(addr, "UDP socket"),
        "UDP socket",
    )
    .await
    .map(|(socket, _)| socket)
    .map_err(map_io)?;
    protect_udp_socket(&socket)?;
    Ok(socket)
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

#[cfg(target_os = "android")]
fn protect_udp_socket(socket: &TokioUdpSocket) -> Result<(), ClientError> {
    use std::os::fd::AsRawFd;

    if crate::platform::protect_socket_fd(socket.as_raw_fd()) {
        Ok(())
    } else {
        Err(ClientError::new("Android VPN socket protection failed"))
    }
}

#[cfg(not(target_os = "android"))]
fn protect_udp_socket(_socket: &TokioUdpSocket) -> Result<(), ClientError> {
    Ok(())
}
