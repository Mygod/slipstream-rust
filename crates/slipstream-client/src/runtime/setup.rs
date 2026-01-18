use crate::error::ClientError;
use slipstream_dns::max_payload_len_for_domain_with_limit;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::UdpSocket as TokioUdpSocket;

pub(crate) fn compute_mtu(domain: &str, max_qname_len: usize) -> Result<u32, ClientError> {
    let max_payload = max_payload_len_for_domain_with_limit(domain, max_qname_len)
        .map_err(|err| ClientError::new(err.to_string()))?;
    if max_payload == 0 {
        return Err(ClientError::new(
            "Max QNAME length leaves no room for payload; adjust --max-qname-len or domain",
        ));
    }
    Ok(max_payload as u32)
}

pub(crate) async fn bind_udp_socket() -> Result<TokioUdpSocket, ClientError> {
    let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
    TokioUdpSocket::bind(bind_addr).await.map_err(map_io)
}

pub(crate) fn map_io(err: std::io::Error) -> ClientError {
    ClientError::new(err.to_string())
}
