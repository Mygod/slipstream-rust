use crate::error::ClientError;
use slipstream_core::net::{
    bind_first_resolved_with_ipv4_fallback, bind_tcp_listener_addr, bind_udp_socket_addr,
};
use slipstream_dns::max_payload_len_for_domain_with_nonce;
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};

pub(crate) fn compute_mtu(domain: &str) -> Result<u32, ClientError> {
    let mtu = max_payload_len_for_domain_with_nonce(domain)
        .map_err(|err| ClientError::new(err.to_string()))?;
    if mtu == 0 {
        return Err(ClientError::new(
            "MTU computed to zero; check domain length",
        ));
    }
    Ok(mtu as u32)
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

#[cfg(test)]
mod tests {
    use super::compute_mtu;
    use slipstream_dns::{
        build_qname, build_qname_with_nonce, max_payload_len_for_domain_with_nonce,
    };

    #[test]
    fn mtu_matches_dns_query_payload_capacity() {
        let domain = "t.taskboards.org";
        let mtu = compute_mtu(domain).expect("mtu") as usize;
        let max_payload = max_payload_len_for_domain_with_nonce(domain).expect("max payload");

        assert_eq!(mtu, max_payload);
        assert!(build_qname_with_nonce(&vec![0; mtu], domain, 0x1234).is_ok());
        assert!(build_qname_with_nonce(&vec![0; mtu + 1], domain, 0x1234).is_err());
        assert!(build_qname(&vec![0; mtu], domain).is_ok());
    }
}
