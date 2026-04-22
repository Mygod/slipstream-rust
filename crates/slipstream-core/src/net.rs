use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{lookup_host, TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};

pub fn is_transient_udp_error(err: &Error) -> bool {
    match err.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {
            return true;
        }
        _ => {}
    }

    matches!(
        err.raw_os_error(),
        Some(code) if code == libc::ENETUNREACH || code == libc::EHOSTUNREACH
    )
}

pub async fn bind_first_resolved<T, F>(
    host: &str,
    port: u16,
    mut bind_addr: F,
    kind: &str,
) -> Result<T, Error>
where
    F: FnMut(SocketAddr) -> Result<T, Error>,
{
    let addrs: Vec<SocketAddr> = lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(Error::new(
            ErrorKind::AddrNotAvailable,
            format!("No addresses resolved for {}:{}", host, port),
        ));
    }
    let mut last_err = None;
    for addr in addrs {
        match bind_addr(addr) {
            Ok(bound) => return Ok(bound),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::new(
            ErrorKind::AddrNotAvailable,
            format!("Failed to bind {} on {}:{}", kind, host, port),
        )
    }))
}

pub async fn bind_first_resolved_with_ipv4_fallback<T, F>(
    host: &str,
    port: u16,
    mut bind_addr: F,
    kind: &str,
) -> Result<(T, String), Error>
where
    F: FnMut(SocketAddr) -> Result<T, Error>,
{
    match bind_first_resolved(host, port, &mut bind_addr, kind).await {
        Ok(bound) => Ok((bound, host.to_string())),
        Err(err) if is_ipv6_unspecified_host(host) && is_ipv6_unavailable_error(&err) => {
            let fallback_host = Ipv4Addr::UNSPECIFIED.to_string();
            tracing::warn!(
                "Failed to bind {} on {}:{} ({}); falling back to {}",
                kind,
                host,
                port,
                err,
                fallback_host
            );
            match bind_first_resolved(&fallback_host, port, &mut bind_addr, kind).await {
                Ok(bound) => Ok((bound, fallback_host)),
                Err(fallback_err) => Err(Error::new(
                    fallback_err.kind(),
                    format!(
                        "Failed to bind {} on {}:{} ({}) or {}:{} ({})",
                        kind, host, port, err, fallback_host, port, fallback_err
                    ),
                )),
            }
        }
        Err(err) => Err(err),
    }
}

pub fn is_ipv6_unspecified_host(host: &str) -> bool {
    host.parse::<Ipv6Addr>()
        .map(|addr| addr.is_unspecified())
        .unwrap_or(false)
}

pub fn is_ipv6_unavailable_error(err: &Error) -> bool {
    if err.kind() == ErrorKind::AddrNotAvailable {
        return true;
    }

    matches!(err.raw_os_error(), Some(code) if is_ipv6_unavailable_error_code(code))
}

#[cfg(windows)]
fn is_ipv6_unavailable_error_code(code: i32) -> bool {
    code == libc::WSAEAFNOSUPPORT || code == libc::WSAEPROTONOSUPPORT
}

#[cfg(not(windows))]
fn is_ipv6_unavailable_error_code(code: i32) -> bool {
    code == libc::EAFNOSUPPORT || code == libc::EPROTONOSUPPORT
}

pub fn bind_tcp_listener_addr(addr: SocketAddr) -> Result<TokioTcpListener, Error> {
    let socket = Socket::new(socket_domain(&addr), Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(not(windows))]
    if let Err(err) = socket.set_reuse_address(true) {
        tracing::warn!("Failed to enable SO_REUSEADDR on {}: {}", addr, err);
    }
    if let SocketAddr::V6(_) = addr {
        if let Err(err) = socket.set_only_v6(false) {
            tracing::warn!(
                "Failed to enable dual-stack TCP listener on {}: {}",
                addr,
                err
            );
        }
    }
    let sock_addr = SockAddr::from(addr);
    socket.bind(&sock_addr)?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TokioTcpListener::from_std(std_listener)
}

pub fn bind_udp_socket_addr(
    addr: SocketAddr,
    dual_stack_label: &str,
) -> Result<TokioUdpSocket, Error> {
    let socket = Socket::new(socket_domain(&addr), Type::DGRAM, Some(Protocol::UDP))?;
    if let SocketAddr::V6(_) = addr {
        if let Err(err) = socket.set_only_v6(false) {
            tracing::warn!(
                "Failed to enable dual-stack {} on {}: {}",
                dual_stack_label,
                addr,
                err
            );
        }
    }
    let sock_addr = SockAddr::from(addr);
    socket.bind(&sock_addr)?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    TokioUdpSocket::from_std(std_socket)
}

fn socket_domain(addr: &SocketAddr) -> Domain {
    match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_platform_ipv6_unavailable_error() {
        #[cfg(windows)]
        let err = Error::from_raw_os_error(libc::WSAEAFNOSUPPORT);
        #[cfg(not(windows))]
        let err = Error::from_raw_os_error(libc::EAFNOSUPPORT);

        assert!(is_ipv6_unavailable_error(&err));
    }
}
