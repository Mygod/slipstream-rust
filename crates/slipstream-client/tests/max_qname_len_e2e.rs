use slipstream_dns::decode_query;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bind_resolver_socket() -> std::io::Result<(UdpSocket, String)> {
    if let Ok(socket) = UdpSocket::bind("[::1]:0") {
        let port = socket.local_addr()?.port();
        return Ok((socket, format!("[::1]:{}", port)));
    }
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let port = socket.local_addr()?.port();
    Ok((socket, format!("127.0.0.1:{}", port)))
}

#[test]
fn max_qname_len_e2e() {
    let domain = "example.com";
    let max_qname_len = 101usize;
    let (socket, resolver) = match bind_resolver_socket() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("skipping max qname len e2e test: {}", err);
            return;
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set UDP timeout");

    let client_bin = PathBuf::from(env!("CARGO_BIN_EXE_slipstream-client"));
    let child = Command::new(client_bin)
        .arg("--tcp-listen-port")
        .arg("0")
        .arg("--resolver")
        .arg(resolver)
        .arg("--domain")
        .arg(domain)
        .arg("--max-qname-len")
        .arg(max_qname_len.to_string())
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start slipstream-client");
    let _child_guard = ChildGuard { child };

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 2048];
    let mut observed_len = None;

    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                if let Ok(decoded) = decode_query(&buf[..size], domain) {
                    let qname_len = decoded.question.name.trim_end_matches('.').len();
                    observed_len = Some(qname_len);
                    break;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(err) => panic!("failed to read UDP query: {}", err),
        }
    }

    let observed_len = observed_len.expect("no DNS query captured from client");
    assert!(
        observed_len <= max_qname_len,
        "observed QNAME length {} exceeds limit {}",
        observed_len,
        max_qname_len
    );
}
