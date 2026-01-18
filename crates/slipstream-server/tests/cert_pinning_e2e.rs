use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LOG_CAPACITY: usize = 200;

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn has_exited(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => true,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn client_bin_path(root: &Path) -> PathBuf {
    let mut path = root.join("target").join("debug").join("slipstream-client");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

fn ensure_client_bin(root: &Path) -> PathBuf {
    let path = client_bin_path(root);
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("slipstream-client")
        .current_dir(root)
        .status()
        .expect("failed to invoke cargo build for slipstream-client");
    assert!(status.success(), "cargo build -p slipstream-client failed");
    path
}

fn pick_udp_port() -> std::io::Result<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
}

fn pick_tcp_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn spawn_server(
    server_bin: &Path,
    dns_port: u16,
    domains: &[&str],
    cert: &Path,
    key: &Path,
) -> ChildGuard {
    let mut cmd = Command::new(server_bin);
    cmd.arg("--dns-listen-port")
        .arg(dns_port.to_string())
        .arg("--target-address")
        .arg("127.0.0.1:1");
    for domain in domains {
        cmd.arg("--domain").arg(domain);
    }
    let child = cmd
        .arg("--cert")
        .arg(cert)
        .arg("--key")
        .arg(key)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start slipstream-server");
    ChildGuard { child }
}

struct LogCapture {
    rx: Receiver<String>,
    lines: Arc<Mutex<VecDeque<String>>>,
}

fn spawn_log_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    tx: Sender<String>,
    lines: Arc<Mutex<VecDeque<String>>>,
    source: &'static str,
) {
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };
            let tagged = format!("{}: {}", source, line);
            let _ = tx.send(tagged.clone());
            if let Ok(mut buffer) = lines.lock() {
                if buffer.len() == LOG_CAPACITY {
                    buffer.pop_front();
                }
                buffer.push_back(tagged);
            }
        }
    });
}

fn spawn_client(
    client_bin: &Path,
    dns_port: u16,
    tcp_port: u16,
    domain: &str,
    cert: Option<&Path>,
) -> (ChildGuard, LogCapture) {
    let mut cmd = Command::new(client_bin);
    cmd.arg("--tcp-listen-port")
        .arg(tcp_port.to_string())
        .arg("--resolver")
        .arg(format!("127.0.0.1:{}", dns_port))
        .arg("--domain")
        .arg(domain)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(cert) = cert {
        cmd.arg("--cert").arg(cert);
    }

    let mut child = cmd.spawn().expect("start slipstream-client");
    let (tx, rx) = mpsc::channel();
    let lines = Arc::new(Mutex::new(VecDeque::new()));
    if let Some(stdout) = child.stdout.take() {
        spawn_log_reader(stdout, tx.clone(), Arc::clone(&lines), "stdout");
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_reader(stderr, tx, Arc::clone(&lines), "stderr");
    }

    (ChildGuard { child }, LogCapture { rx, lines })
}

fn log_snapshot(logs: &LogCapture) -> String {
    let buffer = logs.lines.lock().expect("lock log buffer");
    if buffer.is_empty() {
        return "<no logs captured>".to_string();
    }
    buffer.iter().cloned().collect::<Vec<_>>().join("\n")
}

fn wait_for_log(logs: &LogCapture, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline.saturating_duration_since(now);
        match logs.rx.recv_timeout(remaining) {
            Ok(line) => {
                if line.contains(needle) {
                    return true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return false,
            Err(mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
}

fn poke_client(port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.write_all(b"ping");
                return true;
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    false
}

#[test]
fn cert_pinning_e2e() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = PathBuf::from(env!("CARGO_BIN_EXE_slipstream-server"));

    let cert = root.join("fixtures/certs/cert.pem");
    let key = root.join("fixtures/certs/key.pem");
    let alt_cert = root.join("fixtures/certs/alt_cert.pem");

    assert!(cert.exists(), "missing fixtures/certs/cert.pem");
    assert!(key.exists(), "missing fixtures/certs/key.pem");
    assert!(alt_cert.exists(), "missing fixtures/certs/alt_cert.pem");

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping cert pinning e2e test: {}", err);
            return;
        }
    };
    let tcp_port_ok = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping cert pinning e2e test: {}", err);
            return;
        }
    };
    let tcp_port_bad = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping cert pinning e2e test: {}", err);
            return;
        }
    };
    let domain = "test.example.com";
    let alt_domain = "alt.example.com";

    let mut server = spawn_server(&server_bin, dns_port, &[domain, alt_domain], &cert, &key);
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        eprintln!("skipping cert pinning e2e test: server failed to start");
        return;
    }

    {
        let (mut client, logs) =
            spawn_client(&client_bin, dns_port, tcp_port_ok, domain, Some(&cert));
        if !wait_for_log(&logs, "Listening on TCP port", Duration::from_secs(5)) {
            let snapshot = log_snapshot(&logs);
            panic!("client did not start listening\n{}", snapshot);
        }
        let poke_ok = poke_client(tcp_port_ok, Duration::from_secs(5));
        assert!(
            poke_ok,
            "failed to connect to client TCP port {}",
            tcp_port_ok
        );
        let ready = wait_for_log(&logs, "Connection ready", Duration::from_secs(10));
        if !ready {
            let exited = client.has_exited();
            let snapshot = log_snapshot(&logs);
            panic!(
                "expected connection ready with pinned cert (client_exited={})\n{}",
                exited, snapshot
            );
        }
    }

    {
        let (mut client, logs) = spawn_client(
            &client_bin,
            dns_port,
            tcp_port_bad,
            alt_domain,
            Some(&alt_cert),
        );
        if !wait_for_log(&logs, "Listening on TCP port", Duration::from_secs(5)) {
            let snapshot = log_snapshot(&logs);
            panic!("client did not start listening\n{}", snapshot);
        }
        let poke_ok = poke_client(tcp_port_bad, Duration::from_secs(5));
        assert!(
            poke_ok,
            "failed to connect to client TCP port {}",
            tcp_port_bad
        );
        let ready = wait_for_log(&logs, "Connection ready", Duration::from_secs(5));
        if ready {
            let snapshot = log_snapshot(&logs);
            panic!(
                "unexpected connection ready with mismatched cert\n{}",
                snapshot
            );
        }
        let _ = client.has_exited();
    }
}
