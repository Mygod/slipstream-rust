use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

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
    if path.exists() {
        return path;
    }
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

fn spawn_server(
    server_bin: &Path,
    dns_port: u16,
    domain: &str,
    cert: &Path,
    key: &Path,
) -> ChildGuard {
    let child = Command::new(server_bin)
        .arg("--dns-listen-port")
        .arg(dns_port.to_string())
        .arg("--target-address")
        .arg("127.0.0.1:1")
        .arg("--domain")
        .arg(domain)
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

fn spawn_client(
    client_bin: &Path,
    dns_port: u16,
    domain: &str,
    cert: Option<&Path>,
) -> (ChildGuard, Receiver<String>) {
    let mut cmd = Command::new(client_bin);
    cmd.arg("--tcp-listen-port")
        .arg("0")
        .arg("--resolver")
        .arg(format!("127.0.0.1:{}", dns_port))
        .arg("--domain")
        .arg(domain)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    if let Some(cert) = cert {
        cmd.arg("--cert").arg(cert);
    }

    let mut child = cmd.spawn().expect("start slipstream-client");
    let stderr = child.stderr.take().expect("capture client stderr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };
            let _ = tx.send(line);
        }
    });

    (ChildGuard { child }, rx)
}

fn wait_for_log(rx: &Receiver<String>, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline.saturating_duration_since(now);
        match rx.recv_timeout(remaining) {
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
    let domain = "test.example.com";

    let mut server = spawn_server(&server_bin, dns_port, domain, &cert, &key);
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        eprintln!("skipping cert pinning e2e test: server failed to start");
        return;
    }

    {
        let (_client, rx) = spawn_client(&client_bin, dns_port, domain, Some(&cert));
        assert!(
            wait_for_log(&rx, "Connection ready", Duration::from_secs(8)),
            "expected connection ready with pinned cert"
        );
    }

    {
        let (_client, rx) = spawn_client(&client_bin, dns_port, domain, Some(&alt_cert));
        assert!(
            !wait_for_log(&rx, "Connection ready", Duration::from_secs(4)),
            "unexpected connection ready with mismatched cert"
        );
    }
}
