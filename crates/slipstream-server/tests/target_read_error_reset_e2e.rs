mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use socket2::SockRef;
use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, server_bin_path, spawn_client,
    spawn_server, wait_for_log, workspace_root, ClientArgs, ServerArgs,
};

const DOMAIN: &str = "test.example.com";
#[derive(Debug)]
enum TargetEvent {
    Accepted,
    FirstRead { _bytes: usize },
    Closed,
}

struct ResettingTarget {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    rx: Receiver<TargetEvent>,
}

impl ResettingTarget {
    fn spawn() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let accept = listener.accept();
            if stop_flag.load(Ordering::Relaxed) {
                return;
            }
            match accept {
                Ok((mut stream, _)) => {
                    let _ = tx.send(TargetEvent::Accepted);
                    let _ = stream.set_nodelay(true);
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let mut buf = [0u8; 4096];
                    let mut total = 0usize;
                    loop {
                        if stop_flag.load(Ordering::Relaxed) {
                            return;
                        }
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                total = total.saturating_add(n);
                                break;
                            }
                            Err(err)
                                if err.kind() == std::io::ErrorKind::Interrupted
                                    || err.kind() == std::io::ErrorKind::WouldBlock
                                    || err.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                continue;
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = tx.send(TargetEvent::FirstRead { _bytes: total });
                    let _ = SockRef::from(&stream).set_linger(Some(Duration::from_secs(0)));
                    drop(stream);
                    let _ = tx.send(TargetEvent::Closed);
                }
                Err(_) => {
                    let _ = tx.send(TargetEvent::Closed);
                }
            }
        });

        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
            rx,
        })
    }

    fn recv_event(&self, timeout: Duration) -> Option<TargetEvent> {
        self.rx.recv_timeout(timeout).ok()
    }
}

impl Drop for ResettingTarget {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn target_read_error_triggers_client_reset() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let cert = root.join("fixtures/certs/cert.pem");
    let key = root.join("fixtures/certs/key.pem");
    assert!(cert.exists(), "missing fixtures/certs/cert.pem");
    assert!(key.exists(), "missing fixtures/certs/key.pem");

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping target write error e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping target write error e2e test: {}", err);
            return;
        }
    };

    let target = match ResettingTarget::spawn() {
        Ok(target) => target,
        Err(err) => {
            eprintln!("skipping target write error e2e test: {}", err);
            return;
        }
    };

    let (mut server, server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: Some("127.0.0.1"),
        dns_port,
        target_address: &format!("127.0.0.1:{}", target.addr.port()),
        domains: &[DOMAIN],
        cert: &cert,
        key: &key,
        reset_seed_path: None,
        fallback_addr: None,
        idle_timeout_seconds: None,
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
    let server_logs = server_logs.expect("server logs");
    if server.has_exited() {
        eprintln!("skipping target write error e2e test: server failed to start");
        return;
    }

    let (_client, client_logs) = spawn_client(ClientArgs {
        client_bin: &client_bin,
        dns_port,
        tcp_port,
        domain: DOMAIN,
        cert: Some(&cert),
        keep_alive_interval: Some(1),
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
    let client_logs = client_logs.expect("client logs");
    if !wait_for_log(
        &client_logs,
        "Listening on TCP port",
        Duration::from_secs(5),
    ) {
        let snapshot = log_snapshot(&client_logs);
        panic!("client did not start listening\n{}", snapshot);
    }
    if !wait_for_log(&client_logs, "Connection ready", Duration::from_secs(10)) {
        let snapshot = log_snapshot(&client_logs);
        panic!("client did not become ready\n{}", snapshot);
    }

    let client_addr = SocketAddr::from(([127, 0, 0, 1], tcp_port));
    let mut app = TcpStream::connect_timeout(&client_addr, Duration::from_secs(2))
        .expect("connect client tcp port");
    let _ = app.set_nodelay(true);
    app.write_all(b"first-payload")
        .expect("write first payload");

    let mut saw_accept = false;
    let mut saw_read = false;
    let mut saw_close = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (!saw_accept || !saw_read || !saw_close) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Some(event) = target.recv_event(remaining) else {
            break;
        };
        match event {
            TargetEvent::Accepted => saw_accept = true,
            TargetEvent::FirstRead { .. } => saw_read = true,
            TargetEvent::Closed => saw_close = true,
        }
    }
    if !saw_accept || !saw_read || !saw_close {
        let snapshot = log_snapshot(&server_logs);
        panic!(
            "target did not accept/read/close (accept={} read={} close={})\n{}",
            saw_accept, saw_read, saw_close, snapshot
        );
    }

    if !wait_for_log(&server_logs, "target read error", Duration::from_secs(2)) {
        let snapshot = log_snapshot(&server_logs);
        panic!("expected server target read error\n{}", snapshot);
    }

    if !wait_for_log(&client_logs, "reset event=", Duration::from_secs(5)) {
        let client_snapshot = log_snapshot(&client_logs);
        let server_snapshot = log_snapshot(&server_logs);
        panic!(
            "expected client reset event\nclient logs:\n{}\nserver logs:\n{}",
            client_snapshot, server_snapshot
        );
    }
}
