mod support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, server_bin_path, spawn_client,
    spawn_server, wait_for_log, workspace_root, ClientArgs, ServerArgs,
};

const DOMAIN: &str = "test.example.com";
const RESPONSE_BYTES: usize = 64 * 1024;
const RESPONSE_CHUNK_BYTES: usize = 4096;
const RESPONSE_CHUNK_DELAY_MS: u64 = 50;

#[derive(Debug)]
enum TargetEvent {
    Accepted,
    RequestRead { _bytes: usize },
    ResponseSent { _bytes: usize },
    ResponseFailed,
}

struct DelayedTarget {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    conn_handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    rx: Receiver<TargetEvent>,
}

impl DelayedTarget {
    fn spawn(app_closed_rx: Receiver<()>) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let conn_handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let conn_handles_clone = Arc::clone(&conn_handles);

        let handle = thread::spawn(move || {
            let accept = listener.accept();
            if stop_flag.load(Ordering::Relaxed) {
                return;
            }
            match accept {
                Ok((mut stream, _)) => {
                    let _ = tx.send(TargetEvent::Accepted);
                    let stop_conn = Arc::clone(&stop_flag);
                    let join = thread::spawn(move || {
                        let _ = stream.set_nodelay(true);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let mut buf = [0u8; 4096];
                        let mut total = 0usize;
                        loop {
                            if stop_conn.load(Ordering::Relaxed) {
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
                        let _ = tx.send(TargetEvent::RequestRead { _bytes: total });
                        if app_closed_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                            let _ = tx.send(TargetEvent::ResponseFailed);
                            return;
                        }
                        if stop_conn.load(Ordering::Relaxed) {
                            return;
                        }
                        let response = vec![0u8; RESPONSE_BYTES];
                        for chunk in response.chunks(RESPONSE_CHUNK_BYTES) {
                            if stream.write_all(chunk).is_err() {
                                let _ = tx.send(TargetEvent::ResponseFailed);
                                return;
                            }
                            thread::sleep(Duration::from_millis(RESPONSE_CHUNK_DELAY_MS));
                        }
                        let _ = stream.shutdown(Shutdown::Write);
                        let _ = tx.send(TargetEvent::ResponseSent {
                            _bytes: response.len(),
                        });
                    });
                    if let Ok(mut handles) = conn_handles_clone.lock() {
                        handles.push(join);
                    }
                }
                Err(_) => {
                    let _ = tx.send(TargetEvent::ResponseFailed);
                }
            }
        });

        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
            conn_handles,
            rx,
        })
    }

    fn recv_event(&self, timeout: Duration) -> Option<TargetEvent> {
        self.rx.recv_timeout(timeout).ok()
    }
}

impl Drop for DelayedTarget {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(mut handles) = self.conn_handles.lock() {
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

#[test]
fn epipe_triggers_quic_reset() {
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
            eprintln!("skipping epipe reset e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping epipe reset e2e test: {}", err);
            return;
        }
    };

    let (app_closed_tx, app_closed_rx) = mpsc::channel();
    let target = match DelayedTarget::spawn(app_closed_rx) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("skipping epipe reset e2e test: {}", err);
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
        eprintln!("skipping epipe reset e2e test: server failed to start");
        return;
    }

    let (_client, client_logs) = spawn_client(ClientArgs {
        client_bin: &client_bin,
        dns_port,
        tcp_port,
        domain: DOMAIN,
        cert: Some(&cert),
        keep_alive_interval: Some(0),
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
    app.write_all(b"epipe-reset-test")
        .expect("write app payload");

    let mut saw_accept = false;
    let mut saw_read = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (!saw_accept || !saw_read) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Some(event) = target.recv_event(remaining) else {
            break;
        };
        match event {
            TargetEvent::Accepted => saw_accept = true,
            TargetEvent::RequestRead { .. } => saw_read = true,
            _ => {}
        }
    }
    if !saw_accept || !saw_read {
        let snapshot = log_snapshot(&server_logs);
        panic!(
            "target did not accept/read request (accepted={} read={})\n{}",
            saw_accept, saw_read, snapshot
        );
    }

    drop(app);
    let _ = app_closed_tx.send(());

    let mut response_attempted = false;
    let response_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < response_deadline && !response_attempted {
        let remaining = response_deadline.saturating_duration_since(Instant::now());
        let Some(event) = target.recv_event(remaining) else {
            break;
        };
        match event {
            TargetEvent::ResponseSent { .. } => response_attempted = true,
            TargetEvent::ResponseFailed => response_attempted = true,
            _ => {}
        }
    }
    if !response_attempted {
        let snapshot = log_snapshot(&server_logs);
        panic!("target did not attempt response\n{}", snapshot);
    }

    let saw_local_error = wait_for_any_log(
        &client_logs,
        &["tcp write error", "tcp read error"],
        Duration::from_secs(2),
    );
    if saw_local_error.is_none() {
        let snapshot = log_snapshot(&client_logs);
        panic!("expected client tcp read/write error\n{}", snapshot);
    }

    if !wait_for_log(&server_logs, "reset event=", Duration::from_secs(2)) {
        let client_snapshot = log_snapshot(&client_logs);
        let server_snapshot = log_snapshot(&server_logs);
        panic!(
            "expected server reset event\nclient logs:\n{}\nserver logs:\n{}",
            client_snapshot, server_snapshot
        );
    }
}

fn wait_for_any_log(
    logs: &support::LogCapture,
    needles: &[&str],
    timeout: Duration,
) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline.saturating_duration_since(now);
        match logs.rx.recv_timeout(remaining) {
            Ok(line) => {
                if needles.iter().any(|needle| line.contains(needle)) {
                    return Some(line);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}
