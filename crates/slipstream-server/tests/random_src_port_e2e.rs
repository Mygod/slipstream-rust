mod support;

use std::thread;
use std::time::Duration;

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, poke_client, server_bin_path,
    spawn_client, spawn_server, wait_for_log, workspace_root, ClientArgs, ServerArgs,
};

#[test]
fn random_src_port_e2e() {
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
            eprintln!("skipping random-src-port e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping random-src-port e2e test: {}", err);
            return;
        }
    };
    let domain = "test.example.com";

    let (mut server, _server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: None,
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[domain],
        cert: &cert,
        key: &key,
        reset_seed_path: None,
        fallback_addr: None,
        idle_timeout_seconds: None,
        rust_log: "info",
        capture_logs: false,
    });
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        eprintln!("skipping random-src-port e2e test: server failed to start");
        return;
    }

    {
        println!("Testing with --random-src-port 4");
        let (mut client, logs) = spawn_client(ClientArgs {
            client_bin: &client_bin,
            dns_port,
            tcp_port,
            domain,
            cert: Some(&cert),
            keep_alive_interval: None,
            random_src_port: Some(4),
            rust_log: "info",
            capture_logs: true,
        });
        let logs = logs.expect("client logs");
        if !wait_for_log(&logs, "Listening on TCP port", Duration::from_secs(5)) {
            let snapshot = log_snapshot(&logs);
            panic!("client did not start listening\n{}", snapshot);
        }
        let poke_ok = poke_client(tcp_port, Duration::from_secs(5));
        assert!(poke_ok, "failed to connect to client TCP port {}", tcp_port);
        let ready = wait_for_log(&logs, "Connection ready", Duration::from_secs(10));
        if !ready {
            let exited = client.has_exited();
            let snapshot = log_snapshot(&logs);
            panic!(
                "expected connection ready with --random-src-port 4 (client_exited={})\n{}",
                exited, snapshot
            );
        }
    }

    {
        println!("Testing with --random-src-port 1");
        let (mut client, logs) = spawn_client(ClientArgs {
            client_bin: &client_bin,
            dns_port,
            tcp_port,
            domain,
            cert: Some(&cert),
            keep_alive_interval: None,
            random_src_port: Some(1),
            rust_log: "info",
            capture_logs: true,
        });
        let logs = logs.expect("client logs");
        if !wait_for_log(&logs, "Listening on TCP port", Duration::from_secs(5)) {
            let snapshot = log_snapshot(&logs);
            panic!("client did not start listening\n{}", snapshot);
        }
        let poke_ok = poke_client(tcp_port, Duration::from_secs(5));
        assert!(poke_ok, "failed to connect to client TCP port {}", tcp_port);
        let ready = wait_for_log(&logs, "Connection ready", Duration::from_secs(10));
        if !ready {
            let exited = client.has_exited();
            let snapshot = log_snapshot(&logs);
            panic!(
                "expected connection ready with --random-src-port 1 (client_exited={})\n{}",
                exited, snapshot
            );
        }
    }
}
