use super::*;
use slipstream_dns::{encode_query, QueryParams, CLASS_IN, RR_A};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

fn build_dns_query(name: &str) -> Vec<u8> {
    encode_query(&QueryParams {
        id: 1,
        qname: name,
        qtype: RR_A,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    })
    .expect("dns query")
}

fn spawn_fallback_echo(socket: Arc<TokioUdpSocket>, notify_tx: mpsc::UnboundedSender<Vec<u8>>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        loop {
            let (size, peer) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(_) => break,
            };
            let payload = buf[..size].to_vec();
            let _ = notify_tx.send(payload.clone());
            let _ = socket.send_to(&payload, peer).await;
        }
    });
}

fn build_empty_question_query() -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

async fn recv_with_timeout(socket: &TokioUdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    timeout(Duration::from_secs(1), socket.recv_from(buf))
        .await
        .expect("recv timeout")
        .expect("recv failed")
}

#[tokio::test]
async fn fallback_forwards_non_dns_then_sticks() {
    let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let main_addr = main_socket.local_addr().unwrap();
    let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fallback_addr = fallback_socket.local_addr().unwrap();
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
    spawn_fallback_echo(fallback_socket, notify_tx);

    let mut fallback_mgr = Some(FallbackManager::new(
        main_socket.clone(),
        fallback_addr,
        false,
    ));
    let domains = vec!["example.com"];
    let local_addr_storage = dummy_sockaddr_storage();
    let context = PacketContext {
        domains: &domains,
        quic: std::ptr::null_mut(),
        current_time: 0,
        local_addr_storage: &local_addr_storage,
    };

    let non_dns = b"nope";
    client_socket.send_to(non_dns, main_addr).await.unwrap();
    let mut recv_buf = [0u8; 64];
    let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
    let mut slots = Vec::new();
    handle_packet(
        &mut slots,
        &recv_buf[..size],
        peer,
        &context,
        &mut fallback_mgr,
    )
    .await
    .unwrap();

    let mut client_buf = [0u8; 64];
    let (size, _) = recv_with_timeout(&client_socket, &mut client_buf).await;
    assert_eq!(&client_buf[..size], non_dns);
    let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
        .await
        .expect("fallback receive timeout")
        .expect("fallback receive");
    assert_eq!(echoed, non_dns);

    let dns_packet = build_dns_query("example.com");
    client_socket.send_to(&dns_packet, main_addr).await.unwrap();
    let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
    let mut slots = Vec::new();
    handle_packet(
        &mut slots,
        &recv_buf[..size],
        peer,
        &context,
        &mut fallback_mgr,
    )
    .await
    .unwrap();

    let (size, _) = recv_with_timeout(&client_socket, &mut client_buf).await;
    assert_eq!(&client_buf[..size], dns_packet);
    let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
        .await
        .expect("fallback receive timeout")
        .expect("fallback receive");
    assert_eq!(echoed, dns_packet);

    if let Some(manager) = fallback_mgr.as_mut() {
        for session in manager.sessions.values() {
            let _ = session.shutdown_tx.send(true);
        }
    }
}

#[tokio::test]
async fn fallback_forwards_empty_question_query() {
    let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let main_addr = main_socket.local_addr().unwrap();
    let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fallback_addr = fallback_socket.local_addr().unwrap();
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
    spawn_fallback_echo(fallback_socket, notify_tx);

    let mut fallback_mgr = Some(FallbackManager::new(
        main_socket.clone(),
        fallback_addr,
        false,
    ));
    let domains = vec!["example.com"];
    let local_addr_storage = dummy_sockaddr_storage();
    let context = PacketContext {
        domains: &domains,
        quic: std::ptr::null_mut(),
        current_time: 0,
        local_addr_storage: &local_addr_storage,
    };

    let qdcount_zero = build_empty_question_query();
    client_socket
        .send_to(&qdcount_zero, main_addr)
        .await
        .unwrap();
    let mut recv_buf = [0u8; 64];
    let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
    let mut slots = Vec::new();
    handle_packet(
        &mut slots,
        &recv_buf[..size],
        peer,
        &context,
        &mut fallback_mgr,
    )
    .await
    .unwrap();

    let mut client_buf = [0u8; 64];
    let (size, _) = recv_with_timeout(&client_socket, &mut client_buf).await;
    assert_eq!(&client_buf[..size], qdcount_zero.as_slice());
    let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
        .await
        .expect("fallback receive timeout")
        .expect("fallback receive");
    assert_eq!(echoed, qdcount_zero);

    if let Some(manager) = fallback_mgr.as_mut() {
        for session in manager.sessions.values() {
            let _ = session.shutdown_tx.send(true);
        }
    }
}

#[tokio::test]
async fn fallback_switches_after_non_dns_streak() {
    let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let main_addr = main_socket.local_addr().unwrap();
    let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fallback_addr = fallback_socket.local_addr().unwrap();
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
    spawn_fallback_echo(fallback_socket, notify_tx);

    let mut fallback_mgr = Some(FallbackManager::new(
        main_socket.clone(),
        fallback_addr,
        false,
    ));
    let domains = vec!["example.com"];
    let local_addr_storage = dummy_sockaddr_storage();
    let context = PacketContext {
        domains: &domains,
        quic: std::ptr::null_mut(),
        current_time: 0,
        local_addr_storage: &local_addr_storage,
    };

    let dns_packet = build_dns_query("example.com");
    client_socket.send_to(&dns_packet, main_addr).await.unwrap();
    let mut recv_buf = [0u8; 64];
    let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
    let mut slots = Vec::new();
    handle_packet(
        &mut slots,
        &recv_buf[..size],
        peer,
        &context,
        &mut fallback_mgr,
    )
    .await
    .unwrap();

    if let Some(manager) = fallback_mgr.as_ref() {
        assert!(manager.dns_peers.contains_key(&peer));
    }

    let non_dns = b"nope";
    for _ in 0..(NON_DNS_STREAK_THRESHOLD - 1) {
        client_socket.send_to(non_dns, main_addr).await.unwrap();
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();
    }

    assert!(notify_rx.try_recv().is_err());

    client_socket.send_to(non_dns, main_addr).await.unwrap();
    let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
    let mut slots = Vec::new();
    handle_packet(
        &mut slots,
        &recv_buf[..size],
        peer,
        &context,
        &mut fallback_mgr,
    )
    .await
    .unwrap();

    let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
        .await
        .expect("fallback receive timeout")
        .expect("fallback receive");
    assert_eq!(echoed, non_dns);

    if let Some(manager) = fallback_mgr.as_mut() {
        for session in manager.sessions.values() {
            let _ = session.shutdown_tx.send(true);
        }
    }
}

#[tokio::test]
async fn fallback_session_expires_before_forwarding() {
    let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let main_addr = main_socket.local_addr().unwrap();
    let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fallback_addr = fallback_socket.local_addr().unwrap();
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
    spawn_fallback_echo(fallback_socket, notify_tx);

    let mut fallback_mgr = Some(FallbackManager::new(
        main_socket.clone(),
        fallback_addr,
        false,
    ));
    let domains = vec!["example.com"];
    let local_addr_storage = dummy_sockaddr_storage();
    let context = PacketContext {
        domains: &domains,
        quic: std::ptr::null_mut(),
        current_time: 0,
        local_addr_storage: &local_addr_storage,
    };

    let non_dns = b"nope";
    client_socket.send_to(non_dns, main_addr).await.unwrap();
    let mut recv_buf = [0u8; 64];
    let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
    let mut slots = Vec::new();
    handle_packet(
        &mut slots,
        &recv_buf[..size],
        peer,
        &context,
        &mut fallback_mgr,
    )
    .await
    .unwrap();

    let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
        .await
        .expect("fallback receive timeout")
        .expect("fallback receive");
    assert_eq!(echoed, non_dns);

    if let Some(manager) = fallback_mgr.as_mut() {
        if let Some(session) = manager.sessions.get(&peer) {
            if let Ok(mut last_seen) = session.last_seen.lock() {
                *last_seen = Instant::now() - FALLBACK_IDLE_TIMEOUT - Duration::from_secs(1);
            }
        }
    }

    let dns_packet = build_dns_query("example.com");
    client_socket.send_to(&dns_packet, main_addr).await.unwrap();
    let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
    let mut slots = Vec::new();
    handle_packet(
        &mut slots,
        &recv_buf[..size],
        peer,
        &context,
        &mut fallback_mgr,
    )
    .await
    .unwrap();

    assert!(
        timeout(Duration::from_millis(200), notify_rx.recv())
            .await
            .is_err(),
        "fallback endpoint should not see DNS query after idle"
    );

    if let Some(manager) = fallback_mgr.as_mut() {
        for session in manager.sessions.values() {
            let _ = session.shutdown_tx.send(true);
        }
    }
}
