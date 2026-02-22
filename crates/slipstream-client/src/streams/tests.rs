use super::callback::handle_stream_data;
use super::state::{ClientStream, StreamRecvState, StreamSendState};
use super::test_hooks;
use super::*;
use slipstream_core::flow_control::FlowControlState;
use slipstream_core::test_support::ResetOnDrop;
use std::sync::Arc;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{sleep, timeout, Duration};

#[test]
fn add_to_stream_fin_failure_removes_stream() {
    let _guard = ResetOnDrop::new(|| test_hooks::set_add_to_stream_failures(0));
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState::default(),
        },
    );

    test_hooks::set_add_to_stream_failures(1);

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamClosed { stream_id },
    );

    assert!(
        !state.streams.contains_key(&stream_id),
        "stream state should be removed when add_to_stream(fin) fails"
    );
}

#[test]
fn remote_fin_keeps_local_read_open() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, mut write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: Some(data_rx),
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState::default(),
        },
    );

    handle_stream_data(std::ptr::null_mut(), &mut state, stream_id, true, &[]);

    let stream = state
        .streams
        .get(&stream_id)
        .expect("stream should remain after remote fin");
    assert_eq!(stream.recv_state, StreamRecvState::FinReceived);
    assert_eq!(stream.send_state, StreamSendState::Open);
    assert!(
        stream.data_rx.is_some(),
        "local TCP read side should stay open after remote fin"
    );
    assert!(
        matches!(write_rx.try_recv(), Ok(super::io_tasks::StreamWrite::Fin)),
        "expected a TCP fin to be enqueued"
    );
}

#[test]
fn stream_removal_requires_both_halves_closed() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();
    let (_data_tx, data_rx) = mpsc::channel(1);

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: Some(data_rx),
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState::default(),
        },
    );

    handle_stream_data(std::ptr::null_mut(), &mut state, stream_id, true, &[]);
    assert!(
        state.streams.contains_key(&stream_id),
        "stream should remain when only recv side is closed"
    );

    if let Some(stream) = state.streams.get_mut(&stream_id) {
        stream.send_state = StreamSendState::FinQueued;
    }
    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamWriteDrained {
            stream_id,
            bytes: 0,
            generation: 0,
        },
    );
    assert!(
        !state.streams.contains_key(&stream_id),
        "stream should be removed once both halves are closed"
    );
}

#[test]
fn local_fin_does_not_remove_until_recv_fin() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::FinQueued,
            flow: FlowControlState::default(),
        },
    );

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamWriteDrained {
            stream_id,
            bytes: 0,
            generation: 0,
        },
    );

    assert!(
        state.streams.contains_key(&stream_id),
        "stream should remain when only send side is closed"
    );
}

#[test]
fn mark_active_stream_failure_removes_stream() {
    let _guard = ResetOnDrop::new(|| test_hooks::set_mark_active_stream_failures(0));
    let _limit_guard = ResetOnDrop::new(|| acceptor::ClientAcceptor::set_test_limit(0));
    acceptor::ClientAcceptor::set_test_limit(1);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("build tokio runtime");
    rt.block_on(async {
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            stream
        });
        let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let stream = accept.await.expect("accept join");

        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());
        let acceptor = acceptor::ClientAcceptor::new();
        let reservation = acceptor.reserve_for_test().await;
        let mut state = ClientState::new(command_tx, data_notify, false, acceptor);

        test_hooks::set_mark_active_stream_failures(1);

        handle_command(
            std::ptr::null_mut(),
            &mut state as *mut _,
            Command::NewStream {
                stream,
                reservation,
            },
        );

        assert!(
            state.streams.is_empty(),
            "stream state should be removed when mark_active_stream fails"
        );
    });
}

#[test]
fn stale_task_command_is_ignored_after_reconnect() {
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let acceptor = acceptor::ClientAcceptor::new();
    let mut state = ClientState::new(command_tx, data_notify, false, acceptor);
    let stream_id = 4;
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (read_abort_tx, _read_abort_rx) = oneshot::channel();

    state.streams.insert(
        stream_id,
        ClientStream {
            write_tx,
            read_abort_tx: Some(read_abort_tx),
            data_rx: None,
            tx_bytes: 0,
            recv_state: StreamRecvState::Open,
            send_state: StreamSendState::Open,
            flow: FlowControlState::default(),
        },
    );
    state.connection_generation = 1;

    handle_command(
        std::ptr::null_mut(),
        &mut state as *mut _,
        Command::StreamReadError {
            stream_id,
            generation: 0,
        },
    );

    assert!(
        state.streams.contains_key(&stream_id),
        "stale task command from old generation must not mutate current stream state"
    );
}

#[test]
fn acceptor_backpressure_blocks_new_connections() {
    let _guard = ResetOnDrop::new(|| acceptor::ClientAcceptor::set_test_limit(0));
    acceptor::ClientAcceptor::set_test_limit(1);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("build tokio runtime");
    rt.block_on(async {
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let acceptor = acceptor::ClientAcceptor::new();
        acceptor.spawn(listener, command_tx);

        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(tokio::net::TcpStream::connect(addr).await.expect("connect"));
        }

        sleep(Duration::from_millis(50)).await;

        let _first = timeout(Duration::from_secs(1), command_rx.recv())
            .await
            .expect("first accept")
            .expect("first command");
        let second = timeout(Duration::from_millis(200), command_rx.recv()).await;

        assert!(
            second.is_err(),
            "expected acceptor backpressure to block additional accepts while at limit"
        );

        drop(clients);
    });
}
