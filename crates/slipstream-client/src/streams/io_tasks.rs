use super::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{sleep, Duration};
use tracing::warn;

pub(super) const STREAM_READ_CHUNK_BYTES: usize = 4096;

pub(super) enum StreamWrite {
    Data(Vec<u8>),
    Fin,
}

pub(super) fn spawn_client_reader(
    stream_id: u64,
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    mut read_abort_rx: oneshot::Receiver<()>,
    generation: usize,
    command_tx: mpsc::UnboundedSender<Command>,
    data_tx: mpsc::Sender<Vec<u8>>,
    data_notify: Arc<Notify>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; STREAM_READ_CHUNK_BYTES];
        'read_loop: loop {
            tokio::select! {
                _ = &mut read_abort_rx => {
                    break;
                }
                read_result = read_half.read(&mut buf) => {
                    match read_result {
                        Ok(0) => {
                            let _ = command_tx.send(Command::StreamReadClosed {
                                stream_id,
                                generation,
                            });
                            break;
                        }
                        Ok(n) => {
                            let mut data = Some(buf[..n].to_vec());
                            let mut blocked_ticks = 0u64;
                            loop {
                                tokio::select! {
                                    _ = &mut read_abort_rx => {
                                        break 'read_loop;
                                    }
                                    permit = data_tx.reserve() => {
                                        match permit {
                                            Ok(permit) => {
                                                if let Some(chunk) = data.take() {
                                                    permit.send(chunk);
                                                    data_notify.notify_one();
                                                }
                                                break;
                                            }
                                            Err(_) => break 'read_loop,
                                        }
                                    }
                                    _ = sleep(Duration::from_secs(1)) => {
                                        blocked_ticks = blocked_ticks.saturating_add(1);
                                        warn!(
                                            "stream {}: local TCP reader blocked on bounded channel blocked_ms={} channel_len={} channel_capacity={} channel_max_capacity={}",
                                            stream_id,
                                            blocked_ticks.saturating_mul(1000),
                                            data_tx.max_capacity().saturating_sub(data_tx.capacity()),
                                            data_tx.capacity(),
                                            data_tx.max_capacity()
                                        );
                                    }
                                }
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(_) => {
                            let _ = command_tx.send(Command::StreamReadError {
                                stream_id,
                                generation,
                            });
                            break;
                        }
                    }
                }
            }
        }
        drop(data_tx);
        data_notify.notify_one();
    });
}

pub(super) fn spawn_client_writer(
    stream_id: u64,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    generation: usize,
    command_tx: mpsc::UnboundedSender<Command>,
    coalesce_max_bytes: usize,
) {
    tokio::spawn(async move {
        let coalesce_max_bytes = coalesce_max_bytes.max(1);
        while let Some(msg) = write_rx.recv().await {
            match msg {
                StreamWrite::Data(data) => {
                    let mut buffer = data;
                    let mut saw_fin = false;
                    while buffer.len() < coalesce_max_bytes {
                        match write_rx.try_recv() {
                            Ok(StreamWrite::Data(more)) => {
                                buffer.extend_from_slice(&more);
                                if buffer.len() >= coalesce_max_bytes {
                                    break;
                                }
                            }
                            Ok(StreamWrite::Fin) => {
                                saw_fin = true;
                                break;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                saw_fin = true;
                                break;
                            }
                        }
                    }
                    let len = buffer.len();
                    if write_half.write_all(&buffer).await.is_err() {
                        let _ = command_tx.send(Command::StreamWriteError {
                            stream_id,
                            generation,
                        });
                        return;
                    }
                    let _ = command_tx.send(Command::StreamWriteDrained {
                        stream_id,
                        bytes: len,
                        generation,
                    });
                    if saw_fin {
                        let _ = write_half.shutdown().await;
                        return;
                    }
                }
                StreamWrite::Fin => {
                    let _ = write_half.shutdown().await;
                    return;
                }
            }
        }
        let _ = write_half.shutdown().await;
    });
}
