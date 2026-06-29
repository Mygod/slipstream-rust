use crate::server::{Command, StreamKey, StreamWrite, STREAM_READ_CHUNK_BYTES};
use slipstream_core::tcp::tcp_send_buffer_bytes;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_FWD_UDP: u8 = 0x05;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const UDP_MAX_FRAME: usize = 65_535;

pub(crate) fn spawn_direct_socks_target(
    key: StreamKey,
    proxy_addr: Option<SocketAddr>,
    command_tx: mpsc::UnboundedSender<Command>,
    debug_streams: bool,
    shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let (data_tx, data_rx) = mpsc::channel(64);
        let send_pending = Arc::new(AtomicBool::new(false));
        let _ = command_tx.send(Command::StreamConnected {
            cnx_id: key.cnx,
            stream_id: key.stream_id,
            write_tx,
            data_rx,
            send_pending: send_pending.clone(),
        });
        run_direct_socks(
            key,
            proxy_addr,
            write_rx,
            data_tx,
            command_tx,
            send_pending,
            debug_streams,
            shutdown_rx,
        )
        .await;
    });
}

async fn run_direct_socks(
    key: StreamKey,
    proxy_addr: Option<SocketAddr>,
    mut write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    data_tx: mpsc::Sender<Vec<u8>>,
    command_tx: mpsc::UnboundedSender<Command>,
    send_pending: Arc<AtomicBool>,
    debug_streams: bool,
    shutdown_rx: watch::Receiver<bool>,
) {
    let mut input = ChunkReader::default();
    let result = async {
        read_greeting(&mut write_rx, &mut input).await?;
        drain_consumed(&command_tx, key, input.take_consumed());
        send_stream_data(
            &data_tx,
            &command_tx,
            &send_pending,
            key,
            vec![SOCKS_VERSION, 0x00],
        )
        .await?;
        let request = read_request(&mut write_rx, &mut input).await?;
        drain_consumed(&command_tx, key, input.take_consumed());
        match request.cmd {
            SOCKS_CMD_CONNECT => {
                if debug_streams {
                    debug!(
                        "stream {:?}: direct socks connect {}",
                        key.stream_id, request.addr
                    );
                }
                handle_connect(
                    key,
                    request.addr,
                    proxy_addr,
                    write_rx,
                    input,
                    data_tx,
                    command_tx.clone(),
                    send_pending,
                    shutdown_rx,
                )
                .await
            }
            SOCKS_CMD_FWD_UDP => {
                if debug_streams {
                    debug!("stream {:?}: direct socks fwd_udp", key.stream_id);
                }
                handle_fwd_udp(
                    key,
                    proxy_addr,
                    write_rx,
                    input,
                    data_tx,
                    command_tx.clone(),
                    send_pending,
                    shutdown_rx,
                )
                .await
            }
            _ => {
                send_stream_data(&data_tx, &command_tx, &send_pending, key, socks_reply(0x07)).await
            }
        }
    }
    .await;

    if let Err(err) = result {
        warn!(
            "stream {:?}: direct socks target closed: {}",
            key.stream_id, err
        );
        let _ = command_tx.send(Command::StreamReadError {
            cnx_id: key.cnx,
            stream_id: key.stream_id,
        });
    } else {
        let _ = command_tx.send(Command::StreamClosed {
            cnx_id: key.cnx,
            stream_id: key.stream_id,
        });
    }
}

async fn handle_connect(
    key: StreamKey,
    addr: SocketAddr,
    proxy_addr: Option<SocketAddr>,
    mut write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    mut input: ChunkReader,
    data_tx: mpsc::Sender<Vec<u8>>,
    command_tx: mpsc::UnboundedSender<Command>,
    send_pending: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    let mut target = if let Some(proxy) = proxy_addr {
        connect_via_socks_proxy(proxy, addr).await?
    } else {
        TcpStream::connect(addr)
            .await
            .map_err(|err| format!("tcp connect {} failed: {}", addr, err))?
    };
    let _ = target.set_nodelay(true);
    send_stream_data(&data_tx, &command_tx, &send_pending, key, socks_reply(0x00)).await?;
    let coalesce_max = tcp_send_buffer_bytes(&target)
        .filter(|bytes| *bytes > 0)
        .unwrap_or(256 * 1024);
    let (mut target_rx, mut target_tx) = target.split();
    let mut target_buf = vec![0u8; STREAM_READ_CHUNK_BYTES];
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            data = input.read_some(&mut write_rx, coalesce_max) => {
                let Some(data) = data else {
                    let _ = target_tx.shutdown().await;
                    return Ok(());
                };
                target_tx.write_all(&data).await.map_err(|err| format!("tcp write failed: {}", err))?;
                let _ = command_tx.send(Command::StreamWriteDrained {
                    cnx_id: key.cnx,
                    stream_id: key.stream_id,
                    bytes: data.len(),
                });
            }
            read = target_rx.read(&mut target_buf) => {
                let n = read.map_err(|err| format!("tcp read failed: {}", err))?;
                if n == 0 {
                    return Ok(());
                }
                send_stream_data(&data_tx, &command_tx, &send_pending, key, target_buf[..n].to_vec()).await?;
            }
        }
    }
}

async fn handle_fwd_udp(
    key: StreamKey,
    proxy_addr: Option<SocketAddr>,
    mut write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    mut input: ChunkReader,
    data_tx: mpsc::Sender<Vec<u8>>,
    command_tx: mpsc::UnboundedSender<Command>,
    send_pending: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    let relay = if let Some(proxy) = proxy_addr {
        Some(open_socks_udp_associate(proxy).await?)
    } else {
        None
    };
    let socket = if relay.is_some() {
        UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|err| format!("udp bind failed: {}", err))?
    } else {
        match UdpSocket::bind("[::]:0").await {
            Ok(socket) => socket,
            Err(_) => UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|err| format!("udp bind failed: {}", err))?,
        }
    };
    send_stream_data(&data_tx, &command_tx, &send_pending, key, socks_reply(0x00)).await?;
    let mut recv_buf = vec![0u8; UDP_MAX_FRAME];
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            frame = read_udp_frame(&mut write_rx, &mut input) => {
                let Some(frame) = frame? else {
                    return Ok(());
                };
                if let Some(relay) = relay.as_ref() {
                    let packet = socks_udp_packet(frame.addr, &frame.payload)?;
                    socket
                        .send_to(&packet, relay.udp_addr)
                        .await
                        .map_err(|err| format!("udp proxy send {} failed: {}", frame.addr, err))?;
                } else {
                    socket
                        .send_to(&frame.payload, frame.addr)
                        .await
                        .map_err(|err| format!("udp send {} failed: {}", frame.addr, err))?;
                }
                let _ = command_tx.send(Command::StreamWriteDrained {
                    cnx_id: key.cnx,
                    stream_id: key.stream_id,
                    bytes: frame.wire_len,
                });
            }
            recv = socket.recv_from(&mut recv_buf) => {
                let (n, peer) = recv.map_err(|err| format!("udp recv failed: {}", err))?;
                let (addr, payload) = if relay.is_some() {
                    parse_socks_udp_packet(&recv_buf[..n])?
                } else {
                    (socks_addr_from_socket(peer)?, &recv_buf[..n])
                };
                let mut frame = Vec::with_capacity(3 + addr.len() + payload.len());
                frame.push(((payload.len() >> 8) & 0xFF) as u8);
                frame.push((payload.len() & 0xFF) as u8);
                frame.push((3 + addr.len()) as u8);
                frame.extend_from_slice(&addr);
                frame.extend_from_slice(payload);
                send_stream_data(&data_tx, &command_tx, &send_pending, key, frame).await?;
            }
        }
    }
}

async fn read_greeting(
    write_rx: &mut mpsc::UnboundedReceiver<StreamWrite>,
    input: &mut ChunkReader,
) -> Result<(), String> {
    let header = input
        .read_exact(write_rx, 2)
        .await
        .ok_or_else(|| "eof during socks greeting".to_string())?;
    if header[0] != SOCKS_VERSION {
        return Err("unsupported socks version".to_string());
    }
    let nmethods = header[1] as usize;
    let _ = input
        .read_exact(write_rx, nmethods)
        .await
        .ok_or_else(|| "eof during socks methods".to_string())?;
    Ok(())
}

async fn read_request(
    write_rx: &mut mpsc::UnboundedReceiver<StreamWrite>,
    input: &mut ChunkReader,
) -> Result<SocksRequest, String> {
    let header = input
        .read_exact(write_rx, 4)
        .await
        .ok_or_else(|| "eof during socks request".to_string())?;
    if header[0] != SOCKS_VERSION {
        return Err("unsupported request version".to_string());
    }
    let addr = read_socks_addr(write_rx, input, header[3]).await?;
    Ok(SocksRequest {
        cmd: header[1],
        addr,
    })
}

async fn read_udp_frame(
    write_rx: &mut mpsc::UnboundedReceiver<StreamWrite>,
    input: &mut ChunkReader,
) -> Result<Option<UdpFrame>, String> {
    let Some(header) = input.read_exact(write_rx, 3).await else {
        return Ok(None);
    };
    let payload_len = (((header[0] as usize) << 8) | header[1] as usize).min(UDP_MAX_FRAME);
    let header_len = header[2] as usize;
    if header_len < 5 {
        return Err("bad udp frame header".to_string());
    }
    let addr_len = header_len - 3;
    let addr_bytes = input
        .read_exact(write_rx, addr_len)
        .await
        .ok_or_else(|| "eof during udp frame address".to_string())?;
    let payload = input
        .read_exact(write_rx, payload_len)
        .await
        .ok_or_else(|| "eof during udp payload".to_string())?;
    let addr = parse_socks_addr_bytes(&addr_bytes).await?;
    Ok(Some(UdpFrame {
        addr,
        payload,
        wire_len: 3 + addr_len + payload_len,
    }))
}

async fn read_socks_addr(
    write_rx: &mut mpsc::UnboundedReceiver<StreamWrite>,
    input: &mut ChunkReader,
    atyp: u8,
) -> Result<SocketAddr, String> {
    let mut raw = vec![atyp];
    match atyp {
        ATYP_IPV4 => raw.extend(
            input
                .read_exact(write_rx, 6)
                .await
                .ok_or_else(|| "eof during ipv4 address".to_string())?,
        ),
        ATYP_IPV6 => raw.extend(
            input
                .read_exact(write_rx, 18)
                .await
                .ok_or_else(|| "eof during ipv6 address".to_string())?,
        ),
        ATYP_DOMAIN => {
            let len = input
                .read_exact(write_rx, 1)
                .await
                .ok_or_else(|| "eof during domain length".to_string())?[0]
                as usize;
            raw.push(len as u8);
            raw.extend(
                input
                    .read_exact(write_rx, len + 2)
                    .await
                    .ok_or_else(|| "eof during domain address".to_string())?,
            );
        }
        _ => return Err("unsupported address type".to_string()),
    }
    parse_socks_addr_bytes(&raw).await
}

async fn parse_socks_addr_bytes(raw: &[u8]) -> Result<SocketAddr, String> {
    if raw.len() < 4 {
        return Err("short address".to_string());
    }
    match raw[0] {
        ATYP_IPV4 => {
            if raw.len() != 7 {
                return Err("bad ipv4 address length".to_string());
            }
            let ip = IpAddr::V4(Ipv4Addr::new(raw[1], raw[2], raw[3], raw[4]));
            let port = u16::from_be_bytes([raw[5], raw[6]]);
            Ok(SocketAddr::new(ip, port))
        }
        ATYP_IPV6 => {
            if raw.len() != 19 {
                return Err("bad ipv6 address length".to_string());
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&raw[1..17]);
            let port = u16::from_be_bytes([raw[17], raw[18]]);
            Ok(SocketAddr::new(IpAddr::from(ip), port))
        }
        ATYP_DOMAIN => {
            let len = raw[1] as usize;
            if raw.len() != 2 + len + 2 {
                return Err("bad domain address length".to_string());
            }
            let host = std::str::from_utf8(&raw[2..2 + len])
                .map_err(|_| "domain is not utf8".to_string())?;
            let port = u16::from_be_bytes([raw[2 + len], raw[3 + len]]);
            let mut addrs = lookup_host((host, port))
                .await
                .map_err(|err| format!("resolve {} failed: {}", host, err))?;
            addrs
                .next()
                .ok_or_else(|| format!("resolve {} returned no addresses", host))
        }
        _ => Err("unsupported address type".to_string()),
    }
}

async fn connect_via_socks_proxy(
    proxy: SocketAddr,
    target: SocketAddr,
) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|err| format!("socks proxy connect {} failed: {}", proxy, err))?;
    socks_client_greeting(&mut stream).await?;
    let addr = socks_addr_from_socket(target)?;
    stream
        .write_all(&[SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00])
        .await
        .map_err(|err| format!("socks connect header write failed: {}", err))?;
    stream
        .write_all(&addr)
        .await
        .map_err(|err| format!("socks connect address write failed: {}", err))?;
    read_socks_client_reply(&mut stream).await?;
    Ok(stream)
}

async fn open_socks_udp_associate(proxy: SocketAddr) -> Result<SocksUdpRelay, String> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|err| format!("socks udp proxy connect {} failed: {}", proxy, err))?;
    socks_client_greeting(&mut stream).await?;
    let bind_addr = socks_addr_from_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    stream
        .write_all(&[SOCKS_VERSION, 0x03, 0x00])
        .await
        .map_err(|err| format!("socks udp associate header write failed: {}", err))?;
    stream
        .write_all(&bind_addr)
        .await
        .map_err(|err| format!("socks udp associate address write failed: {}", err))?;
    let udp_addr = read_socks_client_reply(&mut stream).await?;
    Ok(SocksUdpRelay {
        udp_addr,
        _control: stream,
    })
}

async fn socks_client_greeting(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[SOCKS_VERSION, 0x01, 0x00])
        .await
        .map_err(|err| format!("socks greeting write failed: {}", err))?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|err| format!("socks greeting read failed: {}", err))?;
    if reply != [SOCKS_VERSION, 0x00] {
        return Err(format!("socks greeting rejected method={}", reply[1]));
    }
    Ok(())
}

async fn read_socks_client_reply(stream: &mut TcpStream) -> Result<SocketAddr, String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| format!("socks reply read failed: {}", err))?;
    if header[0] != SOCKS_VERSION || header[1] != 0x00 {
        return Err(format!("socks reply rejected rep={}", header[1]));
    }
    read_socks_reply_addr(stream, header[3]).await
}

async fn read_socks_reply_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr, String> {
    let mut raw = vec![atyp];
    match atyp {
        ATYP_IPV4 => {
            let mut rest = [0u8; 6];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("socks ipv4 reply read failed: {}", err))?;
            raw.extend_from_slice(&rest);
        }
        ATYP_IPV6 => {
            let mut rest = [0u8; 18];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("socks ipv6 reply read failed: {}", err))?;
            raw.extend_from_slice(&rest);
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|err| format!("socks domain length reply read failed: {}", err))?;
            raw.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("socks domain reply read failed: {}", err))?;
            raw.extend_from_slice(&rest);
        }
        _ => return Err("unsupported socks reply address type".to_string()),
    }
    parse_socks_addr_bytes(&raw).await
}

fn socks_addr_from_socket(addr: SocketAddr) -> Result<Vec<u8>, String> {
    let port = addr.port().to_be_bytes();
    let mut out = Vec::with_capacity(19);
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&port);
    Ok(out)
}

fn socks_udp_packet(addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
    let socks_addr = socks_addr_from_socket(addr)?;
    let mut out = Vec::with_capacity(3 + socks_addr.len() + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&socks_addr);
    out.extend_from_slice(payload);
    Ok(out)
}

fn parse_socks_udp_packet(packet: &[u8]) -> Result<(Vec<u8>, &[u8]), String> {
    if packet.len() < 10 {
        return Err("short socks udp packet".to_string());
    }
    if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err("fragmented socks udp packet is unsupported".to_string());
    }
    let addr_len = match packet[3] {
        ATYP_IPV4 => 1 + 4 + 2,
        ATYP_IPV6 => 1 + 16 + 2,
        ATYP_DOMAIN => {
            if packet.len() < 5 {
                return Err("short socks udp domain packet".to_string());
            }
            1 + 1 + packet[4] as usize + 2
        }
        _ => return Err("unsupported socks udp address type".to_string()),
    };
    let start = 3;
    let end = start + addr_len;
    if packet.len() < end {
        return Err("truncated socks udp address".to_string());
    }
    Ok((packet[start..end].to_vec(), &packet[end..]))
}

fn socks_reply(rep: u8) -> Vec<u8> {
    vec![SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

fn drain_consumed(command_tx: &mpsc::UnboundedSender<Command>, key: StreamKey, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let _ = command_tx.send(Command::StreamWriteDrained {
        cnx_id: key.cnx,
        stream_id: key.stream_id,
        bytes,
    });
}

async fn send_stream_data(
    data_tx: &mpsc::Sender<Vec<u8>>,
    command_tx: &mpsc::UnboundedSender<Command>,
    send_pending: &Arc<AtomicBool>,
    key: StreamKey,
    data: Vec<u8>,
) -> Result<(), String> {
    data_tx
        .send(data)
        .await
        .map_err(|_| "stream data channel closed".to_string())?;
    if !send_pending.swap(true, Ordering::SeqCst) {
        let _ = command_tx.send(Command::StreamReadable {
            cnx_id: key.cnx,
            stream_id: key.stream_id,
        });
    }
    Ok(())
}

#[derive(Default)]
struct ChunkReader {
    pending: VecDeque<u8>,
    consumed: usize,
}

impl ChunkReader {
    async fn read_exact(
        &mut self,
        write_rx: &mut mpsc::UnboundedReceiver<StreamWrite>,
        len: usize,
    ) -> Option<Vec<u8>> {
        while self.pending.len() < len {
            match write_rx.recv().await? {
                StreamWrite::Data(data) => self.pending.extend(data),
                StreamWrite::Fin => return None,
            }
        }
        self.consumed = self.consumed.saturating_add(len);
        Some(self.pending.drain(..len).collect())
    }

    async fn read_some(
        &mut self,
        write_rx: &mut mpsc::UnboundedReceiver<StreamWrite>,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        if self.pending.is_empty() {
            match write_rx.recv().await? {
                StreamWrite::Data(data) => self.pending.extend(data),
                StreamWrite::Fin => return None,
            }
        }
        let len = self.pending.len().min(max_len.max(1));
        self.consumed = self.consumed.saturating_add(len);
        Some(self.pending.drain(..len).collect())
    }

    fn take_consumed(&mut self) -> usize {
        let consumed = self.consumed;
        self.consumed = 0;
        consumed
    }
}

struct SocksRequest {
    cmd: u8,
    addr: SocketAddr,
}

struct UdpFrame {
    addr: SocketAddr,
    payload: Vec<u8>,
    wire_len: usize,
}

struct SocksUdpRelay {
    udp_addr: SocketAddr,
    _control: TcpStream,
}
