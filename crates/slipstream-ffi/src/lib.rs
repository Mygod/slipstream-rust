use slipstream_core::HostPort;

pub mod picoquic;
pub mod runtime;

pub use picoquic::get_pacing_rate;
pub use picoquic::get_rtt;

#[derive(Debug)]
pub struct ClientConfig<'a> {
    pub tcp_listen_port: u16,
    pub resolvers: &'a [HostPort],
    pub domain: &'a str,
    pub congestion_control: &'a str,
    pub authoritative: bool,
    pub gso: bool,
    pub keep_alive_interval: usize,
    pub debug_poll: bool,
    pub debug_streams: bool,
}

pub use runtime::{
    configure_quic, configure_quic_with_custom, sockaddr_storage_to_socket_addr,
    socket_addr_to_storage, write_stream_or_reset, QuicGuard, SLIPSTREAM_FILE_CANCEL_ERROR,
    SLIPSTREAM_INTERNAL_ERROR,
};
