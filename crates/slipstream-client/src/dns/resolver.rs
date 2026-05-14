use crate::error::ClientError;
use crate::pacing::{PacingBudgetSnapshot, PacingPollBudget};
use slipstream_core::{normalize_dual_stack_addr, resolve_host_port};
use slipstream_ffi::{socket_addr_to_storage, ResolverMode, ResolverSpec};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::warn;

use super::debug::DebugMetrics;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerAddrMode {
    Native,
    DualStack,
}

impl PeerAddrMode {
    pub(crate) fn from_local_addr(addr: SocketAddr) -> Self {
        if matches!(addr, SocketAddr::V6(_)) {
            Self::DualStack
        } else {
            Self::Native
        }
    }

    pub(crate) fn canonicalize(self, addr: SocketAddr) -> SocketAddr {
        match self {
            Self::Native => addr,
            Self::DualStack => normalize_dual_stack_addr(addr),
        }
    }
}

pub(crate) struct ResolverState {
    pub(crate) addr: SocketAddr,
    pub(crate) storage: libc::sockaddr_storage,
    pub(crate) local_addr_storage: Option<libc::sockaddr_storage>,
    pub(crate) mode: ResolverMode,
    pub(crate) added: bool,
    pub(crate) path_id: libc::c_int,
    pub(crate) unique_path_id: Option<u64>,
    pub(crate) probe_attempts: u32,
    pub(crate) next_probe_at: u64,
    pub(crate) disabled_until: u64,
    pub(crate) last_health_check_at: u64,
    pub(crate) last_health_send_packets: u64,
    pub(crate) last_health_dns_responses: u64,
    pub(crate) last_active_poll_kick_at: u64,
    pub(crate) pending_polls: usize,
    pub(crate) inflight_poll_ids: HashMap<u16, u64>,
    pub(crate) pacing_budget: Option<PacingPollBudget>,
    pub(crate) last_pacing_snapshot: Option<PacingBudgetSnapshot>,
    pub(crate) debug: DebugMetrics,
    pub(crate) is_primary: bool,
    pub(crate) path_loss_count: u32,
    pub(crate) last_path_loss_at: u64,
}

impl ResolverState {
    pub(crate) fn label(&self) -> String {
        format!(
            "path_id={} unique_id={:?} resolver={} mode={:?}",
            self.path_id, self.unique_path_id, self.addr, self.mode
        )
    }
}

pub(crate) fn resolve_resolvers(
    resolvers: &[ResolverSpec],
    mtu: u32,
    debug_poll: bool,
    peer_addr_mode: PeerAddrMode,
) -> Result<Vec<ResolverState>, ClientError> {
    let mut resolved = Vec::with_capacity(resolvers.len());
    let mut seen = HashMap::new();
    for (idx, resolver) in resolvers.iter().enumerate() {
        let addr = resolve_host_port(&resolver.resolver)
            .map_err(|err| ClientError::new(err.to_string()))?;
        let addr = peer_addr_mode.canonicalize(addr);
        if let Some(existing_mode) = seen.get(&addr) {
            return Err(ClientError::new(format!(
                "Duplicate resolver address {} (modes: {:?} and {:?})",
                addr, existing_mode, resolver.mode
            )));
        }
        seen.insert(addr, resolver.mode);
        let is_primary = idx == 0;
        resolved.push(ResolverState {
            addr,
            storage: socket_addr_to_storage(addr),
            local_addr_storage: None,
            mode: resolver.mode,
            added: is_primary,
            path_id: if is_primary { 0 } else { -1 },
            unique_path_id: if is_primary { Some(0) } else { None },
            probe_attempts: 0,
            next_probe_at: 0,
            disabled_until: 0,
            last_health_check_at: 0,
            last_health_send_packets: 0,
            last_health_dns_responses: 0,
            last_active_poll_kick_at: 0,
            pending_polls: 0,
            inflight_poll_ids: HashMap::new(),
            pacing_budget: match resolver.mode {
                ResolverMode::Authoritative => Some(PacingPollBudget::new(mtu)),
                ResolverMode::Recursive => None,
            },
            last_pacing_snapshot: None,
            debug: DebugMetrics::new(debug_poll),
            is_primary,
            path_loss_count: 0,
            last_path_loss_at: 0,
        });
    }
    Ok(resolved)
}

const PATH_LOSS_WINDOW_US: u64 = 10_000_000;
const PATH_LOSS_DISABLE_AFTER: u32 = 3;
const PATH_LOSS_DISABLE_US: u64 = 300_000_000;

pub(crate) fn reset_resolver_path(resolver: &mut ResolverState) {
    warn!(
        "Path for resolver {} became unavailable; resetting state",
        resolver.addr
    );
    let now = unsafe { slipstream_ffi::picoquic::picoquic_current_time() };
    if !resolver.is_primary {
        if resolver.last_path_loss_at == 0
            || now.saturating_sub(resolver.last_path_loss_at) > PATH_LOSS_WINDOW_US
        {
            resolver.path_loss_count = 1;
        } else {
            resolver.path_loss_count = resolver.path_loss_count.saturating_add(1);
        }
        resolver.last_path_loss_at = now;
        if resolver.path_loss_count >= PATH_LOSS_DISABLE_AFTER {
            resolver.disabled_until = now.saturating_add(PATH_LOSS_DISABLE_US);
            resolver.path_loss_count = 0;
            warn!(
                "Path for resolver {} is flapping; cooling down for {}ms",
                resolver.addr,
                PATH_LOSS_DISABLE_US / 1000
            );
        }
    }
    resolver.added = false;
    resolver.path_id = -1;
    resolver.unique_path_id = None;
    resolver.local_addr_storage = None;
    resolver.pending_polls = 0;
    resolver.inflight_poll_ids.clear();
    resolver.last_pacing_snapshot = None;
    resolver.probe_attempts = 0;
    resolver.next_probe_at = 0;
    resolver.last_health_check_at = 0;
    resolver.last_health_send_packets = 0;
    resolver.last_health_dns_responses = 0;
    resolver.last_active_poll_kick_at = 0;
}

pub(crate) fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> Result<SocketAddr, ClientError> {
    slipstream_ffi::sockaddr_storage_to_socket_addr(storage).map_err(ClientError::new)
}

#[cfg(test)]
mod tests {
    use super::{resolve_resolvers, PeerAddrMode};
    use slipstream_core::{AddressFamily, HostPort};
    use slipstream_ffi::{ResolverMode, ResolverSpec};
    use std::net::SocketAddr;

    #[test]
    fn rejects_duplicate_resolver_addr() {
        let resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Authoritative,
            },
        ];

        match resolve_resolvers(&resolvers, 900, false, PeerAddrMode::DualStack) {
            Ok(_) => panic!("expected duplicate resolver error"),
            Err(err) => assert!(err.to_string().contains("Duplicate resolver address")),
        }
    }

    #[test]
    fn keeps_ipv4_resolver_family_without_dual_stack_mapping() {
        let resolvers = vec![ResolverSpec {
            resolver: HostPort {
                host: "127.0.0.1".to_string(),
                port: 8853,
                family: AddressFamily::V4,
            },
            mode: ResolverMode::Recursive,
        }];

        let resolved = resolve_resolvers(&resolvers, 900, false, PeerAddrMode::Native)
            .expect("resolve resolver");
        assert!(matches!(resolved[0].addr, SocketAddr::V4(_)));
    }
}
