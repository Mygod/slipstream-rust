use super::{dummy_sockaddr_storage, FallbackManager, PacketContext};
use crate::server::{ServerError, Slot};
use slipstream_dns::{decode_query_with_domains, DecodeQueryError};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_incoming_packet_ex, picoquic_quic_t, slipstream_disable_ack_delay,
};
use slipstream_ffi::take_stateless_packet_for_cid;
use std::net::SocketAddr;

enum DecodeSlotOutcome {
    Slot(Slot),
    DnsOnly,
    Drop,
}

pub(crate) async fn handle_packet(
    slots: &mut Vec<Slot>,
    packet: &[u8],
    peer: SocketAddr,
    context: &PacketContext<'_>,
    fallback_mgr: &mut Option<FallbackManager>,
) -> Result<(), ServerError> {
    if let Some(manager) = fallback_mgr.as_mut() {
        if manager.is_active_fallback_peer(peer) {
            manager.forward_existing(packet, peer).await;
            return Ok(());
        }
    }

    match decode_slot(
        packet,
        peer,
        context.domains,
        context.quic,
        context.current_time,
        context.local_addr_storage,
    )? {
        DecodeSlotOutcome::Slot(slot) => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.mark_dns(peer);
            }
            slots.push(slot);
        }
        DecodeSlotOutcome::DnsOnly => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.mark_dns(peer);
            }
        }
        DecodeSlotOutcome::Drop => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.handle_non_dns(packet, peer).await;
            }
        }
    }

    Ok(())
}

fn decode_slot(
    packet: &[u8],
    peer: SocketAddr,
    domains: &[&str],
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &libc::sockaddr_storage,
) -> Result<DecodeSlotOutcome, ServerError> {
    match decode_query_with_domains(packet, domains) {
        Ok(query) => {
            let mut peer_storage = dummy_sockaddr_storage();
            let mut local_storage = unsafe { std::ptr::read(local_addr_storage) };
            let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
            let mut first_path: libc::c_int = -1;
            let ret = unsafe {
                picoquic_incoming_packet_ex(
                    quic,
                    query.payload.as_ptr() as *mut u8,
                    query.payload.len(),
                    &mut peer_storage as *mut _ as *mut libc::sockaddr,
                    &mut local_storage as *mut _ as *mut libc::sockaddr,
                    0,
                    0,
                    &mut first_cnx,
                    &mut first_path,
                    current_time,
                )
            };
            if ret < 0 {
                return Err(ServerError::new("Failed to process QUIC packet"));
            }
            if first_cnx.is_null() {
                if let Some(payload) =
                    unsafe { take_stateless_packet_for_cid(quic, &query.payload) }
                {
                    if !payload.is_empty() {
                        return Ok(DecodeSlotOutcome::Slot(Slot {
                            peer,
                            id: query.id,
                            rd: query.rd,
                            cd: query.cd,
                            question: query.question,
                            rcode: None,
                            cnx: std::ptr::null_mut(),
                            path_id: -1,
                            payload_override: Some(payload),
                        }));
                    }
                }
                return Ok(DecodeSlotOutcome::DnsOnly);
            }
            unsafe {
                slipstream_disable_ack_delay(first_cnx);
            }
            Ok(DecodeSlotOutcome::Slot(Slot {
                peer,
                id: query.id,
                rd: query.rd,
                cd: query.cd,
                question: query.question,
                rcode: None,
                cnx: first_cnx,
                path_id: first_path,
                payload_override: None,
            }))
        }
        Err(DecodeQueryError::Drop) => Ok(DecodeSlotOutcome::Drop),
        Err(DecodeQueryError::Reply {
            id,
            rd,
            cd,
            question,
            rcode,
        }) => {
            let Some(question) = question else {
                // Treat empty-question queries (QDCOUNT=0) as non-DNS for fallback.
                return Ok(DecodeSlotOutcome::Drop);
            };
            Ok(DecodeSlotOutcome::Slot(Slot {
                peer,
                id,
                rd,
                cd,
                question,
                rcode: Some(rcode),
                cnx: std::ptr::null_mut(),
                path_id: -1,
                payload_override: None,
            }))
        }
    }
}
