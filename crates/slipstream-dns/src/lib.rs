mod base32;
mod codec;
mod dots;
mod name;
mod types;
mod wire;

pub use base32::{decode as base32_decode, encode as base32_encode, Base32Error};
pub use codec::{
    decode_query, decode_query_with_domains, decode_response, encode_query, encode_response,
    is_response,
};
pub use dots::{dotify, undotify};
pub use types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Question, Rcode, ResponseParams,
    CLASS_IN, EDNS_UDP_PAYLOAD, RR_A, RR_OPT, RR_TXT,
};

pub fn build_qname(payload: &[u8], domain: &str) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    let max_payload = max_payload_len_for_domain(domain)?;
    if payload.len() > max_payload {
        return Err(DnsError::new("payload too large for domain"));
    }
    let base32 = base32_encode(payload);
    let dotted = dotify(&base32);
    Ok(format!("{}.{}.", dotted, domain))
}

/// Maximum payload size for EDNS0 OPT record encoding
/// EDNS0 UDP payload is 4096, DNS header ~12 bytes, question ~domain+8, OPT ~11 bytes
/// Conservative limit accounting for domain name overhead
pub const MAX_EDNS0_PAYLOAD: usize = 1232;

/// Threshold for automatically switching to EDNS0 encoding
pub const EDNS0_THRESHOLD: usize = 200;

/// Build a DNS query packet with payload encoded in EDNS0 OPT record
/// This supports much larger payloads (~1232 bytes) than QNAME encoding (~140 bytes)
pub fn build_query_with_edns0_payload(
    payload: &[u8],
    domain: &str,
    query_id: u16,
) -> Result<Vec<u8>, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if payload.len() > MAX_EDNS0_PAYLOAD {
        return Err(DnsError::new("payload too large for EDNS0"));
    }

    let qname = format!("{}.", domain);
    let params = QueryParams {
        id: query_id,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    };

    encode_query_with_opt_payload(&params, payload)
}

pub fn max_payload_len_for_domain(domain: &str) -> Result<usize, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if domain.len() > name::MAX_DNS_NAME_LEN {
        return Err(DnsError::new("domain too long"));
    }
    let max_name_len = name::MAX_DNS_NAME_LEN;
    let max_dotted_len = max_name_len.saturating_sub(domain.len() + 1);
    if max_dotted_len == 0 {
        return Ok(0);
    }
    let mut max_base32_len = 0usize;
    for len in 1..=max_dotted_len {
        let dots = (len - 1) / 57;
        if len + dots > max_dotted_len {
            break;
        }
        max_base32_len = len;
    }

    let mut max_payload = (max_base32_len * 5) / 8;
    while max_payload > 0 && base32_len(max_payload) > max_base32_len {
        max_payload -= 1;
    }
    Ok(max_payload)
}

fn base32_len(payload_len: usize) -> usize {
    if payload_len == 0 {
        return 0;
    }
    (payload_len * 8).div_ceil(5)
}

/// Helper function for encoding query with OPT payload
fn encode_query_with_opt_payload(
    params: &QueryParams<'_>,
    opt_payload: &[u8],
) -> Result<Vec<u8>, DnsError> {
    use codec::encode_query;

    // First encode the basic query
    let mut packet = encode_query(params)?;

    // Now we need to replace the OPT record with one containing our payload
    // The basic encode_query adds an empty OPT record (11 bytes) at the end
    // We need to replace it with an OPT record containing the payload

    // Remove the empty OPT record (last 11 bytes)
    if packet.len() >= 11 {
        packet.truncate(packet.len() - 11);
    }

    // Add OPT record with payload
    // NAME: root (0x00)
    packet.push(0);
    // TYPE: OPT (41)
    packet.extend_from_slice(&RR_OPT.to_be_bytes());
    // CLASS: UDP payload size
    packet.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
    // TTL: extended RCODE and flags (4 bytes, all zeros)
    packet.extend_from_slice(&[0, 0, 0, 0]);
    // RDLENGTH: length of RDATA
    let rdlen = opt_payload.len() as u16;
    packet.extend_from_slice(&rdlen.to_be_bytes());
    // RDATA: our payload
    packet.extend_from_slice(opt_payload);

    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::{
        build_qname, build_query_with_edns0_payload, max_payload_len_for_domain, MAX_EDNS0_PAYLOAD,
    };

    #[test]
    fn build_qname_rejects_payload_overflow() {
        let domain = "test.com";
        let max_payload = max_payload_len_for_domain(domain).expect("max payload");
        let payload = vec![0u8; max_payload + 1];
        assert!(build_qname(&payload, domain).is_err());
    }

    #[test]
    fn build_qname_rejects_long_domain() {
        let domain = format!("{}.com", "a".repeat(260));
        let payload = vec![0u8; 1];
        assert!(build_qname(&payload, &domain).is_err());
    }

    #[test]
    fn build_query_with_edns0_accepts_large_payload() {
        let domain = "test.com";
        let payload = vec![0xAB; 500]; // 500 bytes, much larger than QNAME limit
        let result = build_query_with_edns0_payload(&payload, domain, 0x1234);
        assert!(result.is_ok());
    }

    #[test]
    fn build_query_with_edns0_rejects_oversized_payload() {
        let domain = "test.com";
        let payload = vec![0xAB; MAX_EDNS0_PAYLOAD + 1];
        let result = build_query_with_edns0_payload(&payload, domain, 0x1234);
        assert!(result.is_err());
    }
}
