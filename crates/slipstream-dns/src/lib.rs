mod base32;
mod dns;
mod dots;

pub use base32::{decode as base32_decode, encode as base32_encode, Base32Error};
pub use dns::{
    decode_query, decode_query_with_subdomain_limit, decode_response, encode_query,
    encode_response, is_response, DecodeQueryError, DecodedQuery, DnsError, QueryParams, Question,
    Rcode, ResponseParams, CLASS_IN, EDNS_UDP_PAYLOAD, RR_A, RR_OPT, RR_TXT,
};
pub use dots::{dotify, undotify};

pub fn build_qname(payload: &[u8], domain: &str) -> Result<String, DnsError> {
    build_qname_with_subdomain_limit(payload, domain, None)
}

/// Builds a qname with an optional max subdomain length (dotted labels only).
pub fn build_qname_with_subdomain_limit(
    payload: &[u8],
    domain: &str,
    max_subdomain_len: Option<usize>,
) -> Result<String, DnsError> {
    let max_payload = max_payload_len_for_domain_with_subdomain_limit(domain, max_subdomain_len)?;
    if payload.len() > max_payload {
        return Err(DnsError::new("payload too large for domain"));
    }
    let domain = domain.trim_end_matches('.');
    let base32 = base32_encode(payload);
    let dotted = dotify(&base32);
    Ok(format!("{}.{}.", dotted, domain))
}

pub fn max_payload_len_for_domain(domain: &str) -> Result<usize, DnsError> {
    max_payload_len_for_domain_with_subdomain_limit(domain, None)
}

/// Returns the max payload length for a domain, optionally capping the subdomain length.
pub fn max_payload_len_for_domain_with_subdomain_limit(
    domain: &str,
    max_subdomain_len: Option<usize>,
) -> Result<usize, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    if domain.len() > dns::MAX_DNS_NAME_LEN {
        return Err(DnsError::new("domain too long"));
    }
    let max_name_len = dns::MAX_DNS_NAME_LEN;
    let mut max_dotted_len = max_name_len.saturating_sub(domain.len() + 1);
    if let Some(limit) = max_subdomain_len {
        if limit == 0 {
            return Err(DnsError::new("max subdomain length must be positive"));
        }
        if limit > max_dotted_len {
            return Err(DnsError::new("max subdomain length exceeds DNS name limit"));
        }
        max_dotted_len = limit;
    }
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

#[cfg(test)]
mod tests {
    use super::{
        build_qname, build_qname_with_subdomain_limit, decode_query_with_subdomain_limit,
        encode_query, max_payload_len_for_domain, max_payload_len_for_domain_with_subdomain_limit,
        DecodeQueryError, QueryParams, Rcode, CLASS_IN, RR_TXT,
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
    fn build_qname_respects_subdomain_limit() {
        let domain = "example.com";
        let max_subdomain_len = 101;
        let max_payload =
            max_payload_len_for_domain_with_subdomain_limit(domain, Some(max_subdomain_len))
                .expect("max payload");
        let payload = vec![0u8; max_payload];
        let qname = build_qname_with_subdomain_limit(&payload, domain, Some(max_subdomain_len))
            .expect("build qname");
        let subdomain_len = qname.len() - domain.len() - 2;
        assert!(subdomain_len <= max_subdomain_len);

        let payload = vec![0u8; max_payload + 1];
        assert!(
            build_qname_with_subdomain_limit(&payload, domain, Some(max_subdomain_len)).is_err()
        );
    }

    #[test]
    fn decode_query_enforces_subdomain_limit() {
        let domain = "example.com";
        let payload = vec![0u8; 8];
        let qname = build_qname(&payload, domain).expect("build qname");
        let subdomain_len = qname.len() - domain.len() - 2;
        assert!(subdomain_len > 1);

        let packet = encode_query(&QueryParams {
            id: 0x1234,
            qname: &qname,
            qtype: RR_TXT,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        })
        .expect("encode query");

        let decoded = decode_query_with_subdomain_limit(&packet, domain, Some(subdomain_len))
            .expect("decode query");
        assert_eq!(decoded.payload, payload);

        match decode_query_with_subdomain_limit(&packet, domain, Some(subdomain_len - 1)) {
            Err(DecodeQueryError::Reply { rcode, .. }) => {
                assert_eq!(rcode, Rcode::NameError);
            }
            other => panic!("expected NameError, got {:?}", other),
        }
    }
}
