use crate::base32;
use crate::dots;

use crate::name::{encode_name, extract_subdomain_multi, parse_name};
use crate::types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Rcode, ResponseParams,
    EDNS_SLIPSTREAM_PAYLOAD_OPTION, EDNS_UDP_PAYLOAD, RR_OPT, RR_TXT,
};
use crate::wire::{
    parse_header, parse_question, parse_question_for_reply, read_u16, read_u32, write_u16,
    write_u32,
};

pub fn decode_query(packet: &[u8], domain: &str) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains(packet, &[domain])
}

pub fn decode_query_with_domains(
    packet: &[u8],
    domains: &[&str],
) -> Result<DecodedQuery, DecodeQueryError> {
    let header = match parse_header(packet) {
        Some(header) => header,
        None => return Err(DecodeQueryError::Drop),
    };

    let rd = header.rd;
    let cd = header.cd;

    if header.is_response {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    if header.qdcount != 1 {
        let question = parse_question_for_reply(packet, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    let (question, after_question) = match parse_question(packet, header.offset) {
        Ok((question, offset)) => (question, offset),
        Err(_) => return Err(DecodeQueryError::Drop),
    };

    if question.qtype != RR_TXT {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let subdomain_raw = match extract_subdomain_multi(&question.name, domains) {
        Ok(subdomain_raw) => subdomain_raw,
        Err(rcode) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode,
            })
        }
    };

    if subdomain_raw.eq_ignore_ascii_case("_s") {
        let payload = match parse_edns_raw_payload(packet, after_question, header.arcount) {
            Some(payload) if !payload.is_empty() => payload,
            _ => {
                return Err(DecodeQueryError::Reply {
                    id: header.id,
                    rd,
                    cd,
                    question: Some(question),
                    rcode: Rcode::ServerFailure,
                })
            }
        };
        return Ok(DecodedQuery {
            id: header.id,
            rd,
            cd,
            question,
            payload,
        });
    }

    let undotted = dots::undotify(&subdomain_raw);
    if undotted.is_empty() {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let payload = match base32::decode(&undotted) {
        Ok(payload) => payload,
        Err(_) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode: Rcode::ServerFailure,
            })
        }
    };

    Ok(DecodedQuery {
        id: header.id,
        rd,
        cd,
        question,
        payload,
    })
}

pub fn build_edns_raw_qname(domain: &str) -> Result<String, DnsError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(DnsError::new("domain must not be empty"));
    }
    Ok(format!("_s.{}.", domain))
}

pub fn encode_query(params: &QueryParams<'_>) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(256);
    let mut flags = 0u16;
    if !params.is_query {
        flags |= 0x8000;
    }
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, params.qdcount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    if params.qdcount > 0 {
        encode_name(params.qname, &mut out)?;
        write_u16(&mut out, params.qtype);
        write_u16(&mut out, params.qclass);
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn encode_query_edns_raw(
    id: u16,
    qname: &str,
    payload: &[u8],
    rd: bool,
    cd: bool,
) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(64 + payload.len());
    let mut flags = 0u16;
    if rd {
        flags |= 0x0100;
    }
    if cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(qname, &mut out)?;
    write_u16(&mut out, RR_TXT);
    write_u16(&mut out, crate::types::CLASS_IN);

    encode_opt_record_with_payload(&mut out, Some(payload))?;
    Ok(out)
}

pub fn encode_response(params: &ResponseParams<'_>) -> Result<Vec<u8>, DnsError> {
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);

    let mut rcode = params.rcode.unwrap_or(if payload_len > 0 {
        Rcode::Ok
    } else {
        Rcode::NameError
    });

    let mut ancount = 0u16;
    if payload_len > 0 && rcode == Rcode::Ok {
        ancount = 1;
    } else if params.rcode.is_some() {
        rcode = params.rcode.unwrap_or(Rcode::Ok);
    }

    let mut out = Vec::with_capacity(256);
    let mut flags = 0x8000 | 0x0400;
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }
    flags |= rcode.to_u8() as u16;

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, ancount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(&params.question.name, &mut out)?;
    write_u16(&mut out, params.question.qtype);
    write_u16(&mut out, params.question.qclass);

    if ancount == 1 {
        out.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut out, params.question.qtype);
        write_u16(&mut out, params.question.qclass);
        write_u32(&mut out, 60);
        let chunk_count = payload_len.div_ceil(255);
        let rdata_len = payload_len + chunk_count;
        if rdata_len > u16::MAX as usize {
            return Err(DnsError::new("payload too long"));
        }
        write_u16(&mut out, rdata_len as u16);
        if let Some(payload) = params.payload {
            let mut remaining = payload_len;
            let mut cursor = 0;
            while remaining > 0 {
                let chunk_len = remaining.min(255);
                out.push(chunk_len as u8);
                out.extend_from_slice(&payload[cursor..cursor + chunk_len]);
                cursor += chunk_len;
                remaining -= chunk_len;
            }
        }
    }

    encode_opt_record(&mut out)?;

    Ok(out)
}

pub fn decode_response(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(packet)?;
    if !header.is_response {
        return None;
    }
    let rcode = header.rcode?;
    if rcode != Rcode::Ok {
        return None;
    }
    if header.ancount != 1 {
        return None;
    }

    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }

    let (_, new_offset) = parse_name(packet, offset).ok()?;
    offset = new_offset;
    if offset + 10 > packet.len() {
        return None;
    }
    let qtype = read_u16(packet, offset)?;
    offset += 2;
    let _qclass = read_u16(packet, offset)?;
    offset += 2;
    let _ttl = read_u32(packet, offset)?;
    offset += 4;
    let rdlen = read_u16(packet, offset)? as usize;
    offset += 2;
    if offset + rdlen > packet.len() || rdlen < 1 {
        return None;
    }
    if qtype != RR_TXT {
        return None;
    }

    let mut remaining = rdlen;
    let mut cursor = offset;
    let mut out = Vec::with_capacity(rdlen);
    while remaining > 0 {
        let txt_len = packet[cursor] as usize;
        cursor += 1;
        remaining -= 1;
        if txt_len > remaining {
            return None;
        }
        out.extend_from_slice(&packet[cursor..cursor + txt_len]);
        cursor += txt_len;
        remaining -= txt_len;
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

pub fn is_response(packet: &[u8]) -> bool {
    parse_header(packet)
        .map(|header| header.is_response)
        .unwrap_or(false)
}

fn encode_opt_record(out: &mut Vec<u8>) -> Result<(), DnsError> {
    encode_opt_record_with_payload(out, None)
}

fn encode_opt_record_with_payload(
    out: &mut Vec<u8>,
    payload: Option<&[u8]>,
) -> Result<(), DnsError> {
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    let rdlen = payload.map(|payload| payload.len() + 4).unwrap_or(0);
    if rdlen > u16::MAX as usize {
        return Err(DnsError::new("EDNS payload too long"));
    }
    write_u16(out, rdlen as u16);
    if let Some(payload) = payload {
        write_u16(out, EDNS_SLIPSTREAM_PAYLOAD_OPTION);
        write_u16(out, payload.len() as u16);
        out.extend_from_slice(payload);
    }
    Ok(())
}

fn parse_edns_raw_payload(packet: &[u8], mut offset: usize, arcount: u16) -> Option<Vec<u8>> {
    for _ in 0..arcount {
        let (_, new_offset) = parse_name(packet, offset).ok()?;
        offset = new_offset;
        if offset + 10 > packet.len() {
            return None;
        }
        let rr_type = read_u16(packet, offset)?;
        offset += 2;
        let _rr_class = read_u16(packet, offset)?;
        offset += 2;
        let _ttl = read_u32(packet, offset)?;
        offset += 4;
        let rdlen = read_u16(packet, offset)? as usize;
        offset += 2;
        if offset + rdlen > packet.len() {
            return None;
        }
        if rr_type == RR_OPT {
            let end = offset + rdlen;
            let mut cursor = offset;
            while cursor + 4 <= end {
                let code = read_u16(packet, cursor)?;
                cursor += 2;
                let len = read_u16(packet, cursor)? as usize;
                cursor += 2;
                if cursor + len > end {
                    return None;
                }
                if code == EDNS_SLIPSTREAM_PAYLOAD_OPTION {
                    return Some(packet[cursor..cursor + len].to_vec());
                }
                cursor += len;
            }
        }
        offset += rdlen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::encode_response;
    use crate::types::{Question, ResponseParams, CLASS_IN, RR_TXT};

    #[test]
    fn encode_response_rejects_large_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_TXT,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; u16::MAX as usize];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
        };
        assert!(encode_response(&params).is_err());
    }
}
