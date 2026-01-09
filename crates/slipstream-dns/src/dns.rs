use crate::base32;
use crate::dots;
use std::fmt;

pub const RR_A: u16 = 1;
pub const RR_TXT: u16 = 16;
pub const RR_OPT: u16 = 41;
pub const CLASS_IN: u16 = 1;
pub const EDNS_UDP_PAYLOAD: u16 = 1232;
pub(crate) const MAX_DNS_NAME_LEN: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    Ok,
    FormatError,
    ServerFailure,
    NameError,
}

impl Rcode {
    pub fn to_u8(self) -> u8 {
        match self {
            Rcode::Ok => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Rcode::Ok),
            1 => Some(Rcode::FormatError),
            2 => Some(Rcode::ServerFailure),
            3 => Some(Rcode::NameError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DecodedQuery {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    pub question: Question,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DecodeQueryError {
    Drop,
    Reply {
        id: u16,
        rd: bool,
        cd: bool,
        question: Option<Question>,
        rcode: Rcode,
    },
}

#[derive(Debug, Clone)]
pub struct QueryParams<'a> {
    pub id: u16,
    pub qname: &'a str,
    pub qtype: u16,
    pub qclass: u16,
    pub rd: bool,
    pub cd: bool,
    pub qdcount: u16,
    pub is_query: bool,
}

#[derive(Debug, Clone)]
pub struct ResponseParams<'a> {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    pub question: &'a Question,
    pub payload: Option<&'a [u8]>,
    pub rcode: Option<Rcode>,
}

#[derive(Debug, Clone)]
pub struct DnsError {
    message: String,
}

impl DnsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DnsError {}

pub fn decode_query(packet: &[u8], domain: &str) -> Result<DecodedQuery, DecodeQueryError> {
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

    let question = match parse_question(packet, header.offset) {
        Ok((question, _)) => question,
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

    let subdomain_raw = match extract_subdomain(&question.name, domain) {
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
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    write_u16(out, 0);
    Ok(())
}

fn extract_subdomain(qname: &str, domain: &str) -> Result<String, Rcode> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(Rcode::NameError);
    }

    let suffix = format!(".{}.", domain);
    if !qname
        .to_ascii_lowercase()
        .ends_with(&suffix.to_ascii_lowercase())
    {
        return Err(Rcode::NameError);
    }

    if qname.len() <= domain.len() + 2 {
        return Err(Rcode::NameError);
    }

    let data_len = qname.len() - domain.len() - 2;
    let subdomain = &qname[..data_len];
    if subdomain.is_empty() {
        return Err(Rcode::NameError);
    }
    Ok(subdomain.to_string())
}

#[derive(Debug, Clone, Copy)]
struct Header {
    id: u16,
    is_response: bool,
    rd: bool,
    cd: bool,
    qdcount: u16,
    ancount: u16,
    rcode: Option<Rcode>,
    offset: usize,
}

fn parse_header(packet: &[u8]) -> Option<Header> {
    if packet.len() < 12 {
        return None;
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let qdcount = read_u16(packet, 4)?;
    let ancount = read_u16(packet, 6)?;
    let _nscount = read_u16(packet, 8)?;
    let _arcount = read_u16(packet, 10)?;

    let is_response = flags & 0x8000 != 0;
    let rd = flags & 0x0100 != 0;
    let cd = flags & 0x0010 != 0;
    let rcode = Rcode::from_u8((flags & 0x000f) as u8);

    Some(Header {
        id,
        is_response,
        rd,
        cd,
        qdcount,
        ancount,
        rcode,
        offset: 12,
    })
}

#[derive(Debug)]
enum ParseError {
    NoQuestion,
    Malformed,
}

fn parse_first_question(
    packet: &[u8],
    qdcount: u16,
    offset: usize,
) -> Result<Option<Question>, ParseError> {
    if qdcount == 0 {
        return Err(ParseError::NoQuestion);
    }
    let (question, _) = parse_question(packet, offset).map_err(|_| ParseError::Malformed)?;
    Ok(Some(question))
}

fn parse_question_for_reply(
    packet: &[u8],
    qdcount: u16,
    offset: usize,
) -> Result<Option<Question>, DecodeQueryError> {
    match parse_first_question(packet, qdcount, offset) {
        Ok(question) => Ok(question),
        Err(ParseError::NoQuestion) => Ok(None),
        Err(ParseError::Malformed) => Err(DecodeQueryError::Drop),
    }
}

fn parse_question(packet: &[u8], offset: usize) -> Result<(Question, usize), DnsError> {
    let (name, mut offset) = parse_name(packet, offset).map_err(|_| DnsError::new("bad name"))?;
    if offset + 4 > packet.len() {
        return Err(DnsError::new("truncated question"));
    }
    let qtype = read_u16(packet, offset).ok_or_else(|| DnsError::new("truncated qtype"))?;
    offset += 2;
    let qclass = read_u16(packet, offset).ok_or_else(|| DnsError::new("truncated qclass"))?;
    offset += 2;
    Ok((
        Question {
            name,
            qtype,
            qclass,
        },
        offset,
    ))
}

fn parse_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut end_offset = start;
    let mut seen = Vec::new();
    let mut depth = 0usize;
    let mut name_len = 0usize;

    loop {
        if offset >= packet.len() {
            return Err(DnsError::new("name out of range"));
        }
        let len = packet[offset];
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(DnsError::new("truncated pointer"));
            }
            let ptr = (((len & 0x3F) as usize) << 8) | packet[offset + 1] as usize;
            if ptr >= packet.len() {
                return Err(DnsError::new("pointer out of range"));
            }
            if seen.contains(&ptr) {
                return Err(DnsError::new("pointer loop"));
            }
            seen.push(ptr);
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            depth += 1;
            if depth > 16 {
                return Err(DnsError::new("pointer depth exceeded"));
            }
            continue;
        }
        if len == 0 {
            offset += 1;
            if !jumped {
                end_offset = offset;
            }
            break;
        }
        if len > 63 {
            return Err(DnsError::new("label too long"));
        }
        offset += 1;
        let end = offset + len as usize;
        if end > packet.len() {
            return Err(DnsError::new("label out of range"));
        }
        if !labels.is_empty() {
            name_len += 1;
        }
        name_len += len as usize;
        if name_len > MAX_DNS_NAME_LEN {
            return Err(DnsError::new("name too long"));
        }
        let label = std::str::from_utf8(&packet[offset..end])
            .map_err(|_| DnsError::new("label not utf-8"))?;
        labels.push(label.to_string());
        offset = end;
        if !jumped {
            end_offset = offset;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        let mut name = labels.join(".");
        name.push('.');
        name
    };

    Ok((name, end_offset))
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    if name == "." {
        out.push(0);
        return Ok(());
    }

    let trimmed = name.trim_end_matches('.');
    let mut name_len = 0usize;
    let mut first = true;
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(DnsError::new("empty label"));
        }
        if label.len() > 63 {
            return Err(DnsError::new("label too long"));
        }
        if !first {
            name_len += 1;
        }
        name_len += label.len();
        if name_len > MAX_DNS_NAME_LEN {
            return Err(DnsError::new("name too long"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
        first = false;
    }
    out.push(0);
    Ok(())
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > packet.len() {
        return None;
    }
    Some(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > packet.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    ]))
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        encode_name, encode_response, parse_name, Question, ResponseParams, CLASS_IN,
        MAX_DNS_NAME_LEN, RR_TXT,
    };

    fn build_name(last_label_len: usize) -> String {
        format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(last_label_len)
        )
    }

    #[test]
    fn encode_name_rejects_long_name() {
        let mut out = Vec::new();
        let max_name = build_name(61);
        assert!(max_name.trim_end_matches('.').len() == MAX_DNS_NAME_LEN);
        assert!(encode_name(&max_name, &mut out).is_ok());

        let mut out = Vec::new();
        let too_long = build_name(62);
        assert!(encode_name(&too_long, &mut out).is_err());
    }

    #[test]
    fn parse_name_rejects_long_name() {
        let mut packet = Vec::new();
        let labels = [63usize, 63, 63, 61];
        for len in labels {
            packet.push(len as u8);
            packet.extend(std::iter::repeat_n(b'a', len));
        }
        packet.push(0);
        assert!(parse_name(&packet, 0).is_ok());

        let mut packet = Vec::new();
        let labels = [63usize, 63, 63, 62];
        for len in labels {
            packet.push(len as u8);
            packet.extend(std::iter::repeat_n(b'a', len));
        }
        packet.push(0);
        assert!(parse_name(&packet, 0).is_err());
    }

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
