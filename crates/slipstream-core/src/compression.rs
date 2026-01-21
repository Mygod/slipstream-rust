use std::io::{self, Read, Write};

const COMPRESSION_MAGIC: u8 = 0x28;
const DEFAULT_LEVEL: i32 = 3;

pub fn compress(payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }

    let mut compressed = Vec::with_capacity(1 + payload.len());
    compressed.push(COMPRESSION_MAGIC);

    let mut encoder = zstd::stream::Encoder::new(&mut compressed, DEFAULT_LEVEL)?;
    encoder.write_all(payload)?;
    encoder.finish()?;

    if compressed.len() >= payload.len() {
        return Ok(payload.to_vec());
    }

    Ok(compressed)
}

pub fn decompress(payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }

    if payload[0] != COMPRESSION_MAGIC {
        return Ok(payload.to_vec());
    }

    let mut decompressed = Vec::new();
    let mut decoder = zstd::stream::Decoder::new(&payload[1..])?;
    decoder.read_to_end(&mut decompressed)?;

    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_compressible_data() {
        let data = b"hello world hello world hello world hello world hello world";
        let compressed = compress(data).unwrap();
        assert!(compressed.len() < data.len());
        assert_eq!(compressed[0], COMPRESSION_MAGIC);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn passthrough_small_data() {
        let data = b"hi";
        let result = compress(data).unwrap();
        assert_eq!(result, data);
        let decompressed = decompress(&result).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn passthrough_uncompressed() {
        let data = b"\x01\x02\x03\x04";
        let decompressed = decompress(data).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn empty_input() {
        let compressed = compress(b"").unwrap();
        assert!(compressed.is_empty());
        let decompressed = decompress(b"").unwrap();
        assert!(decompressed.is_empty());
    }
}
