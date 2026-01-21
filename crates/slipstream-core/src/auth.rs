use sha2::{Digest, Sha256};

/// Stream 0 is dedicated to authentication
pub const AUTH_STREAM_ID: u64 = 0;

/// Message type for auth request
const AUTH_REQUEST_TYPE: u8 = 0x01;
/// Message type for auth response
const AUTH_RESPONSE_TYPE: u8 = 0x02;

/// Auth request size: 1 byte type + 32 bytes SHA-256 hash
pub const AUTH_REQUEST_SIZE: usize = 33;
/// Auth response size: 1 byte type + 1 byte status
pub const AUTH_RESPONSE_SIZE: usize = 2;

/// Authentication status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthStatus {
    /// Authentication successful
    Success = 0x00,
    /// Invalid token provided
    Invalid = 0x01,
    /// Authentication required but not provided
    Required = 0x02,
}

impl AuthStatus {
    /// Parse status from a byte value
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(AuthStatus::Success),
            0x01 => Some(AuthStatus::Invalid),
            0x02 => Some(AuthStatus::Required),
            _ => None,
        }
    }
}

/// Hash a token using SHA-256
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

/// Build an authentication request message
/// Format: [0x01][SHA-256(token)] = 33 bytes
pub fn build_auth_request(token: &str) -> [u8; AUTH_REQUEST_SIZE] {
    let mut request = [0u8; AUTH_REQUEST_SIZE];
    request[0] = AUTH_REQUEST_TYPE;
    let hash = hash_token(token);
    request[1..].copy_from_slice(&hash);
    request
}

/// Build an authentication response message
/// Format: [0x02][status] = 2 bytes
pub fn build_auth_response(status: AuthStatus) -> [u8; AUTH_RESPONSE_SIZE] {
    [AUTH_RESPONSE_TYPE, status as u8]
}

/// Parse an authentication request, returning the token hash if valid
pub fn parse_auth_request(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() != AUTH_REQUEST_SIZE {
        return None;
    }
    if data[0] != AUTH_REQUEST_TYPE {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[1..]);
    Some(hash)
}

/// Parse an authentication response, returning the status if valid
pub fn parse_auth_response(data: &[u8]) -> Option<AuthStatus> {
    if data.len() != AUTH_RESPONSE_SIZE {
        return None;
    }
    if data[0] != AUTH_RESPONSE_TYPE {
        return None;
    }
    AuthStatus::from_byte(data[1])
}

/// Validate a received token hash against an expected token
pub fn validate_token_hash(received: &[u8; 32], expected_token: &str) -> bool {
    let expected_hash = hash_token(expected_token);
    // Constant-time comparison to prevent timing attacks
    let mut result = 0u8;
    for (a, b) in received.iter().zip(expected_hash.iter()) {
        result |= a ^ b;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token_deterministic() {
        let hash1 = hash_token("secret");
        let hash2 = hash_token("secret");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let hash1 = hash_token("secret1");
        let hash2 = hash_token("secret2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_build_auth_request() {
        let request = build_auth_request("secret");
        assert_eq!(request.len(), AUTH_REQUEST_SIZE);
        assert_eq!(request[0], AUTH_REQUEST_TYPE);
    }

    #[test]
    fn test_build_auth_response() {
        let response = build_auth_response(AuthStatus::Success);
        assert_eq!(response.len(), AUTH_RESPONSE_SIZE);
        assert_eq!(response[0], AUTH_RESPONSE_TYPE);
        assert_eq!(response[1], 0x00);

        let response = build_auth_response(AuthStatus::Invalid);
        assert_eq!(response[1], 0x01);

        let response = build_auth_response(AuthStatus::Required);
        assert_eq!(response[1], 0x02);
    }

    #[test]
    fn test_parse_auth_request_valid() {
        let request = build_auth_request("secret");
        let hash = parse_auth_request(&request).expect("should parse");
        assert_eq!(hash, hash_token("secret"));
    }

    #[test]
    fn test_parse_auth_request_wrong_size() {
        let data = [0x01; 10];
        assert!(parse_auth_request(&data).is_none());
    }

    #[test]
    fn test_parse_auth_request_wrong_type() {
        let mut request = build_auth_request("secret");
        request[0] = 0xFF;
        assert!(parse_auth_request(&request).is_none());
    }

    #[test]
    fn test_parse_auth_response_valid() {
        let response = build_auth_response(AuthStatus::Success);
        assert_eq!(
            parse_auth_response(&response),
            Some(AuthStatus::Success)
        );

        let response = build_auth_response(AuthStatus::Invalid);
        assert_eq!(
            parse_auth_response(&response),
            Some(AuthStatus::Invalid)
        );

        let response = build_auth_response(AuthStatus::Required);
        assert_eq!(
            parse_auth_response(&response),
            Some(AuthStatus::Required)
        );
    }

    #[test]
    fn test_parse_auth_response_wrong_size() {
        let data = [0x02];
        assert!(parse_auth_response(&data).is_none());
    }

    #[test]
    fn test_parse_auth_response_wrong_type() {
        let data = [0xFF, 0x00];
        assert!(parse_auth_response(&data).is_none());
    }

    #[test]
    fn test_parse_auth_response_unknown_status() {
        let data = [AUTH_RESPONSE_TYPE, 0xFF];
        assert!(parse_auth_response(&data).is_none());
    }

    #[test]
    fn test_validate_token_hash_correct() {
        let hash = hash_token("secret");
        assert!(validate_token_hash(&hash, "secret"));
    }

    #[test]
    fn test_validate_token_hash_incorrect() {
        let hash = hash_token("secret");
        assert!(!validate_token_hash(&hash, "wrong"));
    }

    #[test]
    fn test_round_trip() {
        let token = "my_secret_token";
        let request = build_auth_request(token);
        let received_hash = parse_auth_request(&request).expect("should parse");
        assert!(validate_token_hash(&received_hash, token));
        assert!(!validate_token_hash(&received_hash, "wrong_token"));
    }
}
