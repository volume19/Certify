//! Certificate format transformation utilities
//!
//! This module provides utilities for converting between different certificate
//! formats (PFX/PKCS#12, PEM, DER) used in certificate enrollment and management.

use crate::error::{CertifyError, Result};

/// Certificate format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateFormat {
    /// DER-encoded binary format
    Der,
    /// PEM-encoded text format (Base64 with headers)
    Pem,
    /// PKCS#12/PFX format (includes private key)
    Pfx,
}

/// PEM object types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemType {
    /// X.509 Certificate
    Certificate,
    /// Private key (PKCS#8)
    PrivateKey,
    /// Certificate request (PKCS#10)
    CertificateRequest,
    /// RSA private key
    RsaPrivateKey,
}

impl PemType {
    /// Get the PEM header label for this type
    pub fn label(&self) -> &'static str {
        match self {
            PemType::Certificate => "CERTIFICATE",
            PemType::PrivateKey => "PRIVATE KEY",
            PemType::CertificateRequest => "CERTIFICATE REQUEST",
            PemType::RsaPrivateKey => "RSA PRIVATE KEY",
        }
    }
}

/// Encodes binary data to PEM format
///
/// Converts binary DER data to PEM format with appropriate headers and Base64 encoding.
///
/// # Arguments
///
/// * `data` - Binary DER-encoded data
/// * `pem_type` - Type of PEM object (determines headers)
///
/// # Returns
///
/// PEM-encoded string with headers and Base64 data
///
/// # Example
///
/// ```
/// use certify::crypto::cert_transform::{encode_pem, PemType};
///
/// let der_data = vec![0x30, 0x82, 0x01, 0x00]; // Example DER data
/// let pem = encode_pem(&der_data, PemType::Certificate)?;
/// assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn encode_pem(data: &[u8], pem_type: PemType) -> Result<String> {
    // Encode to Base64
    let base64_data = base64_encode(data);

    // Build PEM format with headers
    let label = pem_type.label();
    let mut pem = format!("-----BEGIN {}-----\n", label);

    // Add Base64 data in 64-character lines
    for chunk in base64_data.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).map_err(|e| {
            CertifyError::Crypto(format!("Invalid UTF-8 in Base64: {}", e))
        })?);
        pem.push('\n');
    }

    pem.push_str(&format!("-----END {}-----\n", label));

    Ok(pem)
}

/// Decodes PEM format to binary DER data
///
/// Extracts the Base64-encoded data from PEM format and decodes it to binary.
///
/// # Arguments
///
/// * `pem` - PEM-encoded string
///
/// # Returns
///
/// Tuple of (binary DER data, PEM type)
///
/// # Example
///
/// ```
/// use certify::crypto::cert_transform::{encode_pem, decode_pem, PemType};
///
/// let der_data = vec![0x30, 0x82, 0x01, 0x00];
/// let pem = encode_pem(&der_data, PemType::Certificate)?;
/// let (decoded, pem_type) = decode_pem(&pem)?;
/// assert_eq!(decoded, der_data);
/// assert_eq!(pem_type, PemType::Certificate);
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn decode_pem(pem: &str) -> Result<(Vec<u8>, PemType)> {
    // Find BEGIN header
    let begin_marker = "-----BEGIN ";
    let end_marker = "-----END ";

    let begin_pos = pem
        .find(begin_marker)
        .ok_or_else(|| CertifyError::Crypto("No PEM BEGIN marker found".to_string()))?;

    let label_start = begin_pos + begin_marker.len();
    let label_end = pem[label_start..]
        .find("-----")
        .ok_or_else(|| CertifyError::Crypto("Malformed PEM BEGIN marker".to_string()))?
        + label_start;

    let label = &pem[label_start..label_end];

    // Determine PEM type from label
    let pem_type = match label {
        "CERTIFICATE" => PemType::Certificate,
        "PRIVATE KEY" => PemType::PrivateKey,
        "CERTIFICATE REQUEST" => PemType::CertificateRequest,
        "RSA PRIVATE KEY" => PemType::RsaPrivateKey,
        _ => {
            return Err(CertifyError::Crypto(format!(
                "Unknown PEM type: {}",
                label
            )))
        }
    };

    // Find END header
    let end_pos = pem
        .find(&format!("{}{}-----", end_marker, label))
        .ok_or_else(|| CertifyError::Crypto("No PEM END marker found".to_string()))?;

    // Extract Base64 data (between headers)
    let data_start = pem[label_end..]
        .find('\n')
        .ok_or_else(|| CertifyError::Crypto("Malformed PEM format".to_string()))?
        + label_end
        + 1;

    let base64_data: String = pem[data_start..end_pos]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Decode Base64
    let der_data = base64_decode(&base64_data)?;

    Ok((der_data, pem_type))
}

/// Simple Base64 encoding implementation
fn base64_encode(data: &[u8]) -> String {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b1 = data[i];
        let b2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b3 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

        result.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
        result.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);

        if i + 1 < data.len() {
            result.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(BASE64_CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Simple Base64 decoding implementation
fn base64_decode(data: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let chars: Vec<char> = data.chars().filter(|c| !c.is_whitespace()).collect();

    if chars.len() % 4 != 0 {
        return Err(CertifyError::Crypto(
            "Invalid Base64 length".to_string(),
        ));
    }

    for chunk in chars.chunks(4) {
        let b1 = base64_char_value(chunk[0])?;
        let b2 = base64_char_value(chunk[1])?;
        let b3 = if chunk[2] != '=' {
            base64_char_value(chunk[2])?
        } else {
            0
        };
        let b4 = if chunk[3] != '=' {
            base64_char_value(chunk[3])?
        } else {
            0
        };

        let n = ((b1 as u32) << 18) | ((b2 as u32) << 12) | ((b3 as u32) << 6) | (b4 as u32);

        result.push(((n >> 16) & 0xFF) as u8);

        if chunk[2] != '=' {
            result.push(((n >> 8) & 0xFF) as u8);
        }

        if chunk[3] != '=' {
            result.push((n & 0xFF) as u8);
        }
    }

    Ok(result)
}

/// Get numeric value for a Base64 character
fn base64_char_value(c: char) -> Result<u8> {
    match c {
        'A'..='Z' => Ok((c as u8) - b'A'),
        'a'..='z' => Ok((c as u8) - b'a' + 26),
        '0'..='9' => Ok((c as u8) - b'0' + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        '=' => Ok(0),
        _ => Err(CertifyError::Crypto(format!(
            "Invalid Base64 character: {}",
            c
        ))),
    }
}

/// Certificate data container
#[derive(Debug, Clone)]
pub struct Certificate {
    /// DER-encoded certificate data
    pub der_data: Vec<u8>,
    /// Certificate format
    pub format: CertificateFormat,
}

impl Certificate {
    /// Create a new certificate from DER data
    pub fn from_der(data: Vec<u8>) -> Self {
        Self {
            der_data: data,
            format: CertificateFormat::Der,
        }
    }

    /// Create a new certificate from PEM data
    pub fn from_pem(pem: &str) -> Result<Self> {
        let (der_data, pem_type) = decode_pem(pem)?;

        if pem_type != PemType::Certificate {
            return Err(CertifyError::Crypto(format!(
                "Expected CERTIFICATE PEM type, got {:?}",
                pem_type
            )));
        }

        Ok(Self {
            der_data,
            format: CertificateFormat::Pem,
        })
    }

    /// Convert certificate to PEM format
    pub fn to_pem(&self) -> Result<String> {
        encode_pem(&self.der_data, PemType::Certificate)
    }

    /// Get DER-encoded data
    pub fn to_der(&self) -> &[u8] {
        &self.der_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_type_label() {
        assert_eq!(PemType::Certificate.label(), "CERTIFICATE");
        assert_eq!(PemType::PrivateKey.label(), "PRIVATE KEY");
        assert_eq!(PemType::CertificateRequest.label(), "CERTIFICATE REQUEST");
    }

    #[test]
    fn test_base64_encode_decode() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_base64_encode_empty() {
        let data = b"";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_base64_roundtrip_various_lengths() {
        // Test different lengths to ensure padding works correctly
        for len in 0..10 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encoded = base64_encode(&data);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(data, decoded);
        }
    }

    #[test]
    fn test_encode_decode_pem() {
        let der_data = vec![
            0x30, 0x82, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        let pem = encode_pem(&der_data, PemType::Certificate).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));

        let (decoded, pem_type) = decode_pem(&pem).unwrap();
        assert_eq!(decoded, der_data);
        assert_eq!(pem_type, PemType::Certificate);
    }

    #[test]
    fn test_certificate_from_der() {
        let der_data = vec![0x30, 0x82, 0x01, 0x00];
        let cert = Certificate::from_der(der_data.clone());

        assert_eq!(cert.der_data, der_data);
        assert_eq!(cert.format, CertificateFormat::Der);
    }

    #[test]
    fn test_certificate_to_pem() {
        let der_data = vec![0x30, 0x82, 0x01, 0x00];
        let cert = Certificate::from_der(der_data);

        let pem = cert.to_pem().unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_certificate_from_pem() {
        let der_data = vec![0x30, 0x82, 0x01, 0x00];
        let pem = encode_pem(&der_data, PemType::Certificate).unwrap();

        let cert = Certificate::from_pem(&pem).unwrap();
        assert_eq!(cert.der_data, der_data);
    }

    #[test]
    fn test_invalid_pem() {
        let invalid_pem = "Not a PEM string";
        assert!(decode_pem(invalid_pem).is_err());
    }

    #[test]
    fn test_base64_invalid_char() {
        assert!(base64_char_value('$').is_err());
        assert!(base64_char_value('@').is_err());
    }
}
