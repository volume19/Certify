//! Certificate SID extension encoding
//!
//! This module provides utilities for encoding Windows SIDs into ASN.1/DER format
//! for use in certificate extensions, particularly the szOID_NTDS_CA_SECURITY_EXT
//! extension used in Active Directory Certificate Services.

use crate::error::{CertifyError, Result};

/// ASN.1 tags for DER encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Asn1Tag {
    /// SEQUENCE tag (0x30)
    Sequence = 0x30,
    /// OCTET STRING tag (0x04)
    OctetString = 0x04,
    /// INTEGER tag (0x02)
    Integer = 0x02,
}

/// Encodes a Windows SID string into binary format
///
/// Converts a SID string like "S-1-5-21-123-456-789-1001" into the binary
/// format used by Windows (revision + identifier authority + sub-authorities).
///
/// # Arguments
///
/// * `sid` - SID string in standard format (S-R-IA-SA1-SA2-...)
///
/// # Returns
///
/// Binary representation of the SID
///
/// # Example
///
/// ```
/// use certify::crypto::sid_extension::encode_sid_binary;
///
/// let sid = "S-1-5-21-123-456-789-1001";
/// let binary = encode_sid_binary(sid)?;
/// assert!(!binary.is_empty());
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn encode_sid_binary(sid: &str) -> Result<Vec<u8>> {
    // Parse SID string format: S-R-IA-SA1-SA2-...
    let parts: Vec<&str> = sid.split('-').collect();

    if parts.len() < 3 || parts[0] != "S" {
        return Err(CertifyError::Crypto(format!("Invalid SID format: {}", sid)));
    }

    // Parse revision (should be 1)
    let revision: u8 = parts[1]
        .parse()
        .map_err(|_| CertifyError::Crypto(format!("Invalid SID revision: {}", parts[1])))?;

    // Parse identifier authority
    let identifier_authority: u64 = parts[2]
        .parse()
        .map_err(|_| CertifyError::Crypto(format!("Invalid identifier authority: {}", parts[2])))?;

    // Parse sub-authorities
    let sub_authorities: Vec<u32> = parts[3..]
        .iter()
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| CertifyError::Crypto(format!("Invalid sub-authority: {}", s)))
        })
        .collect::<Result<Vec<u32>>>()?;

    if sub_authorities.len() > 15 {
        return Err(CertifyError::Crypto(
            "SID cannot have more than 15 sub-authorities".to_string(),
        ));
    }

    // Build binary SID
    let mut binary = Vec::new();

    // Revision (1 byte)
    binary.push(revision);

    // Sub-authority count (1 byte)
    binary.push(sub_authorities.len() as u8);

    // Identifier authority (6 bytes, big-endian)
    binary.extend_from_slice(&[
        ((identifier_authority >> 40) & 0xFF) as u8,
        ((identifier_authority >> 32) & 0xFF) as u8,
        ((identifier_authority >> 24) & 0xFF) as u8,
        ((identifier_authority >> 16) & 0xFF) as u8,
        ((identifier_authority >> 8) & 0xFF) as u8,
        (identifier_authority & 0xFF) as u8,
    ]);

    // Sub-authorities (4 bytes each, little-endian)
    for sub_auth in sub_authorities {
        binary.extend_from_slice(&sub_auth.to_le_bytes());
    }

    Ok(binary)
}

/// Encodes data with ASN.1 DER tag-length-value format
///
/// # Arguments
///
/// * `tag` - ASN.1 tag
/// * `data` - Data to encode
///
/// # Returns
///
/// DER-encoded data with tag and length
fn encode_asn1_tlv(tag: Asn1Tag, data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // Tag
    result.push(tag as u8);

    // Length
    let len = data.len();
    if len < 128 {
        // Short form: length fits in one byte
        result.push(len as u8);
    } else {
        // Long form: first byte indicates number of length bytes
        let len_bytes = if len < 256 {
            1
        } else if len < 65536 {
            2
        } else if len < 16777216 {
            3
        } else {
            4
        };

        result.push(0x80 | len_bytes);

        // Encode length in big-endian
        for i in (0..len_bytes).rev() {
            result.push(((len >> (i * 8)) & 0xFF) as u8);
        }
    }

    // Value
    result.extend_from_slice(data);

    result
}

/// Encodes a SID into ASN.1/DER format for certificate extensions
///
/// This creates an ASN.1 SEQUENCE containing an OCTET STRING with the binary SID.
/// The format is used for the szOID_NTDS_CA_SECURITY_EXT extension in AD CS certificates.
///
/// # Arguments
///
/// * `sid` - SID string in standard format (S-R-IA-SA1-SA2-...)
///
/// # Returns
///
/// ASN.1/DER encoded SID suitable for certificate extensions
///
/// # Example
///
/// ```
/// use certify::crypto::sid_extension::encode_sid_extension;
///
/// let sid = "S-1-5-21-123-456-789-1001";
/// let encoded = encode_sid_extension(sid)?;
/// assert!(!encoded.is_empty());
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn encode_sid_extension(sid: &str) -> Result<Vec<u8>> {
    // Convert SID to binary
    let sid_binary = encode_sid_binary(sid)?;

    // Wrap in OCTET STRING
    let octet_string = encode_asn1_tlv(Asn1Tag::OctetString, &sid_binary);

    // Wrap in SEQUENCE
    let sequence = encode_asn1_tlv(Asn1Tag::Sequence, &octet_string);

    Ok(sequence)
}

/// Decodes a binary SID back to string format
///
/// Converts binary SID format back to the standard string representation.
///
/// # Arguments
///
/// * `binary` - Binary SID data
///
/// # Returns
///
/// SID string in format S-R-IA-SA1-SA2-...
///
/// # Example
///
/// ```
/// use certify::crypto::sid_extension::{encode_sid_binary, decode_sid_binary};
///
/// let sid = "S-1-5-21-123-456-789-1001";
/// let binary = encode_sid_binary(sid)?;
/// let decoded = decode_sid_binary(&binary)?;
/// assert_eq!(decoded, sid);
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn decode_sid_binary(binary: &[u8]) -> Result<String> {
    if binary.len() < 8 {
        return Err(CertifyError::Crypto("SID binary too short".to_string()));
    }

    let revision = binary[0];
    let sub_auth_count = binary[1] as usize;

    // Identifier authority (6 bytes, big-endian)
    let identifier_authority = ((binary[2] as u64) << 40)
        | ((binary[3] as u64) << 32)
        | ((binary[4] as u64) << 24)
        | ((binary[5] as u64) << 16)
        | ((binary[6] as u64) << 8)
        | (binary[7] as u64);

    let mut sid = format!("S-{}-{}", revision, identifier_authority);

    // Sub-authorities (4 bytes each, little-endian)
    let expected_len = 8 + (sub_auth_count * 4);
    if binary.len() < expected_len {
        return Err(CertifyError::Crypto(
            "SID binary length mismatch".to_string(),
        ));
    }

    for i in 0..sub_auth_count {
        let offset = 8 + (i * 4);
        let sub_auth = u32::from_le_bytes([
            binary[offset],
            binary[offset + 1],
            binary[offset + 2],
            binary[offset + 3],
        ]);
        sid.push_str(&format!("-{}", sub_auth));
    }

    Ok(sid)
}

/// Creates an ASN.1 extension value for a collection of SIDs
///
/// Encodes multiple SIDs into a single ASN.1 SEQUENCE for use in certificate extensions.
///
/// # Arguments
///
/// * `sids` - Collection of SID strings
///
/// # Returns
///
/// ASN.1/DER encoded extension value containing all SIDs
pub fn encode_multiple_sids(sids: &[String]) -> Result<Vec<u8>> {
    let mut encoded_sids = Vec::new();

    for sid in sids {
        let sid_binary = encode_sid_binary(sid)?;
        let octet_string = encode_asn1_tlv(Asn1Tag::OctetString, &sid_binary);
        encoded_sids.extend_from_slice(&octet_string);
    }

    // Wrap all in a SEQUENCE
    let sequence = encode_asn1_tlv(Asn1Tag::Sequence, &encoded_sids);

    Ok(sequence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_sid_binary() {
        let sid = "S-1-5-21-123-456-789-1001";
        let binary = encode_sid_binary(sid).unwrap();

        // Check structure
        assert_eq!(binary[0], 1); // Revision
        assert_eq!(binary[1], 5); // Sub-authority count (21, 123, 456, 789, 1001)

        // Check identifier authority (5 encoded as 6 bytes big-endian)
        assert_eq!(&binary[2..8], &[0, 0, 0, 0, 0, 5]);
    }

    #[test]
    fn test_encode_decode_sid_roundtrip() {
        let original_sid = "S-1-5-21-123-456-789-1001";
        let binary = encode_sid_binary(original_sid).unwrap();
        let decoded_sid = decode_sid_binary(&binary).unwrap();

        assert_eq!(original_sid, decoded_sid);
    }

    #[test]
    fn test_encode_well_known_sids() {
        // Test various well-known SIDs
        let sids = vec![
            "S-1-5-32-544",           // Administrators
            "S-1-5-32-545",           // Users
            "S-1-5-18",               // Local System
            "S-1-1-0",                // Everyone
            "S-1-5-11",               // Authenticated Users
        ];

        for sid in sids {
            let binary = encode_sid_binary(sid).unwrap();
            let decoded = decode_sid_binary(&binary).unwrap();
            assert_eq!(sid, decoded);
        }
    }

    #[test]
    fn test_invalid_sid_format() {
        let invalid_sids = vec![
            "invalid",
            "S-1",
            "S-X-5-21",
            "1-5-21-123",
        ];

        for sid in invalid_sids {
            assert!(encode_sid_binary(sid).is_err());
        }
    }

    #[test]
    fn test_encode_asn1_tlv_short_length() {
        let data = vec![1, 2, 3, 4, 5];
        let encoded = encode_asn1_tlv(Asn1Tag::OctetString, &data);

        assert_eq!(encoded[0], 0x04); // OCTET STRING tag
        assert_eq!(encoded[1], 5); // Length
        assert_eq!(&encoded[2..], &data[..]);
    }

    #[test]
    fn test_encode_sid_extension() {
        let sid = "S-1-5-21-123-456-789-1001";
        let encoded = encode_sid_extension(sid).unwrap();

        // Check it starts with SEQUENCE tag
        assert_eq!(encoded[0], 0x30);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_multiple_sids() {
        let sids = vec![
            "S-1-5-21-123-456-789-1001".to_string(),
            "S-1-5-32-544".to_string(),
        ];

        let encoded = encode_multiple_sids(&sids).unwrap();

        // Check it starts with SEQUENCE tag
        assert_eq!(encoded[0], 0x30);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_sid_with_max_sub_authorities() {
        // Windows allows up to 15 sub-authorities
        let sid = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15";
        let binary = encode_sid_binary(sid).unwrap();
        let decoded = decode_sid_binary(&binary).unwrap();
        assert_eq!(sid, decoded);
    }

    #[test]
    fn test_sid_too_many_sub_authorities() {
        // More than 15 sub-authorities should fail
        let sid = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16";
        assert!(encode_sid_binary(sid).is_err());
    }
}
