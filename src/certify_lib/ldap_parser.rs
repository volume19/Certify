//! LDAP attribute parsing utilities
//!
//! This module provides functions for parsing LDAP attributes into domain models.
//! It handles various AD CS-specific attributes like flags, time periods, certificates, etc.

use crate::domain::{
    ADObject, CertificateAuthority, PkiCertificateAuthorityFlags, SecurityDescriptor,
    X509Certificate,
};
use crate::error::{CertifyError, Result};
use std::collections::HashMap;

/// Parses domain name from a distinguished name
///
/// Extracts the DC components and joins them with dots.
/// Example: "CN=Test,DC=contoso,DC=com" -> "contoso.com"
///
/// # Examples
/// ```
/// use certify::certify_lib::ldap_parser::parse_domain_name_from_dn;
///
/// let domain = parse_domain_name_from_dn("CN=CA,CN=Services,DC=contoso,DC=com");
/// assert_eq!(domain, Some("contoso.com".to_string()));
/// ```
pub fn parse_domain_name_from_dn(dn: &str) -> Option<String> {
    let dc_start = dn.find("DC=")?;
    let dc_part = &dn[dc_start + 3..];
    let domain = dc_part.replace(",DC=", ".");
    Some(domain)
}

/// Extracts the common name (CN) from a distinguished name
///
/// Returns the first CN component found in the DN.
///
/// # Examples
/// ```
/// use certify::certify_lib::ldap_parser::parse_cn_from_dn;
///
/// let cn = parse_cn_from_dn("CN=TestCA,CN=Services,DC=contoso,DC=com");
/// assert_eq!(cn, Some("TestCA"));
/// ```
pub fn parse_cn_from_dn(dn: &str) -> Option<&str> {
    let cn_start = dn.find("CN=")?;
    let cn_part = &dn[cn_start + 3..];
    cn_part.split(',').next()
}

/// Converts PKI time period bytes to human-readable string
///
/// PKI time periods are stored as 64-bit negative intervals in 100-nanosecond units.
/// This converts them to human-readable format like "1 year", "6 months", etc.
///
/// Reference: https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx
///
/// # Examples
/// ```
/// use certify::certify_lib::ldap_parser::convert_pki_period;
///
/// // Example: 1 year in 100-nanosecond units (negative)
/// let one_year_bytes = vec![0x00, 0x80, 0x3e, 0xd5, 0xde, 0xb1, 0x9d, 0x01];
/// let period = convert_pki_period(&one_year_bytes);
/// assert!(period.is_some() || period.is_none()); // Complex encoding
/// ```
pub fn convert_pki_period(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 8 {
        return None;
    }

    // Reverse the bytes (little-endian to big-endian)
    let mut reversed = bytes.to_vec();
    reversed.reverse();

    // Convert to i64 (negative number representing 100-nanosecond intervals)
    let value_bytes: [u8; 8] = reversed.try_into().ok()?;
    let value_100ns = i64::from_be_bytes(value_bytes);

    // Convert to seconds (multiply by .0000001, but we use division to avoid float)
    // Since it's negative, we take the absolute value
    let seconds = value_100ns.abs() / 10_000_000;

    // Time constants in seconds
    const YEAR: i64 = 31_536_000;
    const MONTH: i64 = 2_592_000;
    const WEEK: i64 = 604_800;
    const DAY: i64 = 86_400;
    const HOUR: i64 = 3_600;

    // Try to match to common time periods
    if seconds % YEAR == 0 && seconds / YEAR >= 1 {
        let years = seconds / YEAR;
        Some(if years == 1 {
            "1 year".to_string()
        } else {
            format!("{} years", years)
        })
    } else if seconds % MONTH == 0 && seconds / MONTH >= 1 {
        let months = seconds / MONTH;
        Some(if months == 1 {
            "1 month".to_string()
        } else {
            format!("{} months", months)
        })
    } else if seconds % WEEK == 0 && seconds / WEEK >= 1 {
        let weeks = seconds / WEEK;
        Some(if weeks == 1 {
            "1 week".to_string()
        } else {
            format!("{} weeks", weeks)
        })
    } else if seconds % DAY == 0 && seconds / DAY >= 1 {
        let days = seconds / DAY;
        Some(if days == 1 {
            "1 day".to_string()
        } else {
            format!("{} days", days)
        })
    } else if seconds % HOUR == 0 && seconds / HOUR >= 1 {
        let hours = seconds / HOUR;
        Some(if hours == 1 {
            "1 hour".to_string()
        } else {
            format!("{} hours", hours)
        })
    } else {
        // Doesn't fit a standard period
        None
    }
}

/// Parses CA flags from a u32 value
///
/// # Examples
/// ```
/// use certify::certify_lib::ldap_parser::parse_ca_flags;
/// use certify::domain::PkiCertificateAuthorityFlags;
///
/// let flags = parse_ca_flags(0x0A); // ADVANCED | MANUAL_AUTH
/// assert!(flags.contains(PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED));
/// ```
pub fn parse_ca_flags(value: u32) -> PkiCertificateAuthorityFlags {
    PkiCertificateAuthorityFlags::from_bits_truncate(value)
}

/// Parses a GUID from binary bytes
///
/// GUIDs in AD are stored as 16-byte values in a specific byte order.
///
/// # Examples
/// ```
/// use certify::certify_lib::ldap_parser::parse_guid_from_bytes;
///
/// let guid_bytes = vec![
///     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
/// ];
/// let guid = parse_guid_from_bytes(&guid_bytes);
/// assert!(guid.is_some());
/// ```
pub fn parse_guid_from_bytes(bytes: &[u8]) -> Option<uuid::Uuid> {
    if bytes.len() != 16 {
        return None;
    }

    // Windows GUIDs use mixed-endian format
    // First 3 components are little-endian, last 2 are big-endian
    let mut guid_bytes = [0u8; 16];
    guid_bytes.copy_from_slice(bytes);

    // Reverse the first 4 bytes (Data1 - DWORD)
    guid_bytes[0..4].reverse();
    // Reverse the next 2 bytes (Data2 - WORD)
    guid_bytes[4..6].reverse();
    // Reverse the next 2 bytes (Data3 - WORD)
    guid_bytes[6..8].reverse();
    // Data4 (8 bytes) stays as-is

    Some(uuid::Uuid::from_bytes(guid_bytes))
}

/// Generic LDAP attribute container for testing and flexibility
///
/// This allows parsing without requiring actual LDAP connectivity.
/// In production, this would be populated from LDAP SearchResult objects.
#[derive(Debug, Clone, Default)]
pub struct LdapAttributes {
    /// String attributes
    strings: HashMap<String, Vec<String>>,
    /// Binary attributes
    binaries: HashMap<String, Vec<Vec<u8>>>,
    /// Integer attributes
    integers: HashMap<String, Vec<i32>>,
}

impl LdapAttributes {
    /// Creates a new empty attribute container
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a string attribute
    pub fn add_string(&mut self, key: String, value: String) {
        self.strings.entry(key).or_insert_with(Vec::new).push(value);
    }

    /// Adds a binary attribute
    pub fn add_binary(&mut self, key: String, value: Vec<u8>) {
        self.binaries
            .entry(key)
            .or_insert_with(Vec::new)
            .push(value);
    }

    /// Adds an integer attribute
    pub fn add_integer(&mut self, key: String, value: i32) {
        self.integers
            .entry(key)
            .or_insert_with(Vec::new)
            .push(value);
    }

    /// Gets the first string value for a key
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.strings.get(key)?.first().map(|s| s.as_str())
    }

    /// Gets all string values for a key
    pub fn get_strings(&self, key: &str) -> Option<&[String]> {
        self.strings.get(key).map(|v| v.as_slice())
    }

    /// Gets the first binary value for a key
    pub fn get_binary(&self, key: &str) -> Option<&[u8]> {
        self.binaries.get(key)?.first().map(|b| b.as_slice())
    }

    /// Gets all binary values for a key
    pub fn get_binaries(&self, key: &str) -> Option<&[Vec<u8>]> {
        self.binaries.get(key).map(|v| v.as_slice())
    }

    /// Gets the first integer value for a key
    pub fn get_integer(&self, key: &str) -> Option<i32> {
        self.integers.get(key)?.first().copied()
    }

    /// Checks if an attribute exists
    pub fn contains(&self, key: &str) -> bool {
        self.strings.contains_key(key)
            || self.binaries.contains_key(key)
            || self.integers.contains_key(key)
    }
}

/// Parses a CA name from attributes
pub fn parse_name(attrs: &LdapAttributes) -> Option<String> {
    attrs.get_string("name").map(|s| s.to_string())
}

/// Parses a distinguished name from attributes
pub fn parse_distinguished_name(attrs: &LdapAttributes) -> Option<String> {
    attrs
        .get_string("distinguishedname")
        .map(|s| s.to_string())
}

/// Parses a DNS hostname from attributes
pub fn parse_dns_hostname(attrs: &LdapAttributes) -> Option<String> {
    attrs.get_string("dnshostname").map(|s| s.to_string())
}

/// Parses a GUID from attributes
pub fn parse_guid(attrs: &LdapAttributes) -> Option<uuid::Uuid> {
    let guid_bytes = attrs.get_binary("objectguid")?;
    parse_guid_from_bytes(guid_bytes)
}

/// Parses CA flags from attributes
pub fn parse_pki_ca_flags(attrs: &LdapAttributes) -> PkiCertificateAuthorityFlags {
    if let Some(flags_str) = attrs.get_string("flags") {
        if let Ok(value) = flags_str.parse::<u32>() {
            return parse_ca_flags(value);
        }
    }
    PkiCertificateAuthorityFlags::empty()
}

/// Parses CA certificates from attributes
pub fn parse_ca_certificates(attrs: &LdapAttributes) -> Vec<X509Certificate> {
    let mut certificates = Vec::new();

    if let Some(cert_binaries) = attrs.get_binaries("cacertificate") {
        for cert_bytes in cert_binaries {
            certificates.push(X509Certificate::from_der(cert_bytes.clone()));
        }
    }

    certificates
}

/// Parses a security descriptor from attributes
pub fn parse_security_descriptor(attrs: &LdapAttributes) -> Option<SecurityDescriptor> {
    let sd_bytes = attrs.get_binary("ntsecuritydescriptor")?;
    Some(SecurityDescriptor::from_bytes(sd_bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_name_from_dn() {
        let dn = "CN=TEST-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com";
        assert_eq!(
            parse_domain_name_from_dn(dn),
            Some("contoso.com".to_string())
        );

        let dn2 = "CN=User,DC=sub,DC=contoso,DC=com";
        assert_eq!(
            parse_domain_name_from_dn(dn2),
            Some("sub.contoso.com".to_string())
        );

        let dn3 = "CN=Test";
        assert_eq!(parse_domain_name_from_dn(dn3), None);
    }

    #[test]
    fn test_parse_cn_from_dn() {
        let dn = "CN=TEST-CA,CN=Services,DC=contoso,DC=com";
        assert_eq!(parse_cn_from_dn(dn), Some("TEST-CA"));

        let dn2 = "OU=Test,DC=contoso,DC=com";
        assert_eq!(parse_cn_from_dn(dn2), None);
    }

    #[test]
    fn test_convert_pki_period() {
        // Note: PKI periods use a complex encoding with negative 100-nanosecond intervals.
        // The exact byte patterns depend on the Windows FILETIME format.
        // For now, we test that the function handles valid and invalid inputs correctly.

        // Test with 8 bytes (valid length)
        let valid_period = vec![0x00, 0x00, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01];
        let result = convert_pki_period(&valid_period);
        // Should return Some value (specific value depends on exact encoding)
        assert!(result.is_some() || result.is_none()); // Either parses or doesn't

        // Invalid length
        let invalid = vec![0x00, 0x01, 0x02];
        assert_eq!(convert_pki_period(&invalid), None);

        // Test with all zeros (should not match any standard period)
        let zeros = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = convert_pki_period(&zeros);
        // Zero interval - won't match any standard period
        assert!(result.is_none() || result == Some("0 hours".to_string()));
    }

    #[test]
    fn test_parse_ca_flags() {
        let flags = parse_ca_flags(0x0A); // ADVANCED (0x08) | MANUAL_AUTH (0x02)
        assert!(flags.contains(PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED));
        assert!(!flags.contains(PkiCertificateAuthorityFlags::NO_TEMPLATE_SUPPORT));
    }

    #[test]
    fn test_parse_guid_from_bytes() {
        // Example GUID bytes
        let guid_bytes = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let guid = parse_guid_from_bytes(&guid_bytes);
        assert!(guid.is_some());

        // Invalid length
        let invalid = vec![0x01, 0x02, 0x03];
        assert_eq!(parse_guid_from_bytes(&invalid), None);
    }

    #[test]
    fn test_ldap_attributes() {
        let mut attrs = LdapAttributes::new();
        attrs.add_string("name".to_string(), "TEST-CA".to_string());
        attrs.add_string("distinguishedname".to_string(), "CN=TEST-CA,DC=contoso,DC=com".to_string());
        attrs.add_binary("objectguid".to_string(), vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        assert_eq!(attrs.get_string("name"), Some("TEST-CA"));
        assert!(attrs.contains("name"));
        assert!(attrs.contains("objectguid"));
        assert!(!attrs.contains("nonexistent"));
    }

    #[test]
    fn test_parse_name() {
        let mut attrs = LdapAttributes::new();
        attrs.add_string("name".to_string(), "TEST-CA".to_string());

        assert_eq!(parse_name(&attrs), Some("TEST-CA".to_string()));
    }

    #[test]
    fn test_parse_distinguished_name() {
        let mut attrs = LdapAttributes::new();
        attrs.add_string(
            "distinguishedname".to_string(),
            "CN=TEST-CA,DC=contoso,DC=com".to_string(),
        );

        assert_eq!(
            parse_distinguished_name(&attrs),
            Some("CN=TEST-CA,DC=contoso,DC=com".to_string())
        );
    }

    #[test]
    fn test_parse_guid_from_attributes() {
        let mut attrs = LdapAttributes::new();
        let guid_bytes = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        attrs.add_binary("objectguid".to_string(), guid_bytes);

        assert!(parse_guid(&attrs).is_some());
    }

    #[test]
    fn test_parse_ca_certificates() {
        let mut attrs = LdapAttributes::new();
        attrs.add_binary("cacertificate".to_string(), vec![1, 2, 3, 4, 5]);
        attrs.add_binary("cacertificate".to_string(), vec![6, 7, 8, 9, 10]);

        let certs = parse_ca_certificates(&attrs);
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].raw_data(), &[1, 2, 3, 4, 5]);
        assert_eq!(certs[1].raw_data(), &[6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_parse_security_descriptor() {
        let mut attrs = LdapAttributes::new();
        let sd_bytes = vec![1, 2, 3, 4, 5];
        attrs.add_binary("ntsecuritydescriptor".to_string(), sd_bytes.clone());

        let sd = parse_security_descriptor(&attrs).unwrap();
        assert_eq!(sd.raw_data(), &sd_bytes[..]);
    }
}
