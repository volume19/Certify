//! Common OID (Object Identifier) constants
//!
//! This module contains OID constants used throughout the PKI system.
//! OIDs are standardized identifiers for cryptographic algorithms,
//! certificate extensions, and key usage purposes.
//!
//! These constants match the C# `CommonOids` class from the original implementation.

/// Any-purpose OID - no specific usage restrictions
pub const ANY_PURPOSE: &str = "2.5.29.37.0";

/// Client authentication OID - used for SSL/TLS client certificates
pub const CLIENT_AUTHENTICATION: &str = "1.3.6.1.5.5.7.3.2";

/// PKINIT client authentication OID - used for Kerberos PKINIT
pub const PKINIT_CLIENT_AUTHENTICATION: &str = "1.3.6.1.5.2.3.4";

/// Smart card logon OID - used for Windows smart card authentication
pub const SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";

/// Certificate request agent OID - used for enrollment agent certificates
pub const CERTIFICATE_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";

/// User Principal Name OID (szOID_NT_PRINCIPAL_NAME)
/// Used in certificate Subject Alternative Name for UPN
pub const USER_PRINCIPAL_NAME: &str = "1.3.6.1.4.1.311.20.2.3";

/// NTDS CA security extension OID (szOID_NTDS_CA_SECURITY_EXT)
/// Used for Active Directory CA security extensions
pub const NTDS_CA_SECURITY_EXT: &str = "1.3.6.1.4.1.311.25.2";

/// Application policies extension OID
/// Container for certificate application policies
pub const APPLICATION_POLICIES: &str = "1.3.6.1.4.1.311.21.10";

/// Certificate policies extension OID
/// Standard X.509 certificate policies extension
pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_constants_match_csharp() {
        // Verify OID values match the C# implementation exactly
        assert_eq!(ANY_PURPOSE, "2.5.29.37.0");
        assert_eq!(CLIENT_AUTHENTICATION, "1.3.6.1.5.5.7.3.2");
        assert_eq!(PKINIT_CLIENT_AUTHENTICATION, "1.3.6.1.5.2.3.4");
        assert_eq!(SMARTCARD_LOGON, "1.3.6.1.4.1.311.20.2.2");
        assert_eq!(CERTIFICATE_REQUEST_AGENT, "1.3.6.1.4.1.311.20.2.1");
        assert_eq!(USER_PRINCIPAL_NAME, "1.3.6.1.4.1.311.20.2.3");
        assert_eq!(NTDS_CA_SECURITY_EXT, "1.3.6.1.4.1.311.25.2");
        assert_eq!(APPLICATION_POLICIES, "1.3.6.1.4.1.311.21.10");
        assert_eq!(CERTIFICATE_POLICIES, "2.5.29.32");
    }

    #[test]
    fn test_oid_format_validity() {
        // Verify all OIDs follow the correct format (digits and dots)
        let oids = [
            ANY_PURPOSE,
            CLIENT_AUTHENTICATION,
            PKINIT_CLIENT_AUTHENTICATION,
            SMARTCARD_LOGON,
            CERTIFICATE_REQUEST_AGENT,
            USER_PRINCIPAL_NAME,
            NTDS_CA_SECURITY_EXT,
            APPLICATION_POLICIES,
            CERTIFICATE_POLICIES,
        ];

        for oid in &oids {
            // OIDs must contain only digits and dots
            assert!(
                oid.chars().all(|c| c.is_ascii_digit() || c == '.'),
                "Invalid OID format: {}",
                oid
            );
            // OIDs must start with a digit
            assert!(
                oid.chars().next().unwrap().is_ascii_digit(),
                "OID must start with digit: {}",
                oid
            );
            // OIDs must not be empty
            assert!(!oid.is_empty(), "OID cannot be empty");
        }
    }

    #[test]
    fn test_microsoft_vendor_oids() {
        // Microsoft vendor OIDs start with 1.3.6.1.4.1.311
        let microsoft_oids = [
            SMARTCARD_LOGON,
            CERTIFICATE_REQUEST_AGENT,
            USER_PRINCIPAL_NAME,
            NTDS_CA_SECURITY_EXT,
            APPLICATION_POLICIES,
        ];

        for oid in &microsoft_oids {
            assert!(
                oid.starts_with("1.3.6.1.4.1.311"),
                "Expected Microsoft vendor OID prefix, got: {}",
                oid
            );
        }
    }
}
