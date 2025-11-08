//! Certificate Authority domain models
//!
//! This module provides types for representing Certificate Authorities (CAs)
//! in Active Directory Certificate Services.

use super::ad_object::{ADObject, SecurityDescriptor};
use std::fmt;

/// Certificate Authority access rights
///
/// Corresponds to the CertificationAuthorityRights enum from the C# implementation.
/// These flags define the permissions that can be granted on a CA.
///
/// From: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/509360cf-9797-491e-9dd1-795f63cb1538
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CertificationAuthorityRights {
    /// Administrator - Can manage the CA configuration
    ManageCA = 1,
    /// Officer - Can manage certificates (issue, revoke)
    ManageCertificates = 2,
    /// Auditor - Can manage audit settings
    Auditor = 4,
    /// Operator - Can perform backup and restore operations
    Operator = 8,
    /// Read - Can read CA configuration
    Read = 256,
    /// Enroll - Can enroll for certificates
    Enroll = 512,
}

impl CertificationAuthorityRights {
    /// Returns the numeric value of the right
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the name of the right
    pub fn name(self) -> &'static str {
        match self {
            CertificationAuthorityRights::ManageCA => "ManageCA",
            CertificationAuthorityRights::ManageCertificates => "ManageCertificates",
            CertificationAuthorityRights::Auditor => "Auditor",
            CertificationAuthorityRights::Operator => "Operator",
            CertificationAuthorityRights::Read => "Read",
            CertificationAuthorityRights::Enroll => "Enroll",
        }
    }

    /// Checks if a rights value contains this right
    pub fn is_set_in(self, rights: u32) -> bool {
        (rights & self.value()) != 0
    }

    /// Returns all defined CA rights
    pub fn all() -> &'static [CertificationAuthorityRights] {
        &[
            CertificationAuthorityRights::ManageCA,
            CertificationAuthorityRights::ManageCertificates,
            CertificationAuthorityRights::Auditor,
            CertificationAuthorityRights::Operator,
            CertificationAuthorityRights::Read,
            CertificationAuthorityRights::Enroll,
        ]
    }
}

impl fmt::Display for CertificationAuthorityRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// PKI Certificate Authority capability flags
///
/// From certca.h in the Windows SDK. These flags indicate the capabilities
/// and authentication methods supported by a Certificate Authority.
bitflags::bitflags! {
    /// CA capability flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PkiCertificateAuthorityFlags: u32 {
        /// CA does not support certificate templates
        const NO_TEMPLATE_SUPPORT = 0x00000001;
        /// CA supports Windows NT authentication
        const SUPPORTS_NT_AUTHENTICATION = 0x00000002;
        /// CA supports manual authentication
        const CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004;
        /// CA is an Advanced/Enterprise CA
        const CA_SERVERTYPE_ADVANCED = 0x00000008;
    }
}

impl fmt::Display for PkiCertificateAuthorityFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.contains(Self::NO_TEMPLATE_SUPPORT) {
            flags.push("NO_TEMPLATE_SUPPORT");
        }
        if self.contains(Self::SUPPORTS_NT_AUTHENTICATION) {
            flags.push("SUPPORTS_NT_AUTHENTICATION");
        }
        if self.contains(Self::CA_SUPPORTS_MANUAL_AUTHENTICATION) {
            flags.push("CA_SUPPORTS_MANUAL_AUTHENTICATION");
        }
        if self.contains(Self::CA_SERVERTYPE_ADVANCED) {
            flags.push("CA_SERVERTYPE_ADVANCED");
        }

        if flags.is_empty() {
            write!(f, "(none)")
        } else {
            write!(f, "{}", flags.join(" | "))
        }
    }
}

/// Placeholder for X.509 certificate data
///
/// This is a simplified representation for now. In future iterations,
/// this will be replaced with proper X.509 certificate parsing using
/// the x509-cert crate.
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// Raw DER-encoded certificate data
    raw_data: Vec<u8>,
    /// Certificate thumbprint (SHA-1 hash) as hex string
    thumbprint: Option<String>,
}

impl X509Certificate {
    /// Creates a new certificate from raw DER data
    pub fn from_der(data: Vec<u8>) -> Self {
        Self {
            raw_data: data,
            thumbprint: None,
        }
    }

    /// Creates a new certificate with a thumbprint
    pub fn with_thumbprint(data: Vec<u8>, thumbprint: String) -> Self {
        Self {
            raw_data: data,
            thumbprint: Some(thumbprint),
        }
    }

    /// Returns a reference to the raw DER data
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    /// Returns the certificate thumbprint if available
    pub fn thumbprint(&self) -> Option<&str> {
        self.thumbprint.as_deref()
    }
}

/// Represents a Certificate Authority
///
/// This corresponds to the C# CertificateAuthority class. In C#, it inherits
/// from ADObject and implements IDisposable. In Rust, we use composition for
/// the ADObject and implement the Drop trait for cleanup.
///
/// # Examples
/// ```
/// use certify::domain::certificate_authority::{CertificateAuthority, PkiCertificateAuthorityFlags};
/// use certify::domain::ad_object::{ADObject, SecurityDescriptor};
/// use uuid::Uuid;
///
/// let ad_obj = ADObject::new(
///     "CN=TEST-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com".to_string(),
///     SecurityDescriptor::new(),
/// );
///
/// let ca = CertificateAuthority::new(
///     ad_obj,
///     "TEST-CA".to_string(),
///     "contoso.com".to_string(),
///     Uuid::new_v4(),
///     PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED | PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION,
///     Vec::new(),
/// );
///
/// assert_eq!(ca.name(), "TEST-CA");
/// assert_eq!(ca.domain_name(), "contoso.com");
/// ```
#[derive(Debug, Clone)]
pub struct CertificateAuthority {
    /// Base AD object with DN and security descriptor
    base: ADObject,

    /// Friendly name of the CA
    name: String,

    /// Domain name where the CA resides
    domain_name: String,

    /// Unique identifier for the CA
    guid: uuid::Uuid,

    /// CA capability flags
    flags: PkiCertificateAuthorityFlags,

    /// CA certificates (chain)
    certificates: Vec<X509Certificate>,
}

impl CertificateAuthority {
    /// Creates a new Certificate Authority
    ///
    /// # Arguments
    /// * `base` - The base ADObject with DN and security descriptor
    /// * `name` - Friendly name of the CA
    /// * `domain_name` - Domain name
    /// * `guid` - Unique identifier
    /// * `flags` - CA capability flags
    /// * `certificates` - List of CA certificates
    pub fn new(
        base: ADObject,
        name: String,
        domain_name: String,
        guid: uuid::Uuid,
        flags: PkiCertificateAuthorityFlags,
        certificates: Vec<X509Certificate>,
    ) -> Self {
        Self {
            base,
            name,
            domain_name,
            guid,
            flags,
            certificates,
        }
    }

    /// Creates a new CA from individual components
    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        distinguished_name: String,
        name: String,
        domain_name: String,
        guid: uuid::Uuid,
        flags: PkiCertificateAuthorityFlags,
        certificates: Vec<X509Certificate>,
        security_descriptor: SecurityDescriptor,
    ) -> Self {
        let base = ADObject::new(distinguished_name, security_descriptor);
        Self::new(base, name, domain_name, guid, flags, certificates)
    }

    /// Returns a reference to the base AD object
    pub fn base(&self) -> &ADObject {
        &self.base
    }

    /// Returns a mutable reference to the base AD object
    pub fn base_mut(&mut self) -> &mut ADObject {
        &mut self.base
    }

    /// Returns the CA name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the domain name
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }

    /// Returns the CA GUID
    pub fn guid(&self) -> uuid::Uuid {
        self.guid
    }

    /// Returns the CA capability flags
    pub fn flags(&self) -> PkiCertificateAuthorityFlags {
        self.flags
    }

    /// Returns a slice of the CA certificates
    pub fn certificates(&self) -> &[X509Certificate] {
        &self.certificates
    }

    /// Returns the distinguished name from the base object
    pub fn distinguished_name(&self) -> &str {
        self.base.distinguished_name()
    }

    /// Returns a reference to the security descriptor
    pub fn security_descriptor(&self) -> &SecurityDescriptor {
        self.base.security_descriptor()
    }

    /// Checks if the CA supports certificate templates
    pub fn supports_templates(&self) -> bool {
        !self.flags.contains(PkiCertificateAuthorityFlags::NO_TEMPLATE_SUPPORT)
    }

    /// Checks if the CA is an Enterprise CA
    pub fn is_enterprise_ca(&self) -> bool {
        self.flags.contains(PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED)
    }

    /// Checks if the CA supports NT authentication
    pub fn supports_nt_authentication(&self) -> bool {
        self.flags.contains(PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION)
    }

    /// Checks if the CA supports manual authentication
    pub fn supports_manual_authentication(&self) -> bool {
        self.flags.contains(PkiCertificateAuthorityFlags::CA_SUPPORTS_MANUAL_AUTHENTICATION)
    }

    /// Returns the number of certificates in the chain
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }
}

impl fmt::Display for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CA {{ Name: {}, Domain: {}, DN: {}, Flags: {} }}",
            self.name,
            self.domain_name,
            self.base.distinguished_name(),
            self.flags
        )
    }
}

// Implement Drop trait for automatic cleanup (equivalent to IDisposable)
// In this case, the certificates are automatically dropped when the CA is dropped
// because Rust's ownership system handles cleanup. We implement Drop to be
// explicit about the cleanup behavior and match the C# implementation.
impl Drop for CertificateAuthority {
    fn drop(&mut self) {
        // Explicitly clear certificates
        // In Rust, this is not strictly necessary as the Vec will be dropped anyway,
        // but we do it to match the C# behavior and be explicit about cleanup
        self.certificates.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_rights_values() {
        assert_eq!(CertificationAuthorityRights::ManageCA.value(), 1);
        assert_eq!(CertificationAuthorityRights::ManageCertificates.value(), 2);
        assert_eq!(CertificationAuthorityRights::Auditor.value(), 4);
        assert_eq!(CertificationAuthorityRights::Operator.value(), 8);
        assert_eq!(CertificationAuthorityRights::Read.value(), 256);
        assert_eq!(CertificationAuthorityRights::Enroll.value(), 512);
    }

    #[test]
    fn test_ca_rights_is_set_in() {
        let rights = 1 | 2 | 256; // ManageCA | ManageCertificates | Read

        assert!(CertificationAuthorityRights::ManageCA.is_set_in(rights));
        assert!(CertificationAuthorityRights::ManageCertificates.is_set_in(rights));
        assert!(!CertificationAuthorityRights::Auditor.is_set_in(rights));
        assert!(!CertificationAuthorityRights::Operator.is_set_in(rights));
        assert!(CertificationAuthorityRights::Read.is_set_in(rights));
        assert!(!CertificationAuthorityRights::Enroll.is_set_in(rights));
    }

    #[test]
    fn test_ca_rights_display() {
        assert_eq!(CertificationAuthorityRights::ManageCA.to_string(), "ManageCA");
        assert_eq!(CertificationAuthorityRights::Enroll.to_string(), "Enroll");
    }

    #[test]
    fn test_ca_flags() {
        let flags = PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED
            | PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION;

        assert!(flags.contains(PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED));
        assert!(flags.contains(PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION));
        assert!(!flags.contains(PkiCertificateAuthorityFlags::NO_TEMPLATE_SUPPORT));
    }

    #[test]
    fn test_ca_flags_display() {
        let flags = PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED;
        let display = flags.to_string();
        assert!(display.contains("CA_SERVERTYPE_ADVANCED"));
    }

    #[test]
    fn test_x509_certificate() {
        let cert_data = vec![1, 2, 3, 4, 5];
        let cert = X509Certificate::from_der(cert_data.clone());
        assert_eq!(cert.raw_data(), &cert_data[..]);
        assert_eq!(cert.thumbprint(), None);

        let cert_with_thumbprint = X509Certificate::with_thumbprint(
            cert_data.clone(),
            "ABCD1234".to_string(),
        );
        assert_eq!(cert_with_thumbprint.thumbprint(), Some("ABCD1234"));
    }

    #[test]
    fn test_certificate_authority_creation() {
        let dn = "CN=TEST-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com".to_string();
        let ad_obj = ADObject::new(dn.clone(), SecurityDescriptor::new());
        let guid = uuid::Uuid::new_v4();
        let flags = PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED;

        let ca = CertificateAuthority::new(
            ad_obj,
            "TEST-CA".to_string(),
            "contoso.com".to_string(),
            guid,
            flags,
            Vec::new(),
        );

        assert_eq!(ca.name(), "TEST-CA");
        assert_eq!(ca.domain_name(), "contoso.com");
        assert_eq!(ca.guid(), guid);
        assert_eq!(ca.flags(), flags);
        assert_eq!(ca.certificate_count(), 0);
        assert_eq!(ca.distinguished_name(), dn);
    }

    #[test]
    fn test_certificate_authority_from_components() {
        let dn = "CN=TEST-CA,DC=contoso,DC=com".to_string();
        let guid = uuid::Uuid::new_v4();
        let flags = PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION;

        let ca = CertificateAuthority::from_components(
            dn.clone(),
            "TEST-CA".to_string(),
            "contoso.com".to_string(),
            guid,
            flags,
            Vec::new(),
            SecurityDescriptor::new(),
        );

        assert_eq!(ca.name(), "TEST-CA");
        assert_eq!(ca.distinguished_name(), dn);
    }

    #[test]
    fn test_ca_capability_checks() {
        let flags = PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED
            | PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION;

        let ca = CertificateAuthority::from_components(
            "CN=TEST-CA,DC=contoso,DC=com".to_string(),
            "TEST-CA".to_string(),
            "contoso.com".to_string(),
            uuid::Uuid::new_v4(),
            flags,
            Vec::new(),
            SecurityDescriptor::new(),
        );

        assert!(ca.supports_templates());
        assert!(ca.is_enterprise_ca());
        assert!(ca.supports_nt_authentication());
        assert!(!ca.supports_manual_authentication());
    }

    #[test]
    fn test_ca_with_certificates() {
        let cert1 = X509Certificate::from_der(vec![1, 2, 3]);
        let cert2 = X509Certificate::from_der(vec![4, 5, 6]);

        let ca = CertificateAuthority::from_components(
            "CN=TEST-CA,DC=contoso,DC=com".to_string(),
            "TEST-CA".to_string(),
            "contoso.com".to_string(),
            uuid::Uuid::new_v4(),
            PkiCertificateAuthorityFlags::empty(),
            vec![cert1, cert2],
            SecurityDescriptor::new(),
        );

        assert_eq!(ca.certificate_count(), 2);
        assert_eq!(ca.certificates()[0].raw_data(), &[1, 2, 3]);
        assert_eq!(ca.certificates()[1].raw_data(), &[4, 5, 6]);
    }

    #[test]
    fn test_ca_display() {
        let ca = CertificateAuthority::from_components(
            "CN=TEST-CA,DC=contoso,DC=com".to_string(),
            "TEST-CA".to_string(),
            "contoso.com".to_string(),
            uuid::Uuid::new_v4(),
            PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED,
            Vec::new(),
            SecurityDescriptor::new(),
        );

        let display = format!("{}", ca);
        assert!(display.contains("TEST-CA"));
        assert!(display.contains("contoso.com"));
    }

    #[test]
    fn test_ca_drop() {
        // Test that Drop is called correctly
        // Create a CA with certificates and let it go out of scope
        {
            let ca = CertificateAuthority::from_components(
                "CN=TEST-CA,DC=contoso,DC=com".to_string(),
                "TEST-CA".to_string(),
                "contoso.com".to_string(),
                uuid::Uuid::new_v4(),
                PkiCertificateAuthorityFlags::empty(),
                vec![X509Certificate::from_der(vec![1, 2, 3])],
                SecurityDescriptor::new(),
            );
            assert_eq!(ca.certificate_count(), 1);
        }
        // CA is dropped here, certificates should be cleaned up
    }

    #[test]
    fn test_ca_clone() {
        let ca = CertificateAuthority::from_components(
            "CN=TEST-CA,DC=contoso,DC=com".to_string(),
            "TEST-CA".to_string(),
            "contoso.com".to_string(),
            uuid::Uuid::new_v4(),
            PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED,
            vec![X509Certificate::from_der(vec![1, 2, 3])],
            SecurityDescriptor::new(),
        );

        let cloned = ca.clone();
        assert_eq!(cloned.name(), ca.name());
        assert_eq!(cloned.certificate_count(), ca.certificate_count());
    }
}
