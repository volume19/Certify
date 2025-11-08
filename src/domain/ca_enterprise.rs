//! Enterprise Certificate Authority domain model with advanced vulnerability detection
//!
//! This module implements the CertificateAuthorityEnterprise type which extends
//! CertificateAuthority with additional properties and vulnerability detection
//! for ESC6-8, 11, and 16.

use super::certificate_authority::{CertificateAuthority, PkiCertificateAuthorityFlags};
use super::ad_object::{ADObject, SecurityDescriptor};
use super::X509Certificate;
use crate::domain::oids;
use std::collections::HashMap;
use std::fmt;

/// Edit flags for CA policy module configuration
///
/// These flags control what attributes can be modified during certificate enrollment.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct EditFlags: u32 {
        /// Allow editing Extended Key Usage
        const ATTRIBUTE_EKU = 0x00008000;
        /// Allow editing Subject Alternative Name 2
        const ATTRIBUTE_SUBJECTALTNAME2 = 0x00040000;
    }
}

/// Interface flags for CA RPC interface restrictions
///
/// These flags control access to various CA interfaces and protocols.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct InterfaceFlags: u32 {
        /// No remote ICertRequest access
        const NO_REMOTE_ICERTREQUEST = 0x00000002;
        /// No local ICertRequest access
        const NO_LOCAL_ICERTREQUEST = 0x00000004;
        /// No RPC ICertRequest access
        const NO_RPC_ICERTREQUEST = 0x00000008;
        /// No remote ICertAdmin access
        const NO_REMOTE_ICERTADMIN = 0x00000010;
        /// No local ICertAdmin access
        const NO_LOCAL_ICERTADMIN = 0x00000020;
        /// No remote ICertAdmin backup access
        const NO_REMOTE_ICERTADMIN_BACKUP = 0x00000040;
        /// No local ICertAdmin backup access
        const NO_LOCAL_ICERTADMIN_BACKUP = 0x00000080;
        /// No snapshot backup
        const NO_SNAPSHOT_BACKUP = 0x00000100;
        /// Enforce encryption on ICertRequest
        const ENFORCE_ENCRYPT_ICERTREQUEST = 0x00000200;
        /// Enforce encryption on ICertAdmin
        const ENFORCE_ENCRYPT_ICERTADMIN = 0x00000400;
    }
}

/// Represents an Enterprise Certificate Authority
///
/// This extends the base CertificateAuthority with enterprise-specific properties
/// and includes vulnerability detection for ESC6-8, 11, and 16.
///
/// # Examples
/// ```
/// use certify::domain::{CertificateAuthorityEnterprise, CertificateAuthority};
/// use certify::domain::{ADObject, SecurityDescriptor, PkiCertificateAuthorityFlags};
/// use uuid::Uuid;
///
/// let base_ca = CertificateAuthority::new(
///     ADObject::new("CN=CA,DC=contoso,DC=com".to_string(), SecurityDescriptor::new()),
///     "TestCA".to_string(),
///     "contoso.com".to_string(),
///     Uuid::new_v4(),
///     PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED,
///     Vec::new(),
/// );
///
/// let enterprise_ca = CertificateAuthorityEnterprise::new(
///     base_ca,
///     "ca.contoso.com".to_string(),
///     vec!["WebServer".to_string(), "User".to_string()],
///     None,
/// );
///
/// assert_eq!(enterprise_ca.dns_hostname(), "ca.contoso.com");
/// assert_eq!(enterprise_ca.templates().len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct CertificateAuthorityEnterprise {
    /// Base CA object
    base_ca: CertificateAuthority,

    /// DNS hostname of the CA server
    dns_hostname: String,

    /// List of published certificate templates
    templates: Vec<String>,

    /// Whether user-specified SAN is enabled (ESC6)
    user_specified_san: Option<bool>,

    /// Whether RPC request encryption is enforced (ESC11)
    rpc_request_encryption: Option<bool>,

    /// List of disabled certificate extensions
    disabled_extensions: Vec<String>,

    /// Detected vulnerabilities (ESC number -> description)
    vulnerabilities: HashMap<u32, String>,
}

impl CertificateAuthorityEnterprise {
    /// Creates a new Enterprise Certificate Authority
    ///
    /// # Arguments
    /// * `base_ca` - The base CertificateAuthority object
    /// * `dns_hostname` - DNS hostname of the CA server
    /// * `templates` - List of published certificate templates
    /// * `user_sids` - Optional list of SIDs to check for permissions
    pub fn new(
        base_ca: CertificateAuthority,
        dns_hostname: String,
        templates: Vec<String>,
        user_sids: Option<&[String]>,
    ) -> Self {
        let mut ca = Self {
            base_ca,
            dns_hostname,
            templates,
            user_specified_san: None,
            rpc_request_encryption: None,
            disabled_extensions: Vec::new(),
            vulnerabilities: HashMap::new(),
        };

        // Attempt to read CA configuration (Windows-only)
        #[cfg(target_os = "windows")]
        {
            ca.load_ca_configuration();
        }

        ca.find_vulnerabilities(user_sids);
        ca
    }

    /// Returns the base CA object
    pub fn base_ca(&self) -> &CertificateAuthority {
        &self.base_ca
    }

    /// Returns the DNS hostname
    pub fn dns_hostname(&self) -> &str {
        &self.dns_hostname
    }

    /// Returns the full CA name (hostname\name)
    pub fn full_name(&self) -> String {
        format!("{}\\{}", self.dns_hostname, self.base_ca.name())
    }

    /// Returns the list of published templates
    pub fn templates(&self) -> &[String] {
        &self.templates
    }

    /// Returns the detected vulnerabilities
    pub fn vulnerabilities(&self) -> &HashMap<u32, String> {
        &self.vulnerabilities
    }

    /// Returns true if this CA has any vulnerabilities
    pub fn is_vulnerable(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    /// Returns whether user-specified SAN is enabled (if known)
    pub fn user_specified_san(&self) -> Option<bool> {
        self.user_specified_san
    }

    /// Returns whether RPC encryption is enforced (if known)
    pub fn rpc_request_encryption(&self) -> Option<bool> {
        self.rpc_request_encryption
    }

    /// Returns the list of disabled extensions
    pub fn disabled_extensions(&self) -> &[String] {
        &self.disabled_extensions
    }

    /// Loads CA configuration from Windows registry (Windows-only)
    #[cfg(target_os = "windows")]
    fn load_ca_configuration(&mut self) {
        // TODO: Implement registry reading using windows-rs crate
        // This would read from:
        // - HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{Name}\PolicyModules\...\EditFlags
        // - HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{Name}\InterfaceFlags
        // - HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{Name}\PolicyModules\...\DisableExtensionList

        // For now, leave as None to indicate we couldn't read the configuration
    }

    /// Finds all vulnerabilities in this CA
    fn find_vulnerabilities(&mut self, user_sids: Option<&[String]>) {
        self.check_vulnerable_esc6();
        self.check_vulnerable_esc7(user_sids);
        self.check_vulnerable_esc8();
        self.check_vulnerable_esc11();
        self.check_vulnerable_esc16();
    }

    /// ESC6: CA allows enrollees to specify Subject Alternative Names
    ///
    /// If the EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set, users can specify
    /// arbitrary SANs in their certificate requests.
    fn check_vulnerable_esc6(&mut self) {
        if let Some(true) = self.user_specified_san {
            self.vulnerabilities.insert(
                6,
                "The CA allows enrollees to specify SANs.".to_string(),
            );
        }
    }

    /// ESC7: CA has vulnerable permissions
    ///
    /// Low-privileged users have ManageCA or ManageCertificates rights.
    fn check_vulnerable_esc7(&mut self, _user_sids: Option<&[String]>) {
        // TODO: Implement full security descriptor parsing
        // This would check:
        // 1. Owner of the CA (from registry security descriptor)
        // 2. ManageCA rights for low-priv users
        // 3. ManageCertificates rights for low-priv users

        // For now, we can't determine this without registry access and
        // full security descriptor parsing
    }

    /// ESC8: CA supports HTTP(S) enrollment without channel binding
    ///
    /// Web enrollment endpoints without proper channel binding are vulnerable
    /// to NTLM relay attacks.
    fn check_vulnerable_esc8(&mut self) {
        // TODO: Implement HTTP/HTTPS probing
        // This would:
        // 1. Try http://{hostname}/certsrv/
        // 2. Try https://{hostname}/certsrv/
        // 3. Check if authentication works with and without channel binding

        // For now, we'll skip this check as it requires network access
        // and NTLM authentication support
    }

    /// ESC11: CA does not enforce RPC encryption
    ///
    /// If ENFORCE_ENCRYPT_ICERTREQUEST is not set, the ICertPassage RPC
    /// interface doesn't require encryption.
    fn check_vulnerable_esc11(&mut self) {
        if let Some(false) = self.rpc_request_encryption {
            self.vulnerabilities.insert(
                11,
                "The CA does not enforce encryption on the ICertPassage RPC interface.".to_string(),
            );
        }
    }

    /// ESC16: CA has disabled the security extension
    ///
    /// If the szOID_NTDS_CA_SECURITY_EXT extension is disabled, the CA
    /// cannot properly verify the requester's identity.
    fn check_vulnerable_esc16(&mut self) {
        if self.disabled_extensions.contains(&oids::NTDS_CA_SECURITY_EXT.to_string()) {
            self.vulnerabilities.insert(
                16,
                "The CA has disabled the security extension.".to_string(),
            );
        }
    }

    /// Sets user-specified SAN configuration (for testing or manual configuration)
    pub fn set_user_specified_san(&mut self, enabled: bool) {
        self.user_specified_san = Some(enabled);
    }

    /// Sets RPC encryption configuration (for testing or manual configuration)
    pub fn set_rpc_request_encryption(&mut self, enforced: bool) {
        self.rpc_request_encryption = Some(enforced);
    }

    /// Adds a disabled extension (for testing or manual configuration)
    pub fn add_disabled_extension(&mut self, oid: String) {
        if !self.disabled_extensions.contains(&oid) {
            self.disabled_extensions.push(oid);
        }
    }
}

impl fmt::Display for CertificateAuthorityEnterprise {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnterpriseCA {{ Name: {}, Hostname: {}, Templates: {}, Vulnerabilities: {} }}",
            self.base_ca.name(),
            self.dns_hostname,
            self.templates.len(),
            self.vulnerabilities.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ca(name: &str, hostname: &str) -> CertificateAuthorityEnterprise {
        let base_ca = CertificateAuthority::new(
            ADObject::new(
                format!("CN={},CN=Enrollment Services,DC=contoso,DC=com", name),
                SecurityDescriptor::new(),
            ),
            name.to_string(),
            "contoso.com".to_string(),
            uuid::Uuid::new_v4(),
            PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED,
            Vec::new(),
        );

        CertificateAuthorityEnterprise::new(
            base_ca,
            hostname.to_string(),
            vec!["User".to_string(), "WebServer".to_string()],
            None,
        )
    }

    #[test]
    fn test_enterprise_ca_creation() {
        let ca = create_test_ca("TestCA", "ca.contoso.com");

        assert_eq!(ca.dns_hostname(), "ca.contoso.com");
        assert_eq!(ca.full_name(), "ca.contoso.com\\TestCA");
        assert_eq!(ca.templates().len(), 2);
        assert_eq!(ca.templates()[0], "User");
        assert_eq!(ca.templates()[1], "WebServer");
    }

    #[test]
    fn test_esc6_user_specified_san() {
        let mut ca = create_test_ca("VulnerableCA", "ca.contoso.com");

        // Initially no vulnerability
        assert!(!ca.is_vulnerable());

        // Enable user-specified SAN and re-check
        ca.set_user_specified_san(true);
        ca.find_vulnerabilities(None);

        assert!(ca.is_vulnerable());
        assert!(ca.vulnerabilities().contains_key(&6));
        assert!(ca.vulnerabilities()[&6].contains("SANs"));
    }

    #[test]
    fn test_esc11_no_rpc_encryption() {
        let mut ca = create_test_ca("VulnerableCA", "ca.contoso.com");

        // Set RPC encryption to disabled
        ca.set_rpc_request_encryption(false);
        ca.find_vulnerabilities(None);

        assert!(ca.is_vulnerable());
        assert!(ca.vulnerabilities().contains_key(&11));
        assert!(ca.vulnerabilities()[&11].contains("encryption"));
    }

    #[test]
    fn test_esc16_disabled_security_extension() {
        let mut ca = create_test_ca("VulnerableCA", "ca.contoso.com");

        // Add the security extension to disabled list
        ca.add_disabled_extension(oids::NTDS_CA_SECURITY_EXT.to_string());
        ca.find_vulnerabilities(None);

        assert!(ca.is_vulnerable());
        assert!(ca.vulnerabilities().contains_key(&16));
        assert!(ca.vulnerabilities()[&16].contains("security extension"));
    }

    #[test]
    fn test_secure_enterprise_ca() {
        let ca = create_test_ca("SecureCA", "ca.contoso.com");

        // With no configuration issues, should not be vulnerable
        assert!(!ca.is_vulnerable());
        assert_eq!(ca.vulnerabilities().len(), 0);
    }

    #[test]
    fn test_multiple_vulnerabilities() {
        let mut ca = create_test_ca("VulnerableCA", "ca.contoso.com");

        // Enable multiple vulnerabilities
        ca.set_user_specified_san(true);
        ca.set_rpc_request_encryption(false);
        ca.add_disabled_extension(oids::NTDS_CA_SECURITY_EXT.to_string());
        ca.find_vulnerabilities(None);

        assert!(ca.is_vulnerable());
        assert_eq!(ca.vulnerabilities().len(), 3);
        assert!(ca.vulnerabilities().contains_key(&6));
        assert!(ca.vulnerabilities().contains_key(&11));
        assert!(ca.vulnerabilities().contains_key(&16));
    }

    #[test]
    fn test_display() {
        let ca = create_test_ca("TestCA", "ca.contoso.com");
        let display = format!("{}", ca);

        assert!(display.contains("EnterpriseCA"));
        assert!(display.contains("TestCA"));
        assert!(display.contains("ca.contoso.com"));
        assert!(display.contains("Templates: 2"));
    }
}
