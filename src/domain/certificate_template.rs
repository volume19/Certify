//! Certificate Template domain model with vulnerability detection
//!
//! This module implements the CertificateTemplate type which represents
//! Active Directory Certificate Templates and includes detection logic
//! for common AD CS privilege escalation techniques (ESC1-4, 9, 13, 15).

use super::ad_object::{ADObject, SecurityDescriptor};
use crate::domain::oids;
use std::collections::HashMap;
use std::fmt;

/// Certificate Name Flags
///
/// From: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
///
/// These flags control how the subject and subject alternative names are constructed
/// in certificates issued from this template.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MsPkiCertificateNameFlag: u32 {
        const NONE = 0x00000000;
        /// Enrollee can supply their own subject name
        const ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
        /// Add email to subject
        const ADD_EMAIL = 0x00000002;
        /// Add object GUID to subject alternative name
        const ADD_OBJ_GUID = 0x00000004;
        /// Old certificate supplies subject and alternative name
        const OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008;
        /// Add directory path
        const ADD_DIRECTORY_PATH = 0x00000100;
        /// Enrollee can supply subject alternative name
        const ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000;
        /// Require domain DNS in subject alternative name
        const SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000;
        /// Require SPN in subject alternative name
        const SUBJECT_ALT_REQUIRE_SPN = 0x00800000;
        /// Require directory GUID in subject alternative name
        const SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000;
        /// Require UPN in subject alternative name
        const SUBJECT_ALT_REQUIRE_UPN = 0x02000000;
        /// Require email in subject alternative name
        const SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000;
        /// Require DNS in subject alternative name
        const SUBJECT_ALT_REQUIRE_DNS = 0x08000000;
        /// Require DNS as common name
        const SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000;
        /// Require email in subject
        const SUBJECT_REQUIRE_EMAIL = 0x20000000;
        /// Require common name in subject
        const SUBJECT_REQUIRE_COMMON_NAME = 0x40000000;
        /// Require directory path in subject
        const SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000;
    }
}

/// Enrollment Flags
///
/// From: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
///
/// These flags control various enrollment behaviors for the certificate template.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MsPkiEnrollmentFlag: u32 {
        const NONE = 0x00000000;
        /// Include symmetric algorithms
        const INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001;
        /// Require manager approval for all requests
        const PEND_ALL_REQUESTS = 0x00000002;
        /// Publish to KRA container
        const PUBLISH_TO_KRA_CONTAINER = 0x00000004;
        /// Publish certificate to Active Directory
        const PUBLISH_TO_DS = 0x00000008;
        /// Auto-enrollment check user DS certificate
        const AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010;
        /// Enable auto-enrollment
        const AUTO_ENROLLMENT = 0x00000020;
        /// Previous approval validates re-enrollment
        const PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040;
        /// Domain authentication not required
        const DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x00000080;
        /// User interaction required
        const USER_INTERACTION_REQUIRED = 0x00000100;
        /// Add template name extension
        const ADD_TEMPLATE_NAME = 0x00000200;
        /// Remove invalid certificate from personal store
        const REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400;
        /// Allow enrollment on behalf of others
        const ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800;
        /// Add OCSP no-check extension
        const ADD_OCSP_NOCHECK = 0x00001000;
        /// Enable key reuse on NT token keyset storage full
        const ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000;
        /// No revocation information in issued certificates
        const NOREVOCATIONINFOINISSUEDCERTS = 0x00004000;
        /// Include basic constraints for end entity certificates
        const INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000;
        /// Allow previous approval key-based renewal validate re-enrollment
        const ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000;
        /// Issuance policies from request
        const ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000;
        /// Skip auto-renewal
        const SKIP_AUTO_RENEWAL = 0x00040000;
        /// Do not include security extension (szOID_NTDS_CA_SECURITY_EXT)
        const NO_SECURITY_EXTENSION = 0x00080000;
    }
}

/// Represents a Certificate Issuance Policy (OID) with optional group link
#[derive(Debug, Clone)]
pub struct CertificateEnterpriseOid {
    /// Base AD object
    base: ADObject,
    /// GUID of the OID object
    guid: uuid::Uuid,
    /// Name of the OID
    name: String,
    /// Display name
    display_name: String,
    /// The OID value as a string
    oid: String,
    /// Link to a domain group (for ESC13)
    group_link: Option<String>,
}

impl CertificateEnterpriseOid {
    /// Creates a new certificate enterprise OID
    pub fn new(
        base: ADObject,
        guid: uuid::Uuid,
        name: String,
        display_name: String,
        oid: String,
        group_link: Option<String>,
    ) -> Self {
        Self {
            base,
            guid,
            name,
            display_name,
            oid,
            group_link,
        }
    }

    /// Returns the GUID
    pub fn guid(&self) -> uuid::Uuid {
        self.guid
    }

    /// Returns the name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the display name
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the OID value
    pub fn oid(&self) -> &str {
        &self.oid
    }

    /// Returns the group link if present
    pub fn group_link(&self) -> Option<&str> {
        self.group_link.as_deref()
    }

    /// Returns a reference to the base AD object
    pub fn base(&self) -> &ADObject {
        &self.base
    }
}

/// Represents a Certificate Template in Active Directory
///
/// Certificate templates define the properties and settings for certificates
/// that can be issued by an Enterprise CA. This struct includes vulnerability
/// detection for common AD CS privilege escalation techniques.
#[derive(Debug, Clone)]
pub struct CertificateTemplate {
    /// Base AD object with DN and security descriptor
    base: ADObject,

    /// Friendly name of the template
    name: String,

    /// Domain name where the template resides
    domain_name: String,

    /// Unique identifier
    guid: uuid::Uuid,

    /// Template schema version (1-4)
    schema_version: i32,

    /// Display name
    display_name: String,

    /// Certificate validity period (human-readable, e.g., "1 year")
    validity_period: Option<String>,

    /// Certificate renewal/overlap period
    renewal_period: Option<String>,

    /// Template OID
    oid: Option<String>,

    /// Certificate name flags
    certificate_name_flag: MsPkiCertificateNameFlag,

    /// Enrollment flags
    enrollment_flag: MsPkiEnrollmentFlag,

    /// Extended Key Usage OIDs
    extended_key_usage: Vec<String>,

    /// Number of authorized signatures required
    authorized_signatures: i32,

    /// Registration Authority application policies
    ra_application_policies: Vec<String>,

    /// Registration Authority issuance policies
    ra_issuance_policies: Vec<String>,

    /// Application policies
    application_policies: Vec<String>,

    /// Issuance policies (with potential group links for ESC13)
    issuance_policies: Vec<CertificateEnterpriseOid>,

    /// Detected vulnerabilities (ESC number -> description)
    vulnerabilities: HashMap<u32, String>,
}

impl CertificateTemplate {
    /// Creates a new certificate template
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base: ADObject,
        name: String,
        domain_name: String,
        guid: uuid::Uuid,
        schema_version: i32,
        display_name: String,
        validity_period: Option<String>,
        renewal_period: Option<String>,
        oid: Option<String>,
        certificate_name_flag: MsPkiCertificateNameFlag,
        enrollment_flag: MsPkiEnrollmentFlag,
        extended_key_usage: Vec<String>,
        authorized_signatures: i32,
        ra_application_policies: Vec<String>,
        ra_issuance_policies: Vec<String>,
        application_policies: Vec<String>,
        issuance_policies: Vec<CertificateEnterpriseOid>,
        user_sids: Option<&[String]>,
    ) -> Self {
        let mut template = Self {
            base,
            name,
            domain_name,
            guid,
            schema_version,
            display_name,
            validity_period,
            renewal_period,
            oid,
            certificate_name_flag,
            enrollment_flag,
            extended_key_usage,
            authorized_signatures,
            ra_application_policies,
            ra_issuance_policies,
            application_policies,
            issuance_policies,
            vulnerabilities: HashMap::new(),
        };

        template.find_vulnerabilities(user_sids);
        template
    }

    /// Returns the template name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the domain name
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }

    /// Returns the GUID
    pub fn guid(&self) -> uuid::Uuid {
        self.guid
    }

    /// Returns the schema version
    pub fn schema_version(&self) -> i32 {
        self.schema_version
    }

    /// Returns the display name
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the certificate name flags
    pub fn certificate_name_flag(&self) -> MsPkiCertificateNameFlag {
        self.certificate_name_flag
    }

    /// Returns the enrollment flags
    pub fn enrollment_flag(&self) -> MsPkiEnrollmentFlag {
        self.enrollment_flag
    }

    /// Returns true if manager approval is required
    pub fn requires_manager_approval(&self) -> bool {
        self.enrollment_flag.contains(MsPkiEnrollmentFlag::PEND_ALL_REQUESTS)
    }

    /// Returns the number of authorized signatures required
    pub fn authorized_signatures(&self) -> i32 {
        self.authorized_signatures
    }

    /// Returns the extended key usage OIDs
    pub fn extended_key_usage(&self) -> &[String] {
        &self.extended_key_usage
    }

    /// Returns the vulnerabilities detected in this template
    pub fn vulnerabilities(&self) -> &HashMap<u32, String> {
        &self.vulnerabilities
    }

    /// Returns true if this template has any vulnerabilities
    pub fn is_vulnerable(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    /// Returns a reference to the base AD object
    pub fn base(&self) -> &ADObject {
        &self.base
    }

    /// Finds all vulnerabilities in this template
    ///
    /// # Arguments
    /// * `user_sids` - Optional list of SIDs to check for permissions (if None, checks for low-priv SIDs)
    fn find_vulnerabilities(&mut self, user_sids: Option<&[String]>) {
        let has_enroll_rights = self.check_vulnerable_esc4(user_sids);

        // Only check other vulnerabilities if manager approval is disabled
        // and no authorized signatures are required
        if !self.requires_manager_approval() && self.authorized_signatures == 0 {
            if has_enroll_rights {
                self.check_vulnerable_esc1();
                self.check_vulnerable_esc2();
                self.check_vulnerable_esc3();
                self.check_vulnerable_esc9();
                self.check_vulnerable_esc13();
                self.check_vulnerable_esc15();
            }
        }
    }

    /// ESC1: Template allows enrollee to supply subject and has authentication EKU
    ///
    /// If a template allows the enrollee to supply their own subject name and can be used
    /// for authentication, an attacker can request a certificate as any user.
    fn check_vulnerable_esc1(&mut self) {
        let auth_oids = [
            oids::CLIENT_AUTHENTICATION,
            oids::PKINIT_CLIENT_AUTHENTICATION,
            oids::SMARTCARD_LOGON,
            oids::ANY_PURPOSE,
        ];

        let has_auth_eku = self.extended_key_usage.is_empty()
            || self
                .extended_key_usage
                .iter()
                .any(|oid| auth_oids.contains(&oid.as_str()));

        if has_auth_eku
            && self
                .certificate_name_flag
                .contains(MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT)
        {
            self.vulnerabilities.insert(
                1,
                "The template has a client authentication EKU and allows enrollees to supply subject.".to_string(),
            );
        }
    }

    /// ESC2: Template has Any Purpose EKU or no EKU (Subordinate CA)
    ///
    /// Templates with the "Any Purpose" EKU or no EKU can be used for any purpose,
    /// including authentication.
    fn check_vulnerable_esc2(&mut self) {
        if !self
            .certificate_name_flag
            .contains(MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT)
        {
            if self.extended_key_usage.is_empty() {
                self.vulnerabilities.insert(
                    2,
                    "The template has no EKUs (Subordinate CA).".to_string(),
                );
            } else if self.extended_key_usage.contains(&oids::ANY_PURPOSE.to_string()) {
                self.vulnerabilities
                    .insert(2, "The template has the 'Any Purpose' EKU.".to_string());
            }
        }
    }

    /// ESC3: Template has Certificate Request Agent EKU
    ///
    /// The Certificate Request Agent EKU allows enrolling on behalf of other users.
    fn check_vulnerable_esc3(&mut self) {
        if self
            .extended_key_usage
            .contains(&oids::CERTIFICATE_REQUEST_AGENT.to_string())
        {
            // If template also has Any Purpose, it only works for schema v1
            if self.extended_key_usage.contains(&oids::ANY_PURPOSE.to_string()) {
                self.vulnerabilities.insert(
                    3,
                    "The template has the 'Certificate Request Agent' EKU, but only works for schema version 1 templates.".to_string(),
                );
            } else {
                self.vulnerabilities.insert(
                    3,
                    "The template has the 'Certificate Request Agent' EKU.".to_string(),
                );
            }
        }
    }

    /// ESC4: Template has vulnerable permissions
    ///
    /// Low-privileged users can modify the template or have dangerous rights.
    /// Returns true if the user has enroll rights.
    fn check_vulnerable_esc4(&mut self, _user_sids: Option<&[String]>) -> bool {
        // TODO: Implement full security descriptor parsing
        // For now, we'll assume enroll rights exist when checking for vulnerabilities
        // This will be fully implemented in a future phase when we have complete
        // LDAP and security descriptor support

        // This would check:
        // 1. Owner of the template
        // 2. GenericAll, WriteOwner, WriteDacl, WriteProperty rights
        // 3. Extended rights for enrollment

        // Return true to allow other vulnerability checks to run
        // In production, this would actually parse the security descriptor
        true
    }

    /// ESC9: Template has authentication EKU and no security extension
    ///
    /// Without the security extension (szOID_NTDS_CA_SECURITY_EXT), the CA cannot
    /// verify the requester's identity.
    fn check_vulnerable_esc9(&mut self) {
        let auth_oids = [
            oids::CLIENT_AUTHENTICATION,
            oids::PKINIT_CLIENT_AUTHENTICATION,
            oids::SMARTCARD_LOGON,
            oids::ANY_PURPOSE,
        ];

        let has_auth_eku = self.extended_key_usage.is_empty()
            || self
                .extended_key_usage
                .iter()
                .any(|oid| auth_oids.contains(&oid.as_str()));

        if has_auth_eku
            && self
                .enrollment_flag
                .contains(MsPkiEnrollmentFlag::NO_SECURITY_EXTENSION)
        {
            let subject_alt_flags = [
                MsPkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_UPN,
                MsPkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_SPN,
                MsPkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DNS,
            ];

            if subject_alt_flags
                .iter()
                .any(|&flag| self.certificate_name_flag.contains(flag))
            {
                self.vulnerabilities.insert(
                    9,
                    "The template has a client authentication EKU and no security extension.".to_string(),
                );
            } else {
                self.vulnerabilities.insert(
                    9,
                    "The template has a client authentication EKU and no security extension, but only works with ESC6.".to_string(),
                );
            }
        }
    }

    /// ESC13: Template has authentication EKU and issuance policy linked to group
    ///
    /// If an issuance policy is linked to a group, membership in that group might
    /// grant enrollment rights.
    fn check_vulnerable_esc13(&mut self) {
        let auth_oids = [
            oids::CLIENT_AUTHENTICATION,
            oids::PKINIT_CLIENT_AUTHENTICATION,
            oids::SMARTCARD_LOGON,
        ];

        let has_auth_eku = self
            .extended_key_usage
            .iter()
            .any(|oid| auth_oids.contains(&oid.as_str()));

        let has_group_linked_policy = self
            .issuance_policies
            .iter()
            .any(|policy| policy.group_link.is_some());

        if has_auth_eku && has_group_linked_policy {
            self.vulnerabilities.insert(
                13,
                "The template has client authentication and an issuance policy linked to one or more domain group(s).".to_string(),
            );
        }
    }

    /// ESC15: Schema version 1 with enrollee-supplied subject
    ///
    /// Schema version 1 templates don't properly validate subject requirements.
    fn check_vulnerable_esc15(&mut self) {
        if self.schema_version == 1
            && self
                .certificate_name_flag
                .contains(MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT)
        {
            self.vulnerabilities.insert(
                15,
                "The template has schema version 1 and allows enrollees to supply subject.".to_string(),
            );
        }
    }
}

impl fmt::Display for CertificateTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertificateTemplate {{ Name: {}, Domain: {}, Vulnerabilities: {} }}",
            self.name,
            self.domain_name,
            self.vulnerabilities.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_template(
        name: &str,
        cert_name_flags: MsPkiCertificateNameFlag,
        enrollment_flags: MsPkiEnrollmentFlag,
        ekus: Vec<String>,
        schema_version: i32,
    ) -> CertificateTemplate {
        CertificateTemplate::new(
            ADObject::new("CN=Test,DC=contoso,DC=com".to_string(), SecurityDescriptor::new()),
            name.to_string(),
            "contoso.com".to_string(),
            uuid::Uuid::new_v4(),
            schema_version,
            name.to_string(),
            Some("1 year".to_string()),
            Some("6 weeks".to_string()),
            Some("1.2.3.4.5".to_string()),
            cert_name_flags,
            enrollment_flags,
            ekus,
            0,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        )
    }

    #[test]
    fn test_esc1_vulnerability() {
        let template = create_test_template(
            "VulnerableTemplate",
            MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT,
            MsPkiEnrollmentFlag::NONE,
            vec![oids::CLIENT_AUTHENTICATION.to_string()],
            2,
        );

        assert!(template.is_vulnerable());
        assert!(template.vulnerabilities().contains_key(&1));
        assert!(template.vulnerabilities()[&1].contains("client authentication"));
    }

    #[test]
    fn test_esc2_any_purpose() {
        let template = create_test_template(
            "AnyPurposeTemplate",
            MsPkiCertificateNameFlag::NONE,
            MsPkiEnrollmentFlag::NONE,
            vec![oids::ANY_PURPOSE.to_string()],
            2,
        );

        assert!(template.is_vulnerable());
        assert!(template.vulnerabilities().contains_key(&2));
        assert!(template.vulnerabilities()[&2].contains("Any Purpose"));
    }

    #[test]
    fn test_esc2_no_eku() {
        let template = create_test_template(
            "SubCATemplate",
            MsPkiCertificateNameFlag::NONE,
            MsPkiEnrollmentFlag::NONE,
            Vec::new(), // No EKUs
            2,
        );

        assert!(template.is_vulnerable());
        assert!(template.vulnerabilities().contains_key(&2));
        assert!(template.vulnerabilities()[&2].contains("Subordinate CA"));
    }

    #[test]
    fn test_esc3_enrollment_agent() {
        let template = create_test_template(
            "EnrollmentAgentTemplate",
            MsPkiCertificateNameFlag::NONE,
            MsPkiEnrollmentFlag::NONE,
            vec![oids::CERTIFICATE_REQUEST_AGENT.to_string()],
            2,
        );

        assert!(template.is_vulnerable());
        assert!(template.vulnerabilities().contains_key(&3));
        assert!(template.vulnerabilities()[&3].contains("Certificate Request Agent"));
    }

    #[test]
    fn test_esc9_no_security_extension() {
        let template = create_test_template(
            "NoSecExtTemplate",
            MsPkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_UPN,
            MsPkiEnrollmentFlag::NO_SECURITY_EXTENSION,
            vec![oids::CLIENT_AUTHENTICATION.to_string()],
            2,
        );

        assert!(template.is_vulnerable());
        assert!(template.vulnerabilities().contains_key(&9));
        assert!(template.vulnerabilities()[&9].contains("no security extension"));
    }

    #[test]
    fn test_esc15_schema_v1() {
        let template = create_test_template(
            "SchemaV1Template",
            MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT,
            MsPkiEnrollmentFlag::NONE,
            vec![oids::CLIENT_AUTHENTICATION.to_string()],
            1, // Schema version 1
        );

        assert!(template.is_vulnerable());
        assert!(template.vulnerabilities().contains_key(&15));
        assert!(template.vulnerabilities()[&15].contains("schema version 1"));
    }

    #[test]
    fn test_manager_approval_blocks_vulns() {
        let template = create_test_template(
            "ManagerApprovalTemplate",
            MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT,
            MsPkiEnrollmentFlag::PEND_ALL_REQUESTS, // Requires manager approval
            vec![oids::CLIENT_AUTHENTICATION.to_string()],
            2,
        );

        // Should not be vulnerable because manager approval is required
        assert!(!template.is_vulnerable());
    }

    #[test]
    fn test_authorized_signatures_blocks_vulns() {
        let mut template = CertificateTemplate::new(
            ADObject::new("CN=Test,DC=contoso,DC=com".to_string(), SecurityDescriptor::new()),
            "AuthSigTemplate".to_string(),
            "contoso.com".to_string(),
            uuid::Uuid::new_v4(),
            2,
            "AuthSigTemplate".to_string(),
            None,
            None,
            None,
            MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT,
            MsPkiEnrollmentFlag::NONE,
            vec![oids::CLIENT_AUTHENTICATION.to_string()],
            1, // Requires 1 authorized signature
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        );

        // Should not be vulnerable because authorized signatures are required
        assert!(!template.is_vulnerable());
    }

    #[test]
    fn test_secure_template() {
        let template = create_test_template(
            "SecureTemplate",
            MsPkiCertificateNameFlag::SUBJECT_REQUIRE_COMMON_NAME,
            MsPkiEnrollmentFlag::NONE,
            vec!["1.3.6.1.5.5.7.3.8".to_string()], // Time Stamping EKU (non-auth)
            2,
        );

        assert!(!template.is_vulnerable());
        assert_eq!(template.vulnerabilities().len(), 0);
    }
}
