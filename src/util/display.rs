//! Display utilities for formatting PKI object output
//!
//! This module provides functions for formatting and displaying Certificate Authorities,
//! Certificate Templates, and their associated properties in a human-readable format.

use crate::domain::{
    CertificateAuthority, CertificateAuthorityEnterprise, CertificateTemplate,
    MsPkiCertificateNameFlag, MsPkiEnrollmentFlag, PKIObject, PKIObjectACE,
    PkiCertificateAuthorityFlags,
};
use std::fmt::Write as FmtWrite;

/// Format a Certificate Authority for display
///
/// # Arguments
///
/// * `ca` - The Certificate Authority to display
///
/// # Returns
///
/// A formatted string representation of the CA
///
/// # Example
///
/// ```
/// use certify::domain::{CertificateAuthority, SecurityDescriptor, ADObject, PkiCertificateAuthorityFlags};
/// use certify::util::display::format_certificate_authority;
/// use uuid::Uuid;
///
/// let ad_obj = ADObject::new(
///     "CN=TestCA,CN=Configuration,DC=example,DC=com".to_string(),
///     SecurityDescriptor::new(),
/// );
/// let ca = CertificateAuthority::new(
///     ad_obj,
///     "TestCA".to_string(),
///     "example.com".to_string(),
///     Uuid::new_v4(),
///     PkiCertificateAuthorityFlags::empty(),
///     Vec::new(),
/// );
/// let output = format_certificate_authority(&ca);
/// assert!(output.contains("TestCA"));
/// ```
pub fn format_certificate_authority(ca: &CertificateAuthority) -> String {
    let mut output = String::new();

    writeln!(output, "\nCertificate Authority Information:").unwrap();
    writeln!(output, "  Name: {}", ca.name()).unwrap();
    writeln!(output, "  Domain: {}", ca.domain_name()).unwrap();
    writeln!(
        output,
        "  Distinguished Name: {}",
        ca.base().distinguished_name()
    )
    .unwrap();
    writeln!(output, "  GUID: {}", ca.guid()).unwrap();

    // Display flags
    let flags = ca.flags();
    writeln!(output, "  Flags: {}", format_ca_flags(flags)).unwrap();

    // Display capabilities
    writeln!(output, "  Capabilities:").unwrap();
    if ca.supports_templates() {
        writeln!(output, "    - Supports Certificate Templates").unwrap();
    }
    if ca.supports_nt_authentication() {
        writeln!(output, "    - Supports NT Authentication").unwrap();
    }
    if ca.supports_manual_authentication() {
        writeln!(output, "    - Supports Manual Authentication").unwrap();
    }
    if ca.is_enterprise_ca() {
        writeln!(output, "    - Enterprise CA (Advanced)").unwrap();
    }

    // Display certificates
    if !ca.certificates().is_empty() {
        writeln!(output, "  Certificates: {} certificate(s)", ca.certificates().len()).unwrap();
    }

    output
}

/// Format an Enterprise Certificate Authority for display
///
/// # Arguments
///
/// * `ca_enterprise` - The Enterprise CA to display
///
/// # Returns
///
/// A formatted string representation of the Enterprise CA
pub fn format_enterprise_ca(ca_enterprise: &CertificateAuthorityEnterprise) -> String {
    let mut output = String::new();

    writeln!(output, "\n=== Enterprise Certificate Authority ===").unwrap();

    // Display base CA information
    output.push_str(&format_certificate_authority(ca_enterprise.base_ca()));

    // Display enterprise-specific information
    writeln!(output, "\nEnterprise Configuration:").unwrap();
    writeln!(output, "  DNS Hostname: {}", ca_enterprise.dns_hostname()).unwrap();

    // Display templates
    let templates = ca_enterprise.templates();
    if !templates.is_empty() {
        writeln!(output, "\n  Available Templates ({}):", templates.len()).unwrap();
        for template in templates {
            writeln!(output, "    - {}", template).unwrap();
        }
    } else {
        writeln!(output, "  No templates available").unwrap();
    }

    // Display vulnerabilities
    if ca_enterprise.is_vulnerable() {
        writeln!(output, "\n  [!] VULNERABILITIES DETECTED:").unwrap();
        for (esc_num, description) in ca_enterprise.vulnerabilities() {
            writeln!(output, "    [ESC{}] {}", esc_num, description).unwrap();
        }
    } else {
        writeln!(output, "\n  [+] No vulnerabilities detected").unwrap();
    }

    output
}

/// Format a Certificate Template for display
///
/// # Arguments
///
/// * `template` - The Certificate Template to display
///
/// # Returns
///
/// A formatted string representation of the template
///
/// # Example
///
/// ```
/// use certify::domain::{CertificateTemplate, SecurityDescriptor, ADObject, MsPkiCertificateNameFlag, MsPkiEnrollmentFlag};
/// use certify::util::display::format_certificate_template;
/// use uuid::Uuid;
///
/// let ad_obj = ADObject::new(
///     "CN=User,CN=Templates,DC=example,DC=com".to_string(),
///     SecurityDescriptor::new(),
/// );
/// let template = CertificateTemplate::new(
///     ad_obj,
///     "User".to_string(),
///     "example.com".to_string(),
///     Uuid::new_v4(),
///     2,
///     "User Authentication".to_string(),
///     Some("1 year".to_string()),
///     Some("6 weeks".to_string()),
///     None,
///     MsPkiCertificateNameFlag::empty(),
///     MsPkiEnrollmentFlag::empty(),
///     vec!["1.3.6.1.5.5.7.3.2".to_string()],
///     0,
///     Vec::new(),
///     Vec::new(),
///     Vec::new(),
///     Vec::new(),
///     None,
/// );
/// let output = format_certificate_template(&template);
/// assert!(output.contains("User"));
/// ```
pub fn format_certificate_template(template: &CertificateTemplate) -> String {
    let mut output = String::new();

    writeln!(output, "\n=== Certificate Template ===").unwrap();
    writeln!(output, "  Name: {}", template.name()).unwrap();
    writeln!(output, "  Display Name: {}", template.display_name()).unwrap();
    writeln!(output, "  Domain: {}", template.domain_name()).unwrap();
    writeln!(
        output,
        "  Distinguished Name: {}",
        template.base().distinguished_name()
    )
    .unwrap();
    writeln!(output, "  GUID: {}", template.guid()).unwrap();
    writeln!(output, "  Schema Version: {}", template.schema_version()).unwrap();

    // Display validity periods
    if let Some(validity) = template.validity_period() {
        writeln!(output, "  Validity Period: {}", validity).unwrap();
    }
    if let Some(renewal) = template.renewal_period() {
        writeln!(output, "  Renewal Period: {}", renewal).unwrap();
    }

    // Display flags
    writeln!(
        output,
        "\n  Certificate Name Flags: {}",
        format_certificate_name_flags(template.certificate_name_flag())
    )
    .unwrap();
    writeln!(
        output,
        "  Enrollment Flags: {}",
        format_enrollment_flags(template.enrollment_flag())
    )
    .unwrap();

    // Display EKUs
    let ekus = template.extended_key_usage();
    if !ekus.is_empty() {
        writeln!(output, "\n  Extended Key Usages ({}):", ekus.len()).unwrap();
        for eku in ekus {
            let eku_name = get_eku_name(eku);
            writeln!(output, "    - {} ({})", eku_name, eku).unwrap();
        }
    } else {
        writeln!(output, "\n  Extended Key Usages: None (Any Purpose)").unwrap();
    }

    // Display authorized signatures requirement
    if template.authorized_signatures() > 0 {
        writeln!(
            output,
            "\n  Authorized Signatures Required: {}",
            template.authorized_signatures()
        )
        .unwrap();
    }

    // Display vulnerabilities
    if template.is_vulnerable() {
        writeln!(output, "\n  [!] VULNERABILITIES DETECTED:").unwrap();
        for (esc_num, description) in template.vulnerabilities() {
            writeln!(output, "    [ESC{}] {}", esc_num, description).unwrap();
        }
    } else {
        writeln!(output, "\n  [+] No vulnerabilities detected").unwrap();
    }

    output
}

/// Format PKI Certificate Authority flags for display
fn format_ca_flags(flags: PkiCertificateAuthorityFlags) -> String {
    if flags.is_empty() {
        return "None".to_string();
    }

    let mut flag_names = Vec::new();

    if flags.contains(PkiCertificateAuthorityFlags::NO_TEMPLATE_SUPPORT) {
        flag_names.push("NO_TEMPLATE_SUPPORT");
    }
    if flags.contains(PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION) {
        flag_names.push("SUPPORTS_NT_AUTHENTICATION");
    }
    if flags.contains(PkiCertificateAuthorityFlags::CA_SUPPORTS_MANUAL_AUTHENTICATION) {
        flag_names.push("CA_SUPPORTS_MANUAL_AUTHENTICATION");
    }
    if flags.contains(PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED) {
        flag_names.push("CA_SERVERTYPE_ADVANCED");
    }

    format!("0x{:08x} ({})", flags.bits(), flag_names.join(", "))
}

/// Format Certificate Name Flags for display
fn format_certificate_name_flags(flags: MsPkiCertificateNameFlag) -> String {
    if flags.is_empty() {
        return "0x00000000 (None)".to_string();
    }

    let mut flag_names = Vec::new();

    if flags.contains(MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT) {
        flag_names.push("ENROLLEE_SUPPLIES_SUBJECT");
    }
    if flags.contains(MsPkiCertificateNameFlag::ADD_EMAIL) {
        flag_names.push("ADD_EMAIL");
    }
    if flags.contains(MsPkiCertificateNameFlag::ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME) {
        flag_names.push("ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME");
    }
    if flags.contains(MsPkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_UPN) {
        flag_names.push("SUBJECT_ALT_REQUIRE_UPN");
    }
    if flags.contains(MsPkiCertificateNameFlag::SUBJECT_ALT_REQUIRE_DNS) {
        flag_names.push("SUBJECT_ALT_REQUIRE_DNS");
    }

    // Truncate if too many flags
    if flag_names.len() > 5 {
        flag_names.truncate(5);
        flag_names.push("...");
    }

    format!("0x{:08x} ({})", flags.bits(), flag_names.join(", "))
}

/// Format Enrollment Flags for display
fn format_enrollment_flags(flags: MsPkiEnrollmentFlag) -> String {
    if flags.is_empty() {
        return "0x00000000 (None)".to_string();
    }

    let mut flag_names = Vec::new();

    if flags.contains(MsPkiEnrollmentFlag::PEND_ALL_REQUESTS) {
        flag_names.push("PEND_ALL_REQUESTS (Manager Approval)");
    }
    if flags.contains(MsPkiEnrollmentFlag::AUTO_ENROLLMENT) {
        flag_names.push("AUTO_ENROLLMENT");
    }
    if flags.contains(MsPkiEnrollmentFlag::DOMAIN_AUTHENTICATION_NOT_REQUIRED) {
        flag_names.push("DOMAIN_AUTHENTICATION_NOT_REQUIRED");
    }
    if flags.contains(MsPkiEnrollmentFlag::NO_SECURITY_EXTENSION) {
        flag_names.push("NO_SECURITY_EXTENSION");
    }
    if flags.contains(MsPkiEnrollmentFlag::USER_INTERACTION_REQUIRED) {
        flag_names.push("USER_INTERACTION_REQUIRED");
    }

    // Truncate if too many flags
    if flag_names.len() > 5 {
        flag_names.truncate(5);
        flag_names.push("...");
    }

    format!("0x{:08x} ({})", flags.bits(), flag_names.join(", "))
}

/// Get a friendly name for an EKU OID
fn get_eku_name(oid: &str) -> &str {
    match oid {
        "1.3.6.1.5.5.7.3.1" => "Server Authentication",
        "1.3.6.1.5.5.7.3.2" => "Client Authentication",
        "1.3.6.1.5.5.7.3.3" => "Code Signing",
        "1.3.6.1.5.5.7.3.4" => "Email Protection",
        "1.3.6.1.5.5.7.3.8" => "Time Stamping",
        "1.3.6.1.5.2.3.4" => "PKINIT Client Authentication",
        "1.3.6.1.4.1.311.20.2.2" => "Smartcard Logon",
        "1.3.6.1.4.1.311.20.2.1" => "Certificate Request Agent",
        "2.5.29.37.0" => "Any Purpose",
        _ => "Unknown EKU",
    }
}

/// Format a list of templates for summary display
///
/// # Arguments
///
/// * `templates` - Collection of Certificate Templates to display
///
/// # Returns
///
/// A formatted string with summary information
pub fn format_template_summary(templates: &[CertificateTemplate]) -> String {
    let mut output = String::new();

    writeln!(output, "\n=== Certificate Templates Summary ===").unwrap();
    writeln!(output, "Total Templates: {}\n", templates.len()).unwrap();

    // Count vulnerable templates
    let vulnerable_count = templates.iter().filter(|t| t.is_vulnerable()).count();

    if vulnerable_count > 0 {
        writeln!(output, "[!] Vulnerable Templates: {}", vulnerable_count).unwrap();
        writeln!(output, "\nVulnerable Templates:").unwrap();

        for template in templates.iter().filter(|t| t.is_vulnerable()) {
            writeln!(output, "\n  Template: {}", template.name()).unwrap();
            writeln!(output, "    Display Name: {}", template.display_name()).unwrap();

            for (esc_num, description) in template.vulnerabilities() {
                writeln!(output, "    [ESC{}] {}", esc_num, description).unwrap();
            }
        }
    } else {
        writeln!(output, "[+] No vulnerable templates found").unwrap();
    }

    output
}

/// Format a list of Enterprise CAs for summary display
///
/// # Arguments
///
/// * `cas` - Collection of Enterprise CAs to display
///
/// # Returns
///
/// A formatted string with summary information
pub fn format_ca_summary(cas: &[CertificateAuthorityEnterprise]) -> String {
    let mut output = String::new();

    writeln!(output, "\n=== Certificate Authorities Summary ===").unwrap();
    writeln!(output, "Total CAs: {}\n", cas.len()).unwrap();

    // Count vulnerable CAs
    let vulnerable_count = cas.iter().filter(|ca| ca.is_vulnerable()).count();

    if vulnerable_count > 0 {
        writeln!(output, "[!] Vulnerable CAs: {}", vulnerable_count).unwrap();
        writeln!(output, "\nVulnerable CAs:").unwrap();

        for ca in cas.iter().filter(|ca| ca.is_vulnerable()) {
            writeln!(output, "\n  CA: {}", ca.base_ca().name()).unwrap();
            writeln!(output, "    DNS Hostname: {}", ca.dns_hostname()).unwrap();

            for (esc_num, description) in ca.vulnerabilities() {
                writeln!(output, "    [ESC{}] {}", esc_num, description).unwrap();
            }
        }
    } else {
        writeln!(output, "[+] No vulnerable CAs found").unwrap();
    }

    output
}

/// Format ACE information for display
///
/// # Arguments
///
/// * `aces` - Collection of PKI Object ACEs to display
///
/// # Returns
///
/// A formatted string with ACL information
pub fn format_aces(aces: &[PKIObjectACE]) -> String {
    let mut output = String::new();

    if aces.is_empty() {
        writeln!(output, "  No ACEs available").unwrap();
        return output;
    }

    writeln!(output, "  Access Control Entries ({}):", aces.len()).unwrap();
    for (i, ace) in aces.iter().enumerate() {
        writeln!(
            output,
            "    [{}] {} - {} for {}",
            i + 1,
            ace.access_type(),
            ace.rights(),
            ace.principal()
        )
        .unwrap();

        if let Some(guid) = ace.object_type() {
            writeln!(output, "        Object Type: {}", guid).unwrap();
        }
    }

    output
}

/// Format a PKI object for display
///
/// # Arguments
///
/// * `obj` - The PKI object to display
///
/// # Returns
///
/// A formatted string representation
pub fn format_pki_object(obj: &PKIObject) -> String {
    let mut output = String::new();

    writeln!(output, "\n=== PKI Object ===").unwrap();
    writeln!(output, "  Name: {}", obj.name()).unwrap();
    writeln!(output, "  Domain: {}", obj.domain_name()).unwrap();
    writeln!(
        output,
        "  Distinguished Name: {}",
        obj.base().distinguished_name()
    )
    .unwrap();

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ADObject, SecurityDescriptor};
    use uuid::Uuid;

    #[test]
    fn test_format_ca_flags_empty() {
        let flags = PkiCertificateAuthorityFlags::empty();
        let formatted = format_ca_flags(flags);
        assert_eq!(formatted, "None");
    }

    #[test]
    fn test_format_ca_flags_multiple() {
        let flags = PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION
            | PkiCertificateAuthorityFlags::CA_SERVERTYPE_ADVANCED;
        let formatted = format_ca_flags(flags);
        assert!(formatted.contains("SUPPORTS_NT_AUTHENTICATION"));
        assert!(formatted.contains("CA_SERVERTYPE_ADVANCED"));
    }

    #[test]
    fn test_format_certificate_name_flags_empty() {
        let flags = MsPkiCertificateNameFlag::empty();
        let formatted = format_certificate_name_flags(flags);
        assert!(formatted.contains("0x00000000"));
        assert!(formatted.contains("None"));
    }

    #[test]
    fn test_format_enrollment_flags_manager_approval() {
        let flags = MsPkiEnrollmentFlag::PEND_ALL_REQUESTS;
        let formatted = format_enrollment_flags(flags);
        assert!(formatted.contains("PEND_ALL_REQUESTS"));
        assert!(formatted.contains("Manager Approval"));
    }

    #[test]
    fn test_get_eku_name() {
        assert_eq!(
            get_eku_name("1.3.6.1.5.5.7.3.2"),
            "Client Authentication"
        );
        assert_eq!(
            get_eku_name("1.3.6.1.4.1.311.20.2.2"),
            "Smartcard Logon"
        );
        assert_eq!(get_eku_name("9.9.9.9.9"), "Unknown EKU");
    }

    #[test]
    fn test_format_certificate_authority() {
        let ad_obj = ADObject::new(
            "CN=TestCA,CN=Configuration,DC=example,DC=com".to_string(),
            SecurityDescriptor::new(),
        );
        let ca = CertificateAuthority::new(
            ad_obj,
            "TestCA".to_string(),
            "example.com".to_string(),
            Uuid::new_v4(),
            PkiCertificateAuthorityFlags::SUPPORTS_NT_AUTHENTICATION,
            Vec::new(),
        );

        let output = format_certificate_authority(&ca);
        assert!(output.contains("TestCA"));
        assert!(output.contains("example.com"));
        assert!(output.contains("Supports NT Authentication"));
    }

    #[test]
    fn test_format_template_summary() {
        let templates = Vec::new();
        let output = format_template_summary(&templates);
        assert!(output.contains("Total Templates: 0"));
        assert!(output.contains("No vulnerable templates found"));
    }

    #[test]
    fn test_format_ca_summary() {
        let cas = Vec::new();
        let output = format_ca_summary(&cas);
        assert!(output.contains("Total CAs: 0"));
        assert!(output.contains("No vulnerable CAs found"));
    }

    #[test]
    fn test_format_aces_empty() {
        let aces = Vec::new();
        let output = format_aces(&aces);
        assert!(output.contains("No ACEs available"));
    }
}
