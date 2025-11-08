//! LDAP operations for querying Active Directory Certificate Services objects
//!
//! This module provides functions for connecting to LDAP and retrieving
//! PKI-related objects like Certificate Authorities and Certificate Templates.

use crate::certify_lib::ldap_parser::{self, LdapAttributes};
use crate::domain::{
    ADObject, CertificateAuthority, CertificateAuthorityEnterprise, CertificateTemplate,
    MsPkiCertificateNameFlag, MsPkiEnrollmentFlag, PKIObject, PkiCertificateAuthorityFlags,
    SecurityDescriptor,
};
use crate::error::{CertifyError, Result};
use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::HashMap;

/// LDAP connection configuration
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldap://dc.example.com:389")
    pub server_url: String,
    /// Base DN for searches (e.g., "DC=example,DC=com")
    pub base_dn: String,
    /// Optional username for authentication
    pub username: Option<String>,
    /// Optional password for authentication
    pub password: Option<String>,
}

impl LdapConfig {
    /// Create a new LDAP configuration
    pub fn new(server_url: String, base_dn: String) -> Self {
        Self {
            server_url,
            base_dn,
            username: None,
            password: None,
        }
    }

    /// Set credentials for authentication
    pub fn with_credentials(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }
}

/// Establishes an LDAP connection using the provided configuration
///
/// # Arguments
///
/// * `config` - LDAP connection configuration
///
/// # Returns
///
/// A connected LDAP connection or an error
///
/// # Example
///
/// ```no_run
/// use certify::certify_lib::ldap_operations::{LdapConfig, connect};
///
/// let config = LdapConfig::new(
///     "ldap://dc.example.com:389".to_string(),
///     "DC=example,DC=com".to_string()
/// );
/// let ldap = connect(&config)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn connect(config: &LdapConfig) -> Result<LdapConn> {
    let mut ldap = LdapConn::new(&config.server_url)
        .map_err(|e| CertifyError::Ldap(format!("Failed to connect to LDAP: {}", e)))?;

    // Authenticate if credentials provided
    if let (Some(username), Some(password)) = (&config.username, &config.password) {
        ldap.simple_bind(username, password)
            .map_err(|e| CertifyError::Ldap(format!("LDAP authentication failed: {}", e)))?;
    }

    Ok(ldap)
}

/// Retrieves all Enterprise Certificate Authorities from Active Directory
///
/// # Arguments
///
/// * `ldap` - Connected LDAP connection
/// * `base_dn` - Base distinguished name for search
///
/// # Returns
///
/// A vector of `CertificateAuthorityEnterprise` objects
///
/// # Example
///
/// ```no_run
/// use certify::certify_lib::ldap_operations::{LdapConfig, connect, get_enterprise_cas};
///
/// let config = LdapConfig::new(
///     "ldap://dc.example.com:389".to_string(),
///     "DC=example,DC=com".to_string()
/// );
/// let mut ldap = connect(&config)?;
/// let cas = get_enterprise_cas(&mut ldap, &config.base_dn)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn get_enterprise_cas(
    ldap: &mut LdapConn,
    base_dn: &str,
) -> Result<Vec<CertificateAuthorityEnterprise>> {
    // Search for PKI Enrollment Services (Enterprise CAs)
    let filter = "(objectClass=pKIEnrollmentService)";
    let attrs = vec![
        "distinguishedName",
        "name",
        "dNSHostName",
        "certificateTemplates",
        "cACertificate",
        "objectGUID",
        "flags",
        "nTSecurityDescriptor",
        "msPKI-Enrollment-Servers",
        "msPKI-Certificate-Authority-Flag",
    ];

    let (results, _) = ldap
        .search(base_dn, Scope::Subtree, filter, attrs)
        .map_err(|e| CertifyError::Ldap(format!("CA search failed: {}", e)))?
        .success()
        .map_err(|e| CertifyError::Ldap(format!("CA search error: {}", e)))?;

    let mut cas = Vec::new();

    for entry in results {
        let search_entry = SearchEntry::construct(entry);
        let ldap_attrs = parse_search_entry(search_entry)?;

        // Parse base CA
        let base_ca = parse_certificate_authority(&ldap_attrs)?;

        // Parse enterprise-specific fields
        let dns_hostname = ldap_attrs
            .get_string("dNSHostName")
            .unwrap_or("")
            .to_string();

        let templates = ldap_attrs
            .get_strings("certificateTemplates")
            .map(|v| v.to_vec())
            .unwrap_or_default();

        let ca_enterprise = CertificateAuthorityEnterprise::new(base_ca, dns_hostname, templates, None);

        cas.push(ca_enterprise);
    }

    Ok(cas)
}

/// Retrieves all Certificate Templates from Active Directory
///
/// # Arguments
///
/// * `ldap` - Connected LDAP connection
/// * `base_dn` - Base distinguished name for search
///
/// # Returns
///
/// A vector of `CertificateTemplate` objects with vulnerability detection
///
/// # Example
///
/// ```no_run
/// use certify::certify_lib::ldap_operations::{LdapConfig, connect, get_certificate_templates};
///
/// let config = LdapConfig::new(
///     "ldap://dc.example.com:389".to_string(),
///     "DC=example,DC=com".to_string()
/// );
/// let mut ldap = connect(&config)?;
/// let templates = get_certificate_templates(&mut ldap, &config.base_dn)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn get_certificate_templates(
    ldap: &mut LdapConn,
    base_dn: &str,
) -> Result<Vec<CertificateTemplate>> {
    // Search for PKI Certificate Templates
    let filter = "(objectClass=pKICertificateTemplate)";
    let attrs = vec![
        "distinguishedName",
        "name",
        "cn",
        "displayName",
        "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag",
        "pKIExtendedKeyUsage",
        "msPKI-RA-Signature",
        "msPKI-Template-Schema-Version",
        "msPKI-Cert-Template-OID",
        "pKIExpirationPeriod",
        "pKIOverlapPeriod",
        "nTSecurityDescriptor",
        "objectGUID",
    ];

    let (results, _) = ldap
        .search(base_dn, Scope::Subtree, filter, attrs)
        .map_err(|e| CertifyError::Ldap(format!("Template search failed: {}", e)))?
        .success()
        .map_err(|e| CertifyError::Ldap(format!("Template search error: {}", e)))?;

    let mut templates = Vec::new();

    for entry in results {
        let search_entry = SearchEntry::construct(entry);
        let ldap_attrs = parse_search_entry(search_entry)?;

        let template = parse_certificate_template(&ldap_attrs)?;
        templates.push(template);
    }

    Ok(templates)
}

/// Retrieves generic PKI objects from Active Directory
///
/// # Arguments
///
/// * `ldap` - Connected LDAP connection
/// * `base_dn` - Base distinguished name for search
/// * `object_class` - LDAP object class to search for
///
/// # Returns
///
/// A vector of `PKIObject` instances
///
/// # Example
///
/// ```no_run
/// use certify::certify_lib::ldap_operations::{LdapConfig, connect, get_pki_objects};
///
/// let config = LdapConfig::new(
///     "ldap://dc.example.com:389".to_string(),
///     "DC=example,DC=com".to_string()
/// );
/// let mut ldap = connect(&config)?;
/// let objects = get_pki_objects(&mut ldap, &config.base_dn, "certificationAuthority")?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn get_pki_objects(
    ldap: &mut LdapConn,
    base_dn: &str,
    object_class: &str,
) -> Result<Vec<PKIObject>> {
    let filter = format!("(objectClass={})", object_class);
    let attrs = vec!["distinguishedName", "name", "nTSecurityDescriptor"];

    let (results, _) = ldap
        .search(base_dn, Scope::Subtree, &filter, attrs)
        .map_err(|e| CertifyError::Ldap(format!("PKI object search failed: {}", e)))?
        .success()
        .map_err(|e| CertifyError::Ldap(format!("PKI object search error: {}", e)))?;

    let mut objects = Vec::new();

    for entry in results {
        let search_entry = SearchEntry::construct(entry);
        let ldap_attrs = parse_search_entry(search_entry)?;

        let object = parse_pki_object(&ldap_attrs)?;
        objects.push(object);
    }

    Ok(objects)
}

/// Converts an LDAP SearchEntry into our LdapAttributes container
fn parse_search_entry(entry: SearchEntry) -> Result<LdapAttributes> {
    let mut attrs = LdapAttributes::new();

    // Process each attribute
    for (key, values) in entry.attrs {
        // Try to parse as string first
        for value in &values {
            attrs.add_string(key.clone(), value.clone());
        }
    }

    // Process binary attributes separately
    for (key, values) in entry.bin_attrs {
        for value in values {
            attrs.add_binary(key.clone(), value);
        }
    }

    Ok(attrs)
}

/// Parses a CertificateAuthority from LDAP attributes
fn parse_certificate_authority(attrs: &LdapAttributes) -> Result<CertificateAuthority> {
    let dn = attrs
        .get_string("distinguishedName")
        .ok_or_else(|| CertifyError::Parse("Missing distinguishedName".to_string()))?
        .to_string();

    let name = attrs
        .get_string("name")
        .ok_or_else(|| CertifyError::Parse("Missing name".to_string()))?
        .to_string();

    let domain_name = ldap_parser::parse_domain_name_from_dn(&dn)
        .ok_or_else(|| CertifyError::Parse("Failed to parse domain from DN".to_string()))?;

    // Parse GUID
    let guid_bytes = attrs
        .get_binary("objectGUID")
        .ok_or_else(|| CertifyError::Parse("Missing objectGUID".to_string()))?;
    let guid = ldap_parser::parse_guid_from_bytes(guid_bytes)
        .ok_or_else(|| CertifyError::Parse("Failed to parse GUID".to_string()))?;

    // Parse flags
    let flags_value = attrs.get_integer("flags").unwrap_or(0);
    let flags =
        PkiCertificateAuthorityFlags::from_bits_truncate(flags_value as u32);

    // Parse security descriptor
    let security_descriptor_bytes = attrs.get_binary("nTSecurityDescriptor").unwrap_or(&[]);
    let security_descriptor = SecurityDescriptor::from_bytes(security_descriptor_bytes.to_vec());

    // Parse certificates (CA certificates are in DER format)
    let certificates = Vec::new(); // TODO: Parse certificates from cACertificate attribute

    Ok(CertificateAuthority::from_components(
        dn,
        name,
        domain_name,
        guid,
        flags,
        certificates,
        security_descriptor,
    ))
}

/// Parses a CertificateTemplate from LDAP attributes
fn parse_certificate_template(attrs: &LdapAttributes) -> Result<CertificateTemplate> {
    let dn = attrs
        .get_string("distinguishedName")
        .ok_or_else(|| CertifyError::Parse("Missing distinguishedName".to_string()))?
        .to_string();

    let name = attrs
        .get_string("name")
        .ok_or_else(|| CertifyError::Parse("Missing name".to_string()))?
        .to_string();

    let domain_name = ldap_parser::parse_domain_name_from_dn(&dn)
        .ok_or_else(|| CertifyError::Parse("Failed to parse domain from DN".to_string()))?;

    // Parse GUID
    let guid_bytes = attrs
        .get_binary("objectGUID")
        .ok_or_else(|| CertifyError::Parse("Missing objectGUID".to_string()))?;
    let guid = ldap_parser::parse_guid_from_bytes(guid_bytes)
        .ok_or_else(|| CertifyError::Parse("Failed to parse GUID".to_string()))?;

    // Parse schema version
    let schema_version = attrs
        .get_integer("msPKI-Template-Schema-Version")
        .unwrap_or(1);

    // Parse display name
    let display_name = attrs
        .get_string("displayName")
        .unwrap_or(&name)
        .to_string();

    // Parse validity and renewal periods
    let validity_period = attrs
        .get_binary("pKIExpirationPeriod")
        .and_then(|b| ldap_parser::convert_pki_period(b));
    let renewal_period = attrs
        .get_binary("pKIOverlapPeriod")
        .and_then(|b| ldap_parser::convert_pki_period(b));

    // Parse OID
    let oid = attrs
        .get_string("msPKI-Cert-Template-OID")
        .map(|s| s.to_string());

    // Parse flags
    let cert_name_flag = MsPkiCertificateNameFlag::from_bits_truncate(
        attrs
            .get_integer("msPKI-Certificate-Name-Flag")
            .unwrap_or(0) as u32,
    );
    let enrollment_flag = MsPkiEnrollmentFlag::from_bits_truncate(
        attrs.get_integer("msPKI-Enrollment-Flag").unwrap_or(0) as u32,
    );

    // Parse EKUs
    let ekus = attrs
        .get_strings("pKIExtendedKeyUsage")
        .map(|v| v.to_vec())
        .unwrap_or_default();

    // Parse authorized signatures
    let authorized_signatures = attrs.get_integer("msPKI-RA-Signature").unwrap_or(0);

    // Parse RA policies (not commonly populated, use empty vecs)
    let ra_application_policies = Vec::new();
    let ra_issuance_policies = Vec::new();
    let application_policies = Vec::new();
    let issuance_policies = Vec::new();

    // Create base AD object
    let security_descriptor_bytes = attrs.get_binary("nTSecurityDescriptor").unwrap_or(&[]);
    let security_descriptor = SecurityDescriptor::from_bytes(security_descriptor_bytes.to_vec());
    let base = ADObject::new(dn, security_descriptor);

    Ok(CertificateTemplate::new(
        base,
        name,
        domain_name,
        guid,
        schema_version,
        display_name,
        validity_period,
        renewal_period,
        oid,
        cert_name_flag,
        enrollment_flag,
        ekus,
        authorized_signatures,
        ra_application_policies,
        ra_issuance_policies,
        application_policies,
        issuance_policies,
        None, // user_sids - will be provided by caller if needed
    ))
}

/// Parses a generic PKIObject from LDAP attributes
fn parse_pki_object(attrs: &LdapAttributes) -> Result<PKIObject> {
    let dn = attrs
        .get_string("distinguishedName")
        .ok_or_else(|| CertifyError::Parse("Missing distinguishedName".to_string()))?
        .to_string();

    let name = attrs
        .get_string("name")
        .ok_or_else(|| CertifyError::Parse("Missing name".to_string()))?
        .to_string();

    let domain_name = ldap_parser::parse_domain_name_from_dn(&dn)
        .ok_or_else(|| CertifyError::Parse("Failed to parse domain from DN".to_string()))?;

    // Parse security descriptor
    let security_descriptor_bytes = attrs.get_binary("nTSecurityDescriptor").unwrap_or(&[]);
    let security_descriptor = SecurityDescriptor::from_bytes(security_descriptor_bytes.to_vec());

    // Create base AD object and then PKI object
    let base = ADObject::new(dn, security_descriptor);
    Ok(PKIObject::new(base, name, domain_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_creation() {
        let config = LdapConfig::new(
            "ldap://dc.example.com:389".to_string(),
            "DC=example,DC=com".to_string(),
        );

        assert_eq!(config.server_url, "ldap://dc.example.com:389");
        assert_eq!(config.base_dn, "DC=example,DC=com");
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_ldap_config_with_credentials() {
        let config = LdapConfig::new(
            "ldap://dc.example.com:389".to_string(),
            "DC=example,DC=com".to_string(),
        )
        .with_credentials("user@example.com".to_string(), "password".to_string());

        assert_eq!(config.username, Some("user@example.com".to_string()));
        assert_eq!(config.password, Some("password".to_string()));
    }

    #[test]
    fn test_parse_search_entry() {
        let mut entry = SearchEntry {
            dn: "CN=TestCA,CN=Configuration,DC=example,DC=com".to_string(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::new(),
        };

        entry
            .attrs
            .insert("name".to_string(), vec!["TestCA".to_string()]);
        entry.attrs.insert(
            "distinguishedName".to_string(),
            vec!["CN=TestCA,CN=Configuration,DC=example,DC=com".to_string()],
        );

        let attrs = parse_search_entry(entry).unwrap();

        assert_eq!(attrs.get_string("name"), Some("TestCA"));
        assert_eq!(
            attrs.get_string("distinguishedName"),
            Some("CN=TestCA,CN=Configuration,DC=example,DC=com")
        );
    }
}
