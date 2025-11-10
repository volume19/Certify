//! Enumerate generic PKI objects from Active Directory
//!
//! This command retrieves and displays generic PKI objects from the AD PKI container.

use crate::certify_lib::ldap_operations::{self, LdapConfig};
use crate::error::Result;

/// Configuration for EnumPkiObjects command
#[derive(Debug, Clone)]
pub struct EnumPkiObjectsConfig {
    /// LDAP server to connect to (None = domain default)
    pub ldap_server: Option<String>,
    /// Base DN for search (None = auto-detect)
    pub base_dn: Option<String>,
    /// LDAP username for authentication (None = current user)
    pub username: Option<String>,
    /// LDAP password for authentication
    pub password: Option<String>,
    /// Object class to enumerate (e.g., "pKICertificateTemplate", "pKIEnrollmentService")
    pub object_class: String,
}

impl EnumPkiObjectsConfig {
    /// Create a new configuration for enumerating PKI objects
    ///
    /// # Arguments
    ///
    /// * `object_class` - The object class to enumerate
    ///
    /// # Example
    ///
    /// ```
    /// use certify::commands::enum_pki_objects::EnumPkiObjectsConfig;
    ///
    /// let config = EnumPkiObjectsConfig::new("pKICertificateTemplate");
    /// assert_eq!(config.object_class, "pKICertificateTemplate");
    /// ```
    pub fn new(object_class: impl Into<String>) -> Self {
        Self {
            ldap_server: None,
            base_dn: None,
            username: None,
            password: None,
            object_class: object_class.into(),
        }
    }

    /// Set the LDAP server
    pub fn with_ldap_server(mut self, server: impl Into<String>) -> Self {
        self.ldap_server = Some(server.into());
        self
    }

    /// Set the base DN
    pub fn with_base_dn(mut self, base_dn: impl Into<String>) -> Self {
        self.base_dn = Some(base_dn.into());
        self
    }

    /// Set authentication credentials
    pub fn with_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }
}

/// Execute the EnumPkiObjects command
///
/// Enumerates generic PKI objects from Active Directory and formats them for display.
///
/// # Arguments
///
/// * `config` - Command configuration
///
/// # Returns
///
/// Formatted output string with enumerated objects
///
/// # Example
///
/// ```no_run
/// use certify::commands::enum_pki_objects::{EnumPkiObjectsConfig, execute};
///
/// let config = EnumPkiObjectsConfig::new("pKICertificateTemplate");
/// // let output = execute(&config)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn execute(config: &EnumPkiObjectsConfig) -> Result<String> {
    // Determine base DN - required for this command
    let base_dn = config.base_dn.as_ref().ok_or_else(|| {
        crate::error::CertifyError::Ldap("Base DN must be provided".to_string())
    })?;

    // Create LDAP configuration
    let server_url = config
        .ldap_server
        .clone()
        .unwrap_or_else(|| "ldap://localhost:389".to_string());

    let mut ldap_config = LdapConfig::new(server_url, base_dn.clone());

    if let (Some(username), Some(password)) = (&config.username, &config.password) {
        ldap_config = ldap_config.with_credentials(username.clone(), password.clone());
    }

    // Connect to LDAP
    let mut ldap = ldap_operations::connect(&ldap_config)?;

    // Get PKI objects
    let objects = ldap_operations::get_pki_objects(&mut ldap, &base_dn, &config.object_class)?;

    // Format output
    let mut output = String::new();
    output.push_str(&format!(
        "\n[*] Found {} {} objects:\n\n",
        objects.len(),
        config.object_class
    ));

    for obj in &objects {
        output.push_str(&format!("  Object DN: {}\n", obj.base().distinguished_name()));
        output.push_str(&format!("    Name: {}\n", obj.name()));
        output.push_str(&format!("    Domain: {}\n", obj.domain_name()));

        output.push('\n');
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_pki_objects_config_new() {
        let config = EnumPkiObjectsConfig::new("pKICertificateTemplate");
        assert_eq!(config.object_class, "pKICertificateTemplate");
        assert!(config.ldap_server.is_none());
        assert!(config.base_dn.is_none());
    }

    #[test]
    fn test_enum_pki_objects_config_builder() {
        let config = EnumPkiObjectsConfig::new("pKIEnrollmentService")
            .with_ldap_server("dc01.example.com")
            .with_base_dn("CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com")
            .with_credentials("admin", "password");

        assert_eq!(config.object_class, "pKIEnrollmentService");
        assert_eq!(config.ldap_server, Some("dc01.example.com".to_string()));
        assert_eq!(config.username, Some("admin".to_string()));
        assert_eq!(config.password, Some("password".to_string()));
    }

    #[test]
    fn test_execute_requires_base_dn() {
        let config = EnumPkiObjectsConfig::new("pKICertificateTemplate");
        let result = execute(&config);

        // Should fail because base DN is not provided
        assert!(result.is_err());
    }
}
