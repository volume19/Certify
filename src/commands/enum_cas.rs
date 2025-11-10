//! Enumerate Certificate Authorities from Active Directory
//!
//! This command retrieves and displays Enterprise Certificate Authorities
//! from Active Directory with vulnerability analysis.

use crate::certify_lib::ldap_operations::{self, LdapConfig};
use crate::error::Result;
use crate::util::display;

/// Configuration for EnumCas command
#[derive(Debug, Clone)]
pub struct EnumCasConfig {
    /// LDAP server to connect to (None = domain default)
    pub ldap_server: Option<String>,
    /// Base DN for search (None = auto-detect)
    pub base_dn: Option<String>,
    /// LDAP username for authentication (None = current user)
    pub username: Option<String>,
    /// LDAP password for authentication
    pub password: Option<String>,
    /// Show only vulnerable CAs
    pub vulnerable_only: bool,
    /// Show detailed output
    pub show_details: bool,
}

impl EnumCasConfig {
    /// Create a new configuration with default settings
    ///
    /// # Example
    ///
    /// ```
    /// use certify::commands::enum_cas::EnumCasConfig;
    ///
    /// let config = EnumCasConfig::new();
    /// assert!(!config.vulnerable_only);
    /// assert!(!config.show_details);
    /// ```
    pub fn new() -> Self {
        Self {
            ldap_server: None,
            base_dn: None,
            username: None,
            password: None,
            vulnerable_only: false,
            show_details: false,
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

    /// Show only vulnerable CAs
    pub fn vulnerable_only(mut self, enabled: bool) -> Self {
        self.vulnerable_only = enabled;
        self
    }

    /// Show detailed output
    pub fn show_details(mut self, enabled: bool) -> Self {
        self.show_details = enabled;
        self
    }
}

impl Default for EnumCasConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute the EnumCas command
///
/// Enumerates Enterprise Certificate Authorities from Active Directory and
/// displays them with vulnerability analysis.
///
/// # Arguments
///
/// * `config` - Command configuration
///
/// # Returns
///
/// Formatted output string with CA information
///
/// # Example
///
/// ```no_run
/// use certify::commands::enum_cas::{EnumCasConfig, execute};
///
/// let config = EnumCasConfig::new()
///     .with_base_dn("CN=Configuration,DC=example,DC=com");
/// // let output = execute(&config)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn execute(config: &EnumCasConfig) -> Result<String> {
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

    // Get Enterprise CAs
    let cas = ldap_operations::get_enterprise_cas(&mut ldap, &base_dn)?;

    // Filter vulnerable CAs if requested
    let filtered_cas: Vec<_> = if config.vulnerable_only {
        cas.iter()
            .filter(|ca| ca.is_vulnerable())
            .collect()
    } else {
        cas.iter().collect()
    };

    // Format output
    let mut output = String::new();

    if filtered_cas.is_empty() {
        if config.vulnerable_only {
            output.push_str("\n[*] No vulnerable Certificate Authorities found.\n");
        } else {
            output.push_str("\n[*] No Certificate Authorities found.\n");
        }
        return Ok(output);
    }

    output.push_str(&format!(
        "\n[*] Found {} Certificate Authorit{}:\n\n",
        filtered_cas.len(),
        if filtered_cas.len() == 1 { "y" } else { "ies" }
    ));

    if config.show_details {
        // Detailed output for each CA
        for ca in &filtered_cas {
            output.push_str(&display::format_enterprise_ca(ca));
            output.push_str("\n");
        }
    } else {
        // Summary output
        output.push_str(&display::format_ca_summary(
            &filtered_cas.iter().map(|&ca| ca.clone()).collect::<Vec<_>>(),
        ));
    }

    // Show vulnerability summary
    let vulnerable_count = filtered_cas
        .iter()
        .filter(|ca| ca.is_vulnerable())
        .count();

    if vulnerable_count > 0 {
        output.push_str(&format!(
            "\n[!] {} CA{} {} potential vulnerabilities\n",
            vulnerable_count,
            if vulnerable_count == 1 { "" } else { "s" },
            if vulnerable_count == 1 { "has" } else { "have" }
        ));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_cas_config_new() {
        let config = EnumCasConfig::new();
        assert!(config.ldap_server.is_none());
        assert!(config.base_dn.is_none());
        assert!(!config.vulnerable_only);
        assert!(!config.show_details);
    }

    #[test]
    fn test_enum_cas_config_default() {
        let config = EnumCasConfig::default();
        assert!(config.ldap_server.is_none());
    }

    #[test]
    fn test_enum_cas_config_builder() {
        let config = EnumCasConfig::new()
            .with_ldap_server("dc01.example.com")
            .with_base_dn("CN=Configuration,DC=example,DC=com")
            .with_credentials("admin", "password")
            .vulnerable_only(true)
            .show_details(true);

        assert_eq!(config.ldap_server, Some("dc01.example.com".to_string()));
        assert_eq!(
            config.base_dn,
            Some("CN=Configuration,DC=example,DC=com".to_string())
        );
        assert_eq!(config.username, Some("admin".to_string()));
        assert!(config.vulnerable_only);
        assert!(config.show_details);
    }

    #[test]
    fn test_execute_requires_base_dn() {
        let config = EnumCasConfig::new();
        let result = execute(&config);

        // Should fail because base DN is not provided
        assert!(result.is_err());
    }

    #[test]
    fn test_config_clone() {
        let config1 = EnumCasConfig::new().vulnerable_only(true);
        let config2 = config1.clone();

        assert_eq!(config1.vulnerable_only, config2.vulnerable_only);
    }
}
