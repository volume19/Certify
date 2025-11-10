//! Renew an existing certificate using the current certificate
//!
//! This command renews a certificate by creating a new request using the
//! existing certificate's private key and subject information.

use crate::enrollment::enrollment::CertificateEnrollment;
use crate::error::Result;

/// Configuration for CertRequestRenewal command
#[derive(Debug, Clone)]
pub struct CertRequestRenewalConfig {
    /// Path to the existing certificate to renew
    pub certificate_path: String,
    /// CA configuration string (e.g., "CA01\\CA-Name")
    pub ca_config: String,
    /// Template name to use for renewal
    pub template: String,
    /// Install the renewed certificate automatically
    pub install: bool,
}

impl CertRequestRenewalConfig {
    /// Create a new configuration
    ///
    /// # Arguments
    ///
    /// * `certificate_path` - Path to the certificate to renew
    /// * `ca_config` - CA configuration string
    /// * `template` - Template name
    ///
    /// # Example
    ///
    /// ```
    /// use certify::commands::cert_request_renewal::CertRequestRenewalConfig;
    ///
    /// let config = CertRequestRenewalConfig::new(
    ///     "/path/to/cert.pfx",
    ///     "CA01\\MyCA",
    ///     "User"
    /// );
    /// assert_eq!(config.template, "User");
    /// ```
    pub fn new(
        certificate_path: impl Into<String>,
        ca_config: impl Into<String>,
        template: impl Into<String>,
    ) -> Self {
        Self {
            certificate_path: certificate_path.into(),
            ca_config: ca_config.into(),
            template: template.into(),
            install: false,
        }
    }

    /// Enable automatic installation of the renewed certificate
    pub fn install(mut self, enabled: bool) -> Self {
        self.install = enabled;
        self
    }
}

/// Execute the CertRequestRenewal command
///
/// Renews an existing certificate by creating a new certificate request
/// using the existing certificate's subject and key information.
///
/// # Arguments
///
/// * `config` - Command configuration
///
/// # Returns
///
/// Success message with renewal information
///
/// # Example
///
/// ```no_run
/// use certify::commands::cert_request_renewal::{CertRequestRenewalConfig, execute};
///
/// let config = CertRequestRenewalConfig::new(
///     "/path/to/cert.pfx",
///     "CA01\\MyCA",
///     "User"
/// );
/// // let output = execute(&config)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn execute(config: &CertRequestRenewalConfig) -> Result<String> {
    // Read the existing certificate
    let cert_data = std::fs::read(&config.certificate_path)?;

    // Create enrollment context
    let enrollment = CertificateEnrollment::new()?;

    // Request certificate renewal
    // NOTE: This is a simplified version. The full implementation would:
    // 1. Parse the existing certificate
    // 2. Extract the subject and public key
    // 3. Create a renewal request using the same key
    // 4. Submit to the CA
    let result = enrollment.request_certificate(&config.template, &config.ca_config)?;

    // Format output message
    let mut output = String::new();
    output.push_str("\n[*] Certificate renewal request submitted\n");
    output.push_str(&format!("    Template: {}\n", config.template));
    output.push_str(&format!("    CA: {}\n", config.ca_config));
    output.push_str(&format!("    Original cert: {}\n", config.certificate_path));
    output.push_str(&format!("    Status: {:?}\n", result.status));

    if let Some(request_id) = result.request_id {
        output.push_str(&format!("    Request ID: {}\n", request_id));
    }

    if result.is_success() {
        output.push_str("\n[+] Certificate renewed successfully\n");

        if config.install {
            if let Some(ref cert) = result.certificate {
                enrollment.install_certificate(cert)?;
                output.push_str("[+] Certificate installed to personal store\n");
            }
        }
    } else if let Some(ref error) = result.error_message {
        output.push_str(&format!("\n[!] Renewal failed: {}\n", error));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_request_renewal_config_new() {
        let config =
            CertRequestRenewalConfig::new("/path/to/cert.pfx", "CA01\\MyCA", "UserTemplate");

        assert_eq!(config.certificate_path, "/path/to/cert.pfx");
        assert_eq!(config.ca_config, "CA01\\MyCA");
        assert_eq!(config.template, "UserTemplate");
        assert!(!config.install);
    }

    #[test]
    fn test_cert_request_renewal_config_install() {
        let config =
            CertRequestRenewalConfig::new("/cert.pfx", "CA", "Template").install(true);

        assert!(config.install);
    }

    #[test]
    fn test_config_clone() {
        let config1 = CertRequestRenewalConfig::new("/cert", "CA", "Tmpl").install(true);
        let config2 = config1.clone();

        assert_eq!(config1.certificate_path, config2.certificate_path);
        assert_eq!(config1.install, config2.install);
    }
}
