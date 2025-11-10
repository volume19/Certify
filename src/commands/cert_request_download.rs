//! Download a previously issued certificate from a Certificate Authority
//!
//! This command retrieves a certificate that has already been issued by the CA
//! using the request ID returned during the initial request.

use crate::enrollment::enrollment::CertificateEnrollment;
use crate::error::Result;

/// Configuration for CertRequestDownload command
#[derive(Debug, Clone)]
pub struct CertRequestDownloadConfig {
    /// Request ID from the CA
    pub request_id: i32,
    /// CA configuration string (e.g., "CA01\\CA-Name")
    pub ca_config: String,
    /// Output format (PEM or DER)
    pub output_format: OutputFormat,
    /// Optional output file path
    pub output_file: Option<String>,
}

/// Certificate output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// PEM format (Base64 encoded)
    Pem,
    /// DER format (binary)
    Der,
}

impl CertRequestDownloadConfig {
    /// Create a new configuration
    ///
    /// # Arguments
    ///
    /// * `request_id` - The request ID from the CA
    /// * `ca_config` - CA configuration string
    ///
    /// # Example
    ///
    /// ```
    /// use certify::commands::cert_request_download::CertRequestDownloadConfig;
    ///
    /// let config = CertRequestDownloadConfig::new(12345, "CA01\\MyCA");
    /// assert_eq!(config.request_id, 12345);
    /// ```
    pub fn new(request_id: i32, ca_config: impl Into<String>) -> Self {
        Self {
            request_id,
            ca_config: ca_config.into(),
            output_format: OutputFormat::Pem,
            output_file: None,
        }
    }

    /// Set the output format
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    /// Set the output file path
    pub fn with_output_file(mut self, path: impl Into<String>) -> Self {
        self.output_file = Some(path.into());
        self
    }
}

/// Execute the CertRequestDownload command
///
/// Downloads a certificate that has been issued by the CA.
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
/// use certify::commands::cert_request_download::{CertRequestDownloadConfig, execute};
///
/// let config = CertRequestDownloadConfig::new(12345, "CA01\\MyCA");
/// // let output = execute(&config)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn execute(config: &CertRequestDownloadConfig) -> Result<String> {
    // Create enrollment context
    let enrollment = CertificateEnrollment::new()?;

    // Download the certificate
    let cert_der = enrollment.download_certificate(config.request_id, &config.ca_config)?;

    // Convert format if needed
    let cert_data = match config.output_format {
        OutputFormat::Der => cert_der,
        OutputFormat::Pem => {
            // Convert DER to PEM
            let pem = crate::crypto::cert_transform::encode_pem(
                &cert_der,
                crate::crypto::cert_transform::PemType::Certificate,
            )?;
            pem.into_bytes()
        }
    };

    // Write to file if specified
    if let Some(ref output_file) = config.output_file {
        std::fs::write(output_file, &cert_data)?;
    }

    // Format output message
    let mut output = String::new();
    output.push_str(&format!(
        "\n[*] Certificate downloaded successfully (Request ID: {})\n",
        config.request_id
    ));
    output.push_str(&format!("    CA: {}\n", config.ca_config));
    output.push_str(&format!(
        "    Format: {}\n",
        match config.output_format {
            OutputFormat::Pem => "PEM",
            OutputFormat::Der => "DER",
        }
    ));
    output.push_str(&format!("    Size: {} bytes\n", cert_data.len()));

    if let Some(ref output_file) = config.output_file {
        output.push_str(&format!("    Saved to: {}\n", output_file));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_request_download_config_new() {
        let config = CertRequestDownloadConfig::new(12345, "CA01\\MyCA");
        assert_eq!(config.request_id, 12345);
        assert_eq!(config.ca_config, "CA01\\MyCA");
        assert_eq!(config.output_format, OutputFormat::Pem);
        assert!(config.output_file.is_none());
    }

    #[test]
    fn test_cert_request_download_config_builder() {
        let config = CertRequestDownloadConfig::new(999, "TestCA\\CA")
            .with_format(OutputFormat::Der)
            .with_output_file("/tmp/cert.der");

        assert_eq!(config.request_id, 999);
        assert_eq!(config.output_format, OutputFormat::Der);
        assert_eq!(config.output_file, Some("/tmp/cert.der".to_string()));
    }

    #[test]
    fn test_output_format_equality() {
        assert_eq!(OutputFormat::Pem, OutputFormat::Pem);
        assert_eq!(OutputFormat::Der, OutputFormat::Der);
        assert_ne!(OutputFormat::Pem, OutputFormat::Der);
    }

    #[test]
    fn test_config_clone() {
        let config1 = CertRequestDownloadConfig::new(123, "CA").with_format(OutputFormat::Der);
        let config2 = config1.clone();

        assert_eq!(config1.request_id, config2.request_id);
        assert_eq!(config1.output_format, config2.output_format);
    }
}
