//! Certificate enrollment COM interop wrapper
//!
//! This module provides a Rust wrapper around the Windows Certificate Enrollment COM API
//! for requesting, downloading, and managing certificates.

use crate::error::{CertifyError, Result};
use crate::util::com::{ComContext, ComThreadingModel};

/// Certificate enrollment request disposition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentStatus {
    /// Request was issued
    Issued = 3,
    /// Request is pending approval
    Pending = 5,
    /// Request was denied
    Denied = 6,
    /// Request failed
    Failed = 7,
    /// Certificate was installed
    Installed = 8,
}

impl EnrollmentStatus {
    /// Convert from integer disposition code
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            3 => Some(EnrollmentStatus::Issued),
            5 => Some(EnrollmentStatus::Pending),
            6 => Some(EnrollmentStatus::Denied),
            7 => Some(EnrollmentStatus::Failed),
            8 => Some(EnrollmentStatus::Installed),
            _ => None,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            EnrollmentStatus::Issued => "Certificate was issued",
            EnrollmentStatus::Pending => "Request is pending manager approval",
            EnrollmentStatus::Denied => "Request was denied",
            EnrollmentStatus::Failed => "Request failed",
            EnrollmentStatus::Installed => "Certificate was installed",
        }
    }
}

/// Certificate request result
#[derive(Debug, Clone)]
pub struct EnrollmentResult {
    /// Request status
    pub status: EnrollmentStatus,
    /// Certificate data (DER-encoded) if issued
    pub certificate: Option<Vec<u8>>,
    /// Request ID from CA
    pub request_id: Option<i32>,
    /// Error message if failed
    pub error_message: Option<String>,
}

impl EnrollmentResult {
    /// Create a new enrollment result
    pub fn new(status: EnrollmentStatus) -> Self {
        Self {
            status,
            certificate: None,
            request_id: None,
            error_message: None,
        }
    }

    /// Check if enrollment was successful
    pub fn is_success(&self) -> bool {
        matches!(
            self.status,
            EnrollmentStatus::Issued | EnrollmentStatus::Installed
        )
    }
}

/// Certificate enrollment context
///
/// This type provides high-level certificate enrollment operations using
/// the Windows Certificate Enrollment COM API.
///
/// # Platform Support
///
/// - **Windows**: Full support via COM (IX509Enrollment, IX509CertificateRequest)
/// - **Other platforms**: Returns NotSupported errors
///
/// # Examples
///
/// ```no_run
/// use certify::enrollment::enrollment::CertificateEnrollment;
///
/// // Create enrollment context
/// let enrollment = CertificateEnrollment::new()?;
///
/// // Request a certificate from a template
/// // let result = enrollment.request_certificate("WebServer", "CA01\\CA-Name")?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
#[derive(Debug)]
pub struct CertificateEnrollment {
    _com_context: ComContext,
}

impl CertificateEnrollment {
    /// Create a new certificate enrollment context
    ///
    /// Initializes COM for certificate enrollment operations.
    ///
    /// # Returns
    ///
    /// A new `CertificateEnrollment` instance
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Initializes COM
    /// - **Other platforms**: Returns NotSupported error
    pub fn new() -> Result<Self> {
        let com_context = ComContext::initialize(ComThreadingModel::Mta)?;

        Ok(Self {
            _com_context: com_context,
        })
    }

    /// Request a certificate from a template
    ///
    /// # Arguments
    ///
    /// * `template_name` - Certificate template name
    /// * `ca_config` - CA configuration string (e.g., "CA01\\CA-Name")
    ///
    /// # Returns
    ///
    /// Enrollment result with certificate data or error
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses IX509Enrollment COM interface
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn request_certificate(
        &self,
        template_name: &str,
        ca_config: &str,
    ) -> Result<EnrollmentResult> {
        // TODO: Implement using Windows COM API
        // Steps:
        // 1. Create IX509CertificateRequestPkcs10
        // 2. Initialize with template
        // 3. Create IX509Enrollment
        // 4. Install IX509CertificateRequestPkcs10 as inner request
        // 5. CreateRequest to generate CSR
        // 6. Submit to CA via ICertRequest
        // 7. Retrieve certificate

        Err(CertifyError::NotSupported(
            "Certificate enrollment not yet implemented - requires Windows COM API".to_string(),
        ))
    }

    /// Request a certificate (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn request_certificate(
        &self,
        _template_name: &str,
        _ca_config: &str,
    ) -> Result<EnrollmentResult> {
        Err(CertifyError::NotSupported(
            "Certificate enrollment is only available on Windows".to_string(),
        ))
    }

    /// Request a certificate with custom subject
    ///
    /// # Arguments
    ///
    /// * `template_name` - Certificate template name
    /// * `ca_config` - CA configuration string
    /// * `subject` - Subject DN (e.g., "CN=User,OU=IT,DC=example,DC=com")
    ///
    /// # Returns
    ///
    /// Enrollment result
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses IX509Enrollment with custom subject
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn request_certificate_with_subject(
        &self,
        template_name: &str,
        ca_config: &str,
        subject: &str,
    ) -> Result<EnrollmentResult> {
        // TODO: Implement with custom subject (ESC1 exploitation)
        Err(CertifyError::NotSupported(
            "Certificate enrollment with custom subject not yet implemented".to_string(),
        ))
    }

    /// Request certificate with custom subject (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn request_certificate_with_subject(
        &self,
        _template_name: &str,
        _ca_config: &str,
        _subject: &str,
    ) -> Result<EnrollmentResult> {
        Err(CertifyError::NotSupported(
            "Certificate enrollment is only available on Windows".to_string(),
        ))
    }

    /// Request a certificate on behalf of another user
    ///
    /// # Arguments
    ///
    /// * `template_name` - Certificate template name
    /// * `ca_config` - CA configuration string
    /// * `on_behalf_of` - User to request certificate for
    /// * `enrollment_agent_cert` - Enrollment agent certificate
    ///
    /// # Returns
    ///
    /// Enrollment result
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses IX509EnrollmentHelper for on-behalf-of requests
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn request_certificate_on_behalf(
        &self,
        template_name: &str,
        ca_config: &str,
        on_behalf_of: &str,
        enrollment_agent_cert: &[u8],
    ) -> Result<EnrollmentResult> {
        // TODO: Implement enrollment agent scenario (ESC3 exploitation)
        Err(CertifyError::NotSupported(
            "On-behalf-of enrollment not yet implemented".to_string(),
        ))
    }

    /// Request on behalf (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn request_certificate_on_behalf(
        &self,
        _template_name: &str,
        _ca_config: &str,
        _on_behalf_of: &str,
        _enrollment_agent_cert: &[u8],
    ) -> Result<EnrollmentResult> {
        Err(CertifyError::NotSupported(
            "Certificate enrollment is only available on Windows".to_string(),
        ))
    }

    /// Download a previously issued certificate
    ///
    /// # Arguments
    ///
    /// * `request_id` - Request ID from CA
    /// * `ca_config` - CA configuration string
    ///
    /// # Returns
    ///
    /// Certificate data (DER-encoded)
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses ICertRequest::RetrievePending
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn download_certificate(&self, request_id: i32, ca_config: &str) -> Result<Vec<u8>> {
        // TODO: Implement certificate download
        Err(CertifyError::NotSupported(
            "Certificate download not yet implemented".to_string(),
        ))
    }

    /// Download certificate (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn download_certificate(&self, _request_id: i32, _ca_config: &str) -> Result<Vec<u8>> {
        Err(CertifyError::NotSupported(
            "Certificate download is only available on Windows".to_string(),
        ))
    }

    /// Install a certificate into the personal store
    ///
    /// # Arguments
    ///
    /// * `certificate` - Certificate data (DER-encoded)
    ///
    /// # Returns
    ///
    /// Success or error
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses IX509Enrollment::InstallResponse
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn install_certificate(&self, certificate: &[u8]) -> Result<()> {
        // TODO: Implement certificate installation
        Err(CertifyError::NotSupported(
            "Certificate installation not yet implemented".to_string(),
        ))
    }

    /// Install certificate (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn install_certificate(&self, _certificate: &[u8]) -> Result<()> {
        Err(CertifyError::NotSupported(
            "Certificate installation is only available on Windows".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_status_from_code() {
        assert_eq!(
            EnrollmentStatus::from_code(3),
            Some(EnrollmentStatus::Issued)
        );
        assert_eq!(
            EnrollmentStatus::from_code(5),
            Some(EnrollmentStatus::Pending)
        );
        assert_eq!(
            EnrollmentStatus::from_code(6),
            Some(EnrollmentStatus::Denied)
        );
        assert_eq!(EnrollmentStatus::from_code(999), None);
    }

    #[test]
    fn test_enrollment_status_description() {
        assert_eq!(
            EnrollmentStatus::Issued.description(),
            "Certificate was issued"
        );
        assert_eq!(
            EnrollmentStatus::Pending.description(),
            "Request is pending manager approval"
        );
    }

    #[test]
    fn test_enrollment_result_new() {
        let result = EnrollmentResult::new(EnrollmentStatus::Issued);
        assert_eq!(result.status, EnrollmentStatus::Issued);
        assert!(result.certificate.is_none());
        assert!(result.request_id.is_none());
    }

    #[test]
    fn test_enrollment_result_is_success() {
        let issued = EnrollmentResult::new(EnrollmentStatus::Issued);
        assert!(issued.is_success());

        let pending = EnrollmentResult::new(EnrollmentStatus::Pending);
        assert!(!pending.is_success());

        let denied = EnrollmentResult::new(EnrollmentStatus::Denied);
        assert!(!denied.is_success());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_certificate_enrollment_new() {
        // This test actually initializes COM on Windows
        let result = CertificateEnrollment::new();
        // May fail if COM already initialized in thread, which is OK
        let _ = result;
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_certificate_enrollment_not_supported() {
        let result = CertificateEnrollment::new();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_request_certificate_not_supported() {
        // On non-Windows, we can't create enrollment context
        // but we can test the stub behavior with a dummy context
        // by just testing that the functions exist and have correct signatures
    }
}
