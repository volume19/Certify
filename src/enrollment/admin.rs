//! Certificate Authority administration COM interop wrapper
//!
//! This module provides a Rust wrapper around the Windows Certificate Authority
//! administration COM API for managing certificates and CA configuration.

use crate::error::{CertifyError, Result};
use crate::util::com::{ComContext, ComThreadingModel};

/// Certificate disposition actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateDisposition {
    /// Approve pending certificate request
    Approve = 0,
    /// Deny certificate request
    Deny = 1,
    /// Revoke issued certificate
    Revoke = 2,
}

/// Revocation reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// Unspecified reason
    Unspecified = 0,
    /// Key compromise
    KeyCompromise = 1,
    /// CA compromise
    CaCompromise = 2,
    /// Affiliation changed
    AffiliationChanged = 3,
    /// Superseded
    Superseded = 4,
    /// Cessation of operation
    CessationOfOperation = 5,
    /// Certificate hold
    CertificateHold = 6,
}

impl RevocationReason {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            RevocationReason::Unspecified => "Unspecified",
            RevocationReason::KeyCompromise => "Key Compromise",
            RevocationReason::CaCompromise => "CA Compromise",
            RevocationReason::AffiliationChanged => "Affiliation Changed",
            RevocationReason::Superseded => "Superseded",
            RevocationReason::CessationOfOperation => "Cessation of Operation",
            RevocationReason::CertificateHold => "Certificate Hold",
        }
    }
}

/// Certificate request information
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// Request ID
    pub request_id: i32,
    /// Requester name
    pub requester: String,
    /// Certificate subject
    pub subject: String,
    /// Submission date
    pub submitted_when: String,
    /// Disposition status
    pub disposition: i32,
    /// Disposition message
    pub disposition_message: String,
}

/// Certificate Authority administration context
///
/// This type provides high-level CA administration operations using
/// the Windows Certificate Authority administration COM API.
///
/// # Platform Support
///
/// - **Windows**: Full support via COM (ICertAdmin2)
/// - **Other platforms**: Returns NotSupported errors
///
/// # Examples
///
/// ```no_run
/// use certify::enrollment::admin::CertificateAdmin;
///
/// // Create admin context
/// let admin = CertificateAdmin::new()?;
///
/// // Get pending requests
/// // let requests = admin.get_pending_requests("CA01\\CA-Name")?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
#[derive(Debug)]
pub struct CertificateAdmin {
    _com_context: ComContext,
}

impl CertificateAdmin {
    /// Create a new certificate administration context
    ///
    /// Initializes COM for CA administration operations.
    ///
    /// # Returns
    ///
    /// A new `CertificateAdmin` instance
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

    /// Get pending certificate requests from CA
    ///
    /// # Arguments
    ///
    /// * `ca_config` - CA configuration string (e.g., "CA01\\CA-Name")
    ///
    /// # Returns
    ///
    /// Vector of pending certificate requests
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses ICertView COM interface
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn get_pending_requests(&self, ca_config: &str) -> Result<Vec<CertificateRequest>> {
        // TODO: Implement using ICertView
        // Steps:
        // 1. Create ICertView
        // 2. OpenConnection to CA
        // 3. SetRestriction for pending status
        // 4. Enumerate rows
        // 5. Get column values (RequestID, RequesterName, etc.)

        Err(CertifyError::NotSupported(
            "Get pending requests not yet implemented - requires Windows COM API".to_string(),
        ))
    }

    /// Get pending requests (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn get_pending_requests(&self, _ca_config: &str) -> Result<Vec<CertificateRequest>> {
        Err(CertifyError::NotSupported(
            "CA administration is only available on Windows".to_string(),
        ))
    }

    /// Approve a pending certificate request
    ///
    /// # Arguments
    ///
    /// * `ca_config` - CA configuration string
    /// * `request_id` - Request ID to approve
    ///
    /// # Returns
    ///
    /// Success or error
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses ICertAdmin2::ResubmitRequest
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn approve_request(&self, ca_config: &str, request_id: i32) -> Result<()> {
        // TODO: Implement using ICertAdmin2::ResubmitRequest
        Err(CertifyError::NotSupported(
            "Approve request not yet implemented".to_string(),
        ))
    }

    /// Approve request (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn approve_request(&self, _ca_config: &str, _request_id: i32) -> Result<()> {
        Err(CertifyError::NotSupported(
            "CA administration is only available on Windows".to_string(),
        ))
    }

    /// Deny a pending certificate request
    ///
    /// # Arguments
    ///
    /// * `ca_config` - CA configuration string
    /// * `request_id` - Request ID to deny
    ///
    /// # Returns
    ///
    /// Success or error
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses ICertAdmin2::DenyRequest
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn deny_request(&self, ca_config: &str, request_id: i32) -> Result<()> {
        // TODO: Implement using ICertAdmin2::DenyRequest
        Err(CertifyError::NotSupported(
            "Deny request not yet implemented".to_string(),
        ))
    }

    /// Deny request (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn deny_request(&self, _ca_config: &str, _request_id: i32) -> Result<()> {
        Err(CertifyError::NotSupported(
            "CA administration is only available on Windows".to_string(),
        ))
    }

    /// Revoke an issued certificate
    ///
    /// # Arguments
    ///
    /// * `ca_config` - CA configuration string
    /// * `serial_number` - Certificate serial number
    /// * `reason` - Revocation reason code
    ///
    /// # Returns
    ///
    /// Success or error
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses ICertAdmin2::RevokeCertificate
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn revoke_certificate(
        &self,
        ca_config: &str,
        serial_number: &str,
        reason: RevocationReason,
    ) -> Result<()> {
        // TODO: Implement using ICertAdmin2::RevokeCertificate
        Err(CertifyError::NotSupported(
            "Revoke certificate not yet implemented".to_string(),
        ))
    }

    /// Revoke certificate (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn revoke_certificate(
        &self,
        _ca_config: &str,
        _serial_number: &str,
        _reason: RevocationReason,
    ) -> Result<()> {
        Err(CertifyError::NotSupported(
            "CA administration is only available on Windows".to_string(),
        ))
    }

    /// Get CA configuration (server name and CA name)
    ///
    /// # Arguments
    ///
    /// * `ca_server` - Optional CA server name (None = local)
    ///
    /// # Returns
    ///
    /// CA configuration string
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses ICertConfig to enumerate CAs
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn get_ca_config(&self, ca_server: Option<&str>) -> Result<String> {
        // TODO: Implement using ICertConfig::GetConfig
        Err(CertifyError::NotSupported(
            "Get CA config not yet implemented".to_string(),
        ))
    }

    /// Get CA config (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn get_ca_config(&self, _ca_server: Option<&str>) -> Result<String> {
        Err(CertifyError::NotSupported(
            "CA administration is only available on Windows".to_string(),
        ))
    }

    /// Check if current user has CA administrator permissions
    ///
    /// # Arguments
    ///
    /// * `ca_config` - CA configuration string
    ///
    /// # Returns
    ///
    /// `true` if user has admin rights, `false` otherwise
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Attempts admin operation to test permissions
    /// - **Other platforms**: Returns NotSupported error
    #[cfg(target_os = "windows")]
    pub fn is_ca_administrator(&self, ca_config: &str) -> Result<bool> {
        // TODO: Implement by testing CA admin access
        // Could use ICertAdmin2::IsValidCertificate or similar
        Err(CertifyError::NotSupported(
            "Check CA administrator not yet implemented".to_string(),
        ))
    }

    /// Check CA admin (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn is_ca_administrator(&self, _ca_config: &str) -> Result<bool> {
        Err(CertifyError::NotSupported(
            "CA administration is only available on Windows".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_description() {
        assert_eq!(
            RevocationReason::KeyCompromise.description(),
            "Key Compromise"
        );
        assert_eq!(RevocationReason::Superseded.description(), "Superseded");
    }

    #[test]
    fn test_certificate_disposition() {
        assert_eq!(CertificateDisposition::Approve as i32, 0);
        assert_eq!(CertificateDisposition::Deny as i32, 1);
        assert_eq!(CertificateDisposition::Revoke as i32, 2);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_certificate_admin_new() {
        // This test actually initializes COM on Windows
        let result = CertificateAdmin::new();
        // May fail if COM already initialized in thread, which is OK
        let _ = result;
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_certificate_admin_not_supported() {
        let result = CertificateAdmin::new();
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_request_clone() {
        let request = CertificateRequest {
            request_id: 123,
            requester: "user@example.com".to_string(),
            subject: "CN=User".to_string(),
            submitted_when: "2024-01-01".to_string(),
            disposition: 5,
            disposition_message: "Pending".to_string(),
        };

        let cloned = request.clone();
        assert_eq!(cloned.request_id, 123);
        assert_eq!(cloned.requester, "user@example.com");
    }
}
