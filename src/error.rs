//! Error types for the Certify application

use thiserror::Error;

/// Main error type for Certify operations
#[derive(Error, Debug)]
pub enum CertifyError {
    /// LDAP operation error
    #[error("LDAP error: {0}")]
    Ldap(String),

    /// Parsing error
    #[error("Parse error: {0}")]
    Parse(String),

    /// COM interop error (Windows-only)
    #[error("COM error: {0}")]
    Com(String),

    /// Cryptography error
    #[error("Cryptography error: {0}")]
    Crypto(String),

    /// Registry access error
    #[error("Registry error: {0}")]
    Registry(String),

    /// Privilege elevation error
    #[error("Elevation error: {0}")]
    Elevation(String),

    /// Display/output error
    #[error("Display error: {0}")]
    Display(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Feature not supported on this platform
    #[error("Feature not supported on this platform: {0}")]
    NotSupported(String),

    /// Generic error for other cases
    #[error("{0}")]
    Other(String),
}

/// Type alias for Result with CertifyError
pub type Result<T> = std::result::Result<T, CertifyError>;
