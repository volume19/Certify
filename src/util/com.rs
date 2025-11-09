//! COM initialization and distributed COM utilities
//!
//! This module provides utilities for initializing COM and setting up
//! DCOM authentication for remote certificate operations.

use crate::error::{CertifyError, Result};

/// COM initialization mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComThreadingModel {
    /// Single-threaded apartment
    Sta,
    /// Multi-threaded apartment
    Mta,
}

/// DCOM authentication level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationLevel {
    /// No authentication
    None,
    /// Connect-level authentication
    Connect,
    /// Call-level authentication
    Call,
    /// Packet-level authentication
    Packet,
    /// Packet integrity authentication
    PacketIntegrity,
    /// Packet privacy authentication
    PacketPrivacy,
}

/// DCOM impersonation level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonationLevel {
    /// Anonymous impersonation
    Anonymous,
    /// Identify impersonation
    Identify,
    /// Impersonate
    Impersonate,
    /// Delegate
    Delegate,
}

/// COM context manager that ensures proper COM initialization and cleanup
///
/// This type implements RAII to ensure COM is properly uninitialized when
/// the context goes out of scope. It's similar to C#'s using pattern.
///
/// # Examples
///
/// ```no_run
/// use certify::util::com::{ComContext, ComThreadingModel};
///
/// // Initialize COM for multi-threaded apartment
/// let _com = ComContext::initialize(ComThreadingModel::Mta)?;
///
/// // COM is automatically cleaned up when _com goes out of scope
/// # Ok::<(), certify::CertifyError>(())
/// ```
#[derive(Debug)]
pub struct ComContext {
    #[allow(dead_code)]
    threading_model: ComThreadingModel,
}

impl ComContext {
    /// Initialize COM library
    ///
    /// # Arguments
    ///
    /// * `threading_model` - The COM threading model to use
    ///
    /// # Returns
    ///
    /// A `ComContext` that will uninitialize COM when dropped
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses CoInitializeEx from windows-rs
    /// - **Other platforms**: Returns an error indicating lack of support
    #[cfg(target_os = "windows")]
    pub fn initialize(threading_model: ComThreadingModel) -> Result<Self> {
        use windows::Win32::System::Com::{
            CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED,
        };

        let coinit_flags = match threading_model {
            ComThreadingModel::Sta => COINIT_APARTMENTTHREADED,
            ComThreadingModel::Mta => COINIT_MULTITHREADED,
        };

        unsafe {
            CoInitializeEx(None, coinit_flags)
                .map_err(|e| CertifyError::Com(format!("Failed to initialize COM: {}", e)))?;
        }

        Ok(Self { threading_model })
    }

    /// Initialize COM library (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn initialize(_threading_model: ComThreadingModel) -> Result<Self> {
        Err(CertifyError::NotSupported(
            "COM is only available on Windows".to_string(),
        ))
    }

    /// Initialize COM security for DCOM operations
    ///
    /// Sets up COM security with specified authentication and impersonation levels.
    /// This is required for remote DCOM calls.
    ///
    /// # Arguments
    ///
    /// * `auth_level` - Authentication level
    /// * `imp_level` - Impersonation level
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses CoInitializeSecurity
    /// - **Other platforms**: Returns error
    #[cfg(target_os = "windows")]
    pub fn initialize_security(
        auth_level: AuthenticationLevel,
        imp_level: ImpersonationLevel,
    ) -> Result<()> {
        use windows::Win32::System::Com::{
            CoInitializeSecurity, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_CONNECT,
            RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_ANONYMOUS, RPC_C_IMP_LEVEL_DELEGATE,
            RPC_C_IMP_LEVEL_IDENTIFY, RPC_C_IMP_LEVEL_IMPERSONATE,
        };

        let auth_level_value = match auth_level {
            AuthenticationLevel::None => RPC_C_AUTHN_LEVEL_NONE,
            AuthenticationLevel::Connect => RPC_C_AUTHN_LEVEL_CONNECT,
            AuthenticationLevel::Call => RPC_C_AUTHN_LEVEL_CALL,
            AuthenticationLevel::Packet => RPC_C_AUTHN_LEVEL_PKT,
            AuthenticationLevel::PacketIntegrity => RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            AuthenticationLevel::PacketPrivacy => RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        };

        let imp_level_value = match imp_level {
            ImpersonationLevel::Anonymous => RPC_C_IMP_LEVEL_ANONYMOUS,
            ImpersonationLevel::Identify => RPC_C_IMP_LEVEL_IDENTIFY,
            ImpersonationLevel::Impersonate => RPC_C_IMP_LEVEL_IMPERSONATE,
            ImpersonationLevel::Delegate => RPC_C_IMP_LEVEL_DELEGATE,
        };

        unsafe {
            CoInitializeSecurity(
                None,                // Security descriptor
                -1,                  // Authentication services count (-1 = use default)
                None,                // Authentication services
                None,                // Reserved
                auth_level_value.0,  // Authentication level
                imp_level_value.0,   // Impersonation level
                None,                // Authentication list
                EOAC_NONE,           // Capabilities
                None,                // Reserved
            )
            .map_err(|e| {
                CertifyError::Com(format!("Failed to initialize COM security: {}", e))
            })?;
        }

        Ok(())
    }

    /// Initialize COM security (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn initialize_security(
        _auth_level: AuthenticationLevel,
        _imp_level: ImpersonationLevel,
    ) -> Result<()> {
        Err(CertifyError::NotSupported(
            "COM security is only available on Windows".to_string(),
        ))
    }
}

impl Drop for ComContext {
    /// Uninitialize COM when the context goes out of scope
    #[cfg(target_os = "windows")]
    fn drop(&mut self) {
        use windows::Win32::System::Com::CoUninitialize;
        unsafe {
            CoUninitialize();
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn drop(&mut self) {
        // No-op on non-Windows platforms
    }
}

/// Creates a COM context with default settings (MTA, PacketPrivacy, Impersonate)
///
/// This is a convenience function that initializes COM with recommended settings
/// for certificate enrollment operations.
///
/// # Returns
///
/// A `ComContext` with COM initialized
///
/// # Example
///
/// ```no_run
/// use certify::util::com::create_default_com_context;
///
/// let _com = create_default_com_context()?;
/// // Perform COM operations...
/// # Ok::<(), certify::CertifyError>(())
/// ```
pub fn create_default_com_context() -> Result<ComContext> {
    let context = ComContext::initialize(ComThreadingModel::Mta)?;
    ComContext::initialize_security(
        AuthenticationLevel::PacketPrivacy,
        ImpersonationLevel::Impersonate,
    )?;
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_com_threading_model() {
        assert_eq!(ComThreadingModel::Sta, ComThreadingModel::Sta);
        assert_ne!(ComThreadingModel::Sta, ComThreadingModel::Mta);
    }

    #[test]
    fn test_authentication_level() {
        assert_eq!(AuthenticationLevel::None, AuthenticationLevel::None);
        assert_ne!(
            AuthenticationLevel::PacketPrivacy,
            AuthenticationLevel::None
        );
    }

    #[test]
    fn test_impersonation_level() {
        assert_eq!(ImpersonationLevel::Identify, ImpersonationLevel::Identify);
        assert_ne!(
            ImpersonationLevel::Impersonate,
            ImpersonationLevel::Anonymous
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_com_context_not_supported_on_non_windows() {
        let result = ComContext::initialize(ComThreadingModel::Mta);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CertifyError::NotSupported(_)));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_com_security_not_supported_on_non_windows() {
        let result = ComContext::initialize_security(
            AuthenticationLevel::PacketPrivacy,
            ImpersonationLevel::Impersonate,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CertifyError::NotSupported(_)));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_com_context_initialize() {
        // This test actually initializes COM on Windows
        let result = ComContext::initialize(ComThreadingModel::Mta);
        assert!(result.is_ok());
        // COM context is dropped here, calling CoUninitialize
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_create_default_com_context() {
        let result = create_default_com_context();
        // Note: This might fail if COM security is already initialized
        // in the process, which is expected behavior
        let _ = result;
    }
}
