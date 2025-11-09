//! Token impersonation and privilege elevation utilities
//!
//! This module provides utilities for impersonating user tokens and elevating
//! privileges, which is useful for certificate enrollment on behalf of other users.

use crate::error::{CertifyError, Result};

/// Token impersonation guard that ensures proper token cleanup
///
/// This type implements RAII to ensure tokens are properly reverted when
/// the guard goes out of scope. It's similar to WindowsIdentity.Impersonate()
/// in C#.
///
/// # Examples
///
/// ```no_run
/// use certify::util::elevation::TokenImpersonation;
///
/// // Impersonate a user token (handle obtained from elsewhere)
/// // let token_handle = ...; // Get token handle
/// // let _impersonation = TokenImpersonation::impersonate(token_handle)?;
///
/// // Token is automatically reverted when _impersonation goes out of scope
/// # Ok::<(), certify::CertifyError>(())
/// ```
#[derive(Debug)]
pub struct TokenImpersonation {
    #[allow(dead_code)]
    impersonating: bool,
}

impl TokenImpersonation {
    /// Impersonate a user token
    ///
    /// # Arguments
    ///
    /// * `token_handle` - Handle to the token to impersonate
    ///
    /// # Returns
    ///
    /// A `TokenImpersonation` guard that will revert to self when dropped
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses ImpersonateLoggedOnUser from Windows API
    /// - **Other platforms**: Returns error
    ///
    /// # Safety
    ///
    /// The token handle must be valid and have IMPERSONATE access rights.
    #[cfg(target_os = "windows")]
    pub fn impersonate(token_handle: isize) -> Result<Self> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::ImpersonateLoggedOnUser;

        unsafe {
            ImpersonateLoggedOnUser(HANDLE(token_handle)).map_err(|e| {
                CertifyError::Elevation(format!("Failed to impersonate token: {}", e))
            })?;
        }

        Ok(Self {
            impersonating: true,
        })
    }

    /// Impersonate a user token (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn impersonate(_token_handle: isize) -> Result<Self> {
        Err(CertifyError::NotSupported(
            "Token impersonation is only available on Windows".to_string(),
        ))
    }

    /// Revert to self (stop impersonating)
    ///
    /// This is called automatically when the guard is dropped, but can
    /// be called manually to revert earlier.
    ///
    /// # Platform Support
    ///
    /// - **Windows**: Uses RevertToSelf
    /// - **Other platforms**: No-op
    #[cfg(target_os = "windows")]
    pub fn revert(&mut self) -> Result<()> {
        use windows::Win32::Security::RevertToSelf;

        if self.impersonating {
            unsafe {
                RevertToSelf().map_err(|e| {
                    CertifyError::Elevation(format!("Failed to revert to self: {}", e))
                })?;
            }
            self.impersonating = false;
        }

        Ok(())
    }

    /// Revert to self (non-Windows stub)
    #[cfg(not(target_os = "windows"))]
    pub fn revert(&mut self) -> Result<()> {
        self.impersonating = false;
        Ok(())
    }
}

impl Drop for TokenImpersonation {
    /// Automatically revert to self when the impersonation guard is dropped
    fn drop(&mut self) {
        let _ = self.revert();
    }
}

/// Privilege names for Windows access tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// SE_ASSIGNPRIMARYTOKEN_NAME
    AssignPrimaryToken,
    /// SE_BACKUP_NAME
    Backup,
    /// SE_DEBUG_NAME
    Debug,
    /// SE_IMPERSONATE_NAME
    Impersonate,
    /// SE_INCREASE_QUOTA_NAME
    IncreaseQuota,
    /// SE_RESTORE_NAME
    Restore,
    /// SE_SECURITY_NAME
    Security,
    /// SE_TAKE_OWNERSHIP_NAME
    TakeOwnership,
    /// SE_TCB_NAME (Trusted Computer Base)
    Tcb,
}

impl Privilege {
    /// Get the Windows privilege name string
    pub fn as_str(&self) -> &'static str {
        match self {
            Privilege::AssignPrimaryToken => "SeAssignPrimaryTokenPrivilege",
            Privilege::Backup => "SeBackupPrivilege",
            Privilege::Debug => "SeDebugPrivilege",
            Privilege::Impersonate => "SeImpersonatePrivilege",
            Privilege::IncreaseQuota => "SeIncreaseQuotaPrivilege",
            Privilege::Restore => "SeRestorePrivilege",
            Privilege::Security => "SeSecurityPrivilege",
            Privilege::TakeOwnership => "SeTakeOwnershipPrivilege",
            Privilege::Tcb => "SeTcbPrivilege",
        }
    }
}

/// Enable a privilege in the current thread token
///
/// # Arguments
///
/// * `privilege` - The privilege to enable
///
/// # Returns
///
/// Result indicating success or failure
///
/// # Platform Support
///
/// - **Windows**: Uses AdjustTokenPrivileges
/// - **Other platforms**: Returns error
///
/// # Example
///
/// ```no_run
/// use certify::util::elevation::{enable_privilege, Privilege};
///
/// // Enable backup privilege for the current thread
/// // enable_privilege(Privilege::Backup)?;
/// # Ok::<(), certify::CertifyError>(())
/// ```
#[cfg(target_os = "windows")]
pub fn enable_privilege(privilege: Privilege) -> Result<()> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{GetLastError, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        // Open the current process token
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .map_err(|e| CertifyError::Elevation(format!("Failed to open process token: {}", e)))?;

        // Look up the privilege LUID
        let privilege_name = privilege.as_str();
        let mut privilege_name_wide: Vec<u16> = privilege_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut luid = LUID::default();

        LookupPrivilegeValueW(None, PWSTR(privilege_name_wide.as_mut_ptr()), &mut luid)
            .map_err(|_| {
                let err = GetLastError();
                CertifyError::Elevation(format!(
                    "Failed to lookup privilege {}: error code {}",
                    privilege_name,
                    err.0
                ))
            })?;

        // Set up the TOKEN_PRIVILEGES structure
        let mut token_privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // Adjust the token privileges
        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&mut token_privileges),
            0,
            None,
            None,
        )
        .map_err(|e| {
            CertifyError::Elevation(format!("Failed to adjust token privileges: {}", e))
        })?;

        // Check if the privilege was actually enabled
        let last_error = GetLastError();
        if last_error.0 != 0 {
            return Err(CertifyError::Elevation(format!(
                "Failed to enable privilege: error code {}",
                last_error.0
            )));
        }

        Ok(())
    }
}

/// Enable a privilege (non-Windows stub)
#[cfg(not(target_os = "windows"))]
pub fn enable_privilege(_privilege: Privilege) -> Result<()> {
    Err(CertifyError::NotSupported(
        "Privilege elevation is only available on Windows".to_string(),
    ))
}

/// Check if the current process is running with elevated privileges (Administrator)
///
/// # Returns
///
/// `true` if running as administrator, `false` otherwise
///
/// # Platform Support
///
/// - **Windows**: Checks token elevation status
/// - **Other platforms**: Returns `false`
#[cfg(target_os = "windows")]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length = 0u32;

        if GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .is_err()
        {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

/// Check if elevated (non-Windows stub)
#[cfg(not(target_os = "windows"))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_as_str() {
        assert_eq!(Privilege::Debug.as_str(), "SeDebugPrivilege");
        assert_eq!(Privilege::Backup.as_str(), "SeBackupPrivilege");
        assert_eq!(
            Privilege::Impersonate.as_str(),
            "SeImpersonatePrivilege"
        );
    }

    #[test]
    fn test_privilege_equality() {
        assert_eq!(Privilege::Debug, Privilege::Debug);
        assert_ne!(Privilege::Debug, Privilege::Backup);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_token_impersonation_not_supported_on_non_windows() {
        let result = TokenImpersonation::impersonate(0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CertifyError::NotSupported(_)));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_enable_privilege_not_supported_on_non_windows() {
        let result = enable_privilege(Privilege::Debug);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CertifyError::NotSupported(_)));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_is_elevated_returns_false_on_non_windows() {
        assert!(!is_elevated());
    }

    #[test]
    fn test_token_impersonation_revert() {
        #[cfg(not(target_os = "windows"))]
        {
            // On non-Windows, we can't actually impersonate, but we can test
            // the revert logic doesn't panic
            let mut impersonation = TokenImpersonation {
                impersonating: true,
            };
            assert!(impersonation.revert().is_ok());
            assert!(!impersonation.impersonating);
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_is_elevated_returns_bool() {
        // Just check that it returns a boolean value without panicking
        let _ = is_elevated();
    }
}
