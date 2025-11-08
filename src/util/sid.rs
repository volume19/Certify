//! SID (Security Identifier) utility functions
//!
//! This module provides functions for validating and classifying Windows Security Identifiers (SIDs).
//! SIDs are unique identifiers used by Windows to identify security principals like users and groups.
//!
//! # SID Format
//! A SID has the format: S-R-I-S-S...
//! - S: Literal "S" indicating it's a SID
//! - R: Revision level (usually 1)
//! - I: Identifier authority value
//! - S: One or more subauthority values
//!
//! Example: S-1-5-21-3623811015-3361044348-30300820-1013

use regex::Regex;
use std::sync::OnceLock;

/// Regular expression for validating SID format
static SID_REGEX: OnceLock<Regex> = OnceLock::new();

/// Regular expression for matching admin SIDs (RID pattern)
static ADMIN_RID_REGEX: OnceLock<Regex> = OnceLock::new();

/// Regular expression for matching low-privilege SIDs (RID pattern)
static LOW_PRIV_RID_REGEX: OnceLock<Regex> = OnceLock::new();

/// Initialize or get the SID validation regex
fn get_sid_regex() -> &'static Regex {
    SID_REGEX.get_or_init(|| {
        Regex::new(r"^S-1-\d+(-\d+){1,15}$").expect("Failed to compile SID regex")
    })
}

/// Initialize or get the admin RID regex
fn get_admin_rid_regex() -> &'static Regex {
    ADMIN_RID_REGEX.get_or_init(|| {
        Regex::new(r"^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$")
            .expect("Failed to compile admin RID regex")
    })
}

/// Initialize or get the low-privilege RID regex
fn get_low_priv_rid_regex() -> &'static Regex {
    LOW_PRIV_RID_REGEX.get_or_init(|| {
        Regex::new(r"^S-1-5-21-.+-(513|515|545)$")
            .expect("Failed to compile low-priv RID regex")
    })
}

/// Checks if a SID represents an administrative account or group
///
/// This includes well-known admin SIDs and domain accounts with admin RIDs:
/// - Domain RIDs: 498 (Enterprise Read-Only Domain Controllers), 500 (Administrator),
///   502 (KRBTGT), 512 (Domain Admins), 516 (Domain Controllers),
///   518 (Schema Admins), 519 (Enterprise Admins), 521 (Read-Only Domain Controllers)
/// - S-1-5-9: Enterprise Domain Controllers
/// - S-1-5-32-544: Administrators (built-in)
///
/// # Examples
/// ```
/// use certify::util::sid::is_admin_sid;
///
/// assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-500")); // Domain Administrator
/// assert!(is_admin_sid("S-1-5-32-544")); // Built-in Administrators
/// assert!(!is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-1001")); // Regular user
/// ```
pub fn is_admin_sid(sid: &str) -> bool {
    get_admin_rid_regex().is_match(sid)
        || sid == "S-1-5-9"      // Enterprise Domain Controllers
        || sid == "S-1-5-32-544" // Administrators
}

/// Checks if a SID represents a low-privilege account or group
///
/// This includes well-known low-privilege SIDs and domain accounts with low-privilege RIDs:
/// - Domain RIDs: 513 (Domain Users), 515 (Domain Computers), 545 (Users - built-in)
/// - S-1-1-0: Everyone
/// - S-1-5-11: Authenticated Users
///
/// # Examples
/// ```
/// use certify::util::sid::is_low_priv_sid;
///
/// assert!(is_low_priv_sid("S-1-5-21-3623811015-3361044348-30300820-513")); // Domain Users
/// assert!(is_low_priv_sid("S-1-1-0")); // Everyone
/// assert!(!is_low_priv_sid("S-1-5-21-3623811015-3361044348-30300820-500")); // Administrator
/// ```
pub fn is_low_priv_sid(sid: &str) -> bool {
    get_low_priv_rid_regex().is_match(sid)
        || sid == "S-1-1-0"   // Everyone
        || sid == "S-1-5-11"  // Authenticated Users
}

/// Validates that a string is a properly formatted SID
///
/// A valid SID must:
/// - Start with "S-1-"
/// - Contain 1 to 15 subauthority values (hyphen-separated numbers)
/// - Use only digits and hyphens after the initial "S-"
///
/// # Examples
/// ```
/// use certify::util::sid::is_valid_sid;
///
/// assert!(is_valid_sid("S-1-5-21-3623811015-3361044348-30300820-1001"));
/// assert!(is_valid_sid("S-1-5-32-544"));
/// assert!(!is_valid_sid("S-1")); // Too short
/// assert!(!is_valid_sid("invalid")); // Not a SID format
/// ```
pub fn is_valid_sid(sid: &str) -> bool {
    get_sid_regex().is_match(sid)
}

/// Checks if a SID represents a computer account
///
/// Computer accounts in Active Directory have SIDs that end with a RID,
/// but are distinguished by their sAMAccountName which ends with a dollar sign ($).
/// However, since this function only receives the SID, it cannot definitively
/// determine if it's a computer account without additional context.
///
/// This function checks if the SID belongs to the Domain Computers group (RID 515).
///
/// # Note
/// For accurate computer account detection, you should check the sAMAccountName
/// attribute from LDAP, not just the SID.
///
/// # Examples
/// ```
/// use certify::util::sid::is_computer_account_group;
///
/// assert!(is_computer_account_group("S-1-5-21-3623811015-3361044348-30300820-515"));
/// assert!(!is_computer_account_group("S-1-5-21-3623811015-3361044348-30300820-513"));
/// ```
pub fn is_computer_account_group(sid: &str) -> bool {
    // Domain Computers group
    sid.ends_with("-515") && sid.starts_with("S-1-5-21-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_admin_sid() {
        // Domain admin RIDs
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-498")); // Enterprise RO DCs
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-500")); // Administrator
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-502")); // KRBTGT
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-512")); // Domain Admins
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-516")); // Domain Controllers
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-518")); // Schema Admins
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-519")); // Enterprise Admins
        assert!(is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-521")); // RO Domain Controllers

        // Well-known admin SIDs
        assert!(is_admin_sid("S-1-5-9"));      // Enterprise Domain Controllers
        assert!(is_admin_sid("S-1-5-32-544")); // Administrators

        // Non-admin SIDs
        assert!(!is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-1001"));
        assert!(!is_admin_sid("S-1-5-21-3623811015-3361044348-30300820-513"));
        assert!(!is_admin_sid("S-1-1-0"));
    }

    #[test]
    fn test_is_low_priv_sid() {
        // Domain low-priv RIDs
        assert!(is_low_priv_sid("S-1-5-21-3623811015-3361044348-30300820-513")); // Domain Users
        assert!(is_low_priv_sid("S-1-5-21-3623811015-3361044348-30300820-515")); // Domain Computers
        assert!(is_low_priv_sid("S-1-5-21-3623811015-3361044348-30300820-545")); // Users

        // Well-known low-priv SIDs
        assert!(is_low_priv_sid("S-1-1-0"));   // Everyone
        assert!(is_low_priv_sid("S-1-5-11"));  // Authenticated Users

        // Non-low-priv SIDs
        assert!(!is_low_priv_sid("S-1-5-21-3623811015-3361044348-30300820-500"));
        assert!(!is_low_priv_sid("S-1-5-32-544"));
    }

    #[test]
    fn test_is_valid_sid() {
        // Valid SIDs
        assert!(is_valid_sid("S-1-5-21-3623811015-3361044348-30300820-1001"));
        assert!(is_valid_sid("S-1-5-32-544"));
        assert!(is_valid_sid("S-1-1-0"));
        assert!(is_valid_sid("S-1-5-21-1-2-3-4"));

        // SID with maximum subauthorities (15)
        assert!(is_valid_sid("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15"));

        // Invalid SIDs
        assert!(!is_valid_sid("S-1")); // Too short
        assert!(!is_valid_sid("S-2-5-21-1-2-3-4")); // Wrong revision
        assert!(!is_valid_sid("invalid")); // Not a SID
        assert!(!is_valid_sid("S-1-5-21-abc-def-ghi")); // Non-numeric
        assert!(!is_valid_sid("1-5-21-1-2-3-4")); // Missing 'S'

        // SID with too many subauthorities (>15)
        assert!(!is_valid_sid("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16"));
    }

    #[test]
    fn test_is_computer_account_group() {
        // Domain Computers group
        assert!(is_computer_account_group("S-1-5-21-3623811015-3361044348-30300820-515"));

        // Not Domain Computers
        assert!(!is_computer_account_group("S-1-5-21-3623811015-3361044348-30300820-513"));
        assert!(!is_computer_account_group("S-1-5-21-3623811015-3361044348-30300820-500"));
        assert!(!is_computer_account_group("S-1-5-32-544"));
    }

    #[test]
    fn test_case_insensitivity() {
        // SID validation should be case-insensitive for the 'S' prefix
        // However, based on the C# implementation, it appears to be case-sensitive
        // The regex uses IgnoreCase in C# for IsValidSid, so let's test both

        // Standard uppercase (should always work)
        assert!(is_valid_sid("S-1-5-21-3623811015-3361044348-30300820-1001"));

        // Lowercase 's' - C# regex has IgnoreCase, but in practice SIDs are always uppercase
        // Our implementation follows the regex pattern which is case-sensitive
        assert!(!is_valid_sid("s-1-5-21-3623811015-3361044348-30300820-1001"));
    }

    #[test]
    fn test_edge_cases() {
        // Empty string
        assert!(!is_valid_sid(""));
        assert!(!is_admin_sid(""));
        assert!(!is_low_priv_sid(""));

        // Single character
        assert!(!is_valid_sid("S"));

        // Minimum valid SID
        assert!(is_valid_sid("S-1-0-0"));

        // Trailing/leading whitespace
        assert!(!is_valid_sid(" S-1-5-21-1-2-3-4"));
        assert!(!is_valid_sid("S-1-5-21-1-2-3-4 "));
    }

    #[test]
    fn test_well_known_sids() {
        // Test various well-known SIDs for correct classification

        // Everyone - low priv
        assert!(is_valid_sid("S-1-1-0"));
        assert!(is_low_priv_sid("S-1-1-0"));
        assert!(!is_admin_sid("S-1-1-0"));

        // Local System (not in our lists)
        assert!(is_valid_sid("S-1-5-18"));
        assert!(!is_admin_sid("S-1-5-18"));
        assert!(!is_low_priv_sid("S-1-5-18"));

        // Authenticated Users - low priv
        assert!(is_valid_sid("S-1-5-11"));
        assert!(is_low_priv_sid("S-1-5-11"));
        assert!(!is_admin_sid("S-1-5-11"));

        // Built-in Administrators - admin
        assert!(is_valid_sid("S-1-5-32-544"));
        assert!(is_admin_sid("S-1-5-32-544"));
        assert!(!is_low_priv_sid("S-1-5-32-544"));
    }
}
