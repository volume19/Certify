//! Certify - Active Directory Certificate Services security auditing tool
//!
//! This is a Rust port of the C# Certify tool for enumerating and auditing
//! misconfigurations in Active Directory Certificate Services (AD CS).
//!
//! # Security Context
//! This tool is intended for authorized penetration testing and defensive
//! security auditing only. Use responsibly and only on systems you have
//! explicit permission to test.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod certify_lib;
pub mod domain;
pub mod error;
pub mod util;

/// Library version matching original C# implementation
pub const VERSION: &str = "2.0.0";

// Re-export common types
pub use error::{CertifyError, Result};
