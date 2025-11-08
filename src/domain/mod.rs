//! Domain models for PKI objects
//!
//! This module contains data structures representing Active Directory
//! Certificate Services objects like CAs, templates, and PKI objects.

pub mod oids;

// Re-export common types
pub use oids::*;
