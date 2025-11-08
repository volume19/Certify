//! Domain models for PKI objects
//!
//! This module contains data structures representing Active Directory
//! Certificate Services objects like CAs, templates, and PKI objects.

pub mod ad_object;
pub mod ca_web_services;
pub mod oids;
pub mod pki_object;

// Re-export common types
pub use ad_object::{ADObject, SecurityDescriptor};
pub use ca_web_services::CertificateAuthorityWebServices;
pub use oids::*;
pub use pki_object::{AccessControlType, PKIObject, PKIObjectACE};
