//! Active Directory object base types
//!
//! This module provides the foundational types for representing Active Directory objects
//! retrieved via LDAP queries. These types form the base for more specialized PKI objects.

use std::fmt;

/// Represents an Active Directory security descriptor
///
/// This is a placeholder for the security descriptor that will be fully implemented
/// when we add LDAP parsing functionality. For now, it can store the raw binary data
/// from LDAP's nTSecurityDescriptor attribute.
///
/// In the future, this will be enhanced to parse the binary format into a structured
/// representation similar to .NET's ActiveDirectorySecurity class.
#[derive(Debug, Clone, Default)]
pub struct SecurityDescriptor {
    /// Raw binary security descriptor data from LDAP
    raw_data: Vec<u8>,
}

impl SecurityDescriptor {
    /// Creates a new empty security descriptor
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a security descriptor from raw binary data
    ///
    /// # Arguments
    /// * `data` - Raw security descriptor bytes from LDAP nTSecurityDescriptor attribute
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { raw_data: data }
    }

    /// Returns a reference to the raw binary data
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    /// Returns true if the security descriptor is empty
    pub fn is_empty(&self) -> bool {
        self.raw_data.is_empty()
    }

    /// Returns the size of the security descriptor in bytes
    pub fn len(&self) -> usize {
        self.raw_data.len()
    }
}

impl fmt::Display for SecurityDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "<empty security descriptor>")
        } else {
            write!(f, "<security descriptor: {} bytes>", self.len())
        }
    }
}

/// Base type for Active Directory objects
///
/// This struct represents the common properties of all Active Directory objects,
/// specifically those retrieved from LDAP queries. It corresponds to the C# ADObject class
/// from the original implementation.
///
/// In C#, other domain objects inherit from this class. In Rust, we use composition
/// instead of inheritance - specialized types will contain an ADObject field.
///
/// # Examples
/// ```
/// use certify::domain::ad_object::{ADObject, SecurityDescriptor};
///
/// let ad_obj = ADObject::new(
///     "CN=TestUser,CN=Users,DC=contoso,DC=com".to_string(),
///     SecurityDescriptor::new(),
/// );
/// assert_eq!(ad_obj.distinguished_name(), "CN=TestUser,CN=Users,DC=contoso,DC=com");
/// ```
#[derive(Debug, Clone)]
pub struct ADObject {
    /// The LDAP distinguished name (DN) of the object
    distinguished_name: String,

    /// The security descriptor (DACL/SACL) for the object
    security_descriptor: SecurityDescriptor,
}

impl ADObject {
    /// Creates a new Active Directory object
    ///
    /// # Arguments
    /// * `distinguished_name` - The LDAP distinguished name (e.g., "CN=User,DC=contoso,DC=com")
    /// * `security_descriptor` - The security descriptor for the object
    pub fn new(distinguished_name: String, security_descriptor: SecurityDescriptor) -> Self {
        Self {
            distinguished_name,
            security_descriptor,
        }
    }

    /// Returns the distinguished name of the AD object
    pub fn distinguished_name(&self) -> &str {
        &self.distinguished_name
    }

    /// Returns a reference to the security descriptor
    pub fn security_descriptor(&self) -> &SecurityDescriptor {
        &self.security_descriptor
    }

    /// Sets the distinguished name
    pub fn set_distinguished_name(&mut self, dn: String) {
        self.distinguished_name = dn;
    }

    /// Sets the security descriptor
    pub fn set_security_descriptor(&mut self, sd: SecurityDescriptor) {
        self.security_descriptor = sd;
    }

    /// Extracts the common name (CN) from the distinguished name
    ///
    /// Returns None if the DN doesn't have a CN component.
    ///
    /// # Examples
    /// ```
    /// use certify::domain::ad_object::{ADObject, SecurityDescriptor};
    ///
    /// let ad_obj = ADObject::new(
    ///     "CN=TestUser,CN=Users,DC=contoso,DC=com".to_string(),
    ///     SecurityDescriptor::new(),
    /// );
    /// assert_eq!(ad_obj.extract_cn(), Some("TestUser"));
    /// ```
    pub fn extract_cn(&self) -> Option<&str> {
        // Simple extraction - look for CN= at the start
        if let Some(cn_part) = self.distinguished_name.strip_prefix("CN=") {
            // Find the first comma (if any) to get just the CN value
            cn_part.split(',').next()
        } else {
            // Try to find CN= anywhere in the DN
            self.distinguished_name
                .split(',')
                .find_map(|part| part.trim().strip_prefix("CN="))
        }
    }

    /// Extracts the domain name from the distinguished name
    ///
    /// Returns the domain in DNS format (e.g., "contoso.com" from DC=contoso,DC=com)
    ///
    /// # Examples
    /// ```
    /// use certify::domain::ad_object::{ADObject, SecurityDescriptor};
    ///
    /// let ad_obj = ADObject::new(
    ///     "CN=TestUser,CN=Users,DC=contoso,DC=com".to_string(),
    ///     SecurityDescriptor::new(),
    /// );
    /// assert_eq!(ad_obj.extract_domain(), Some("contoso.com".to_string()));
    /// ```
    pub fn extract_domain(&self) -> Option<String> {
        let dc_parts: Vec<&str> = self
            .distinguished_name
            .split(',')
            .filter_map(|part| part.trim().strip_prefix("DC="))
            .collect();

        if dc_parts.is_empty() {
            None
        } else {
            Some(dc_parts.join("."))
        }
    }
}

impl fmt::Display for ADObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ADObject {{ DN: {} }}", self.distinguished_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_descriptor_creation() {
        let sd = SecurityDescriptor::new();
        assert!(sd.is_empty());
        assert_eq!(sd.len(), 0);
    }

    #[test]
    fn test_security_descriptor_from_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let sd = SecurityDescriptor::from_bytes(data.clone());
        assert!(!sd.is_empty());
        assert_eq!(sd.len(), 5);
        assert_eq!(sd.raw_data(), &data[..]);
    }

    #[test]
    fn test_security_descriptor_display() {
        let empty_sd = SecurityDescriptor::new();
        assert_eq!(empty_sd.to_string(), "<empty security descriptor>");

        let sd = SecurityDescriptor::from_bytes(vec![1, 2, 3]);
        assert_eq!(sd.to_string(), "<security descriptor: 3 bytes>");
    }

    #[test]
    fn test_ad_object_creation() {
        let dn = "CN=TestUser,CN=Users,DC=contoso,DC=com".to_string();
        let sd = SecurityDescriptor::new();
        let ad_obj = ADObject::new(dn.clone(), sd);

        assert_eq!(ad_obj.distinguished_name(), dn);
        assert!(ad_obj.security_descriptor().is_empty());
    }

    #[test]
    fn test_ad_object_setters() {
        let mut ad_obj = ADObject::new(
            "CN=Test,DC=example,DC=com".to_string(),
            SecurityDescriptor::new(),
        );

        let new_dn = "CN=NewTest,DC=example,DC=com".to_string();
        ad_obj.set_distinguished_name(new_dn.clone());
        assert_eq!(ad_obj.distinguished_name(), new_dn);

        let new_sd = SecurityDescriptor::from_bytes(vec![1, 2, 3]);
        ad_obj.set_security_descriptor(new_sd);
        assert_eq!(ad_obj.security_descriptor().len(), 3);
    }

    #[test]
    fn test_extract_cn() {
        let ad_obj = ADObject::new(
            "CN=TestUser,CN=Users,DC=contoso,DC=com".to_string(),
            SecurityDescriptor::new(),
        );
        assert_eq!(ad_obj.extract_cn(), Some("TestUser"));

        let ad_obj2 = ADObject::new(
            "OU=Sales,DC=contoso,DC=com".to_string(),
            SecurityDescriptor::new(),
        );
        assert_eq!(ad_obj2.extract_cn(), None);

        let ad_obj3 = ADObject::new(
            "OU=Test,CN=InnerUser,DC=contoso,DC=com".to_string(),
            SecurityDescriptor::new(),
        );
        assert_eq!(ad_obj3.extract_cn(), Some("InnerUser"));
    }

    #[test]
    fn test_extract_domain() {
        let ad_obj = ADObject::new(
            "CN=TestUser,CN=Users,DC=contoso,DC=com".to_string(),
            SecurityDescriptor::new(),
        );
        assert_eq!(ad_obj.extract_domain(), Some("contoso.com".to_string()));

        let ad_obj2 = ADObject::new(
            "CN=User,DC=sub,DC=contoso,DC=com".to_string(),
            SecurityDescriptor::new(),
        );
        assert_eq!(
            ad_obj2.extract_domain(),
            Some("sub.contoso.com".to_string())
        );

        let ad_obj3 = ADObject::new("CN=Test".to_string(), SecurityDescriptor::new());
        assert_eq!(ad_obj3.extract_domain(), None);
    }

    #[test]
    fn test_ad_object_display() {
        let ad_obj = ADObject::new(
            "CN=Test,DC=example,DC=com".to_string(),
            SecurityDescriptor::new(),
        );
        let display = format!("{}", ad_obj);
        assert!(display.contains("ADObject"));
        assert!(display.contains("CN=Test,DC=example,DC=com"));
    }

    #[test]
    fn test_ad_object_clone() {
        let ad_obj = ADObject::new(
            "CN=Test,DC=example,DC=com".to_string(),
            SecurityDescriptor::from_bytes(vec![1, 2, 3]),
        );

        let cloned = ad_obj.clone();
        assert_eq!(cloned.distinguished_name(), ad_obj.distinguished_name());
        assert_eq!(
            cloned.security_descriptor().len(),
            ad_obj.security_descriptor().len()
        );
    }
}
