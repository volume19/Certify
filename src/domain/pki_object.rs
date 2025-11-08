//! PKI object types for AD Certificate Services
//!
//! This module provides types for representing PKI-related objects in Active Directory,
//! such as certificate templates, CAs, and other PKI configuration objects.

use super::ad_object::{ADObject, SecurityDescriptor};
use std::fmt;

/// Represents an Access Control Entry (ACE) for PKI objects
///
/// This corresponds to the C# PKIObjectACE class and represents a single
/// access control entry from an object's security descriptor.
///
/// # Fields
/// * `access_type` - Whether this is an Allow or Deny ACE
/// * `rights` - The Active Directory rights granted/denied (e.g., ReadProperty, WriteProperty)
/// * `object_type` - Optional GUID identifying the specific property or extended right
/// * `principal` - The SID or name of the security principal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PKIObjectACE {
    /// The type of access control (Allow or Deny)
    access_type: AccessControlType,

    /// The Active Directory rights
    rights: String,

    /// Optional GUID for property-specific or extended rights
    object_type: Option<uuid::Uuid>,

    /// The security principal (SID or name)
    principal: String,
}

/// Represents the type of access control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControlType {
    /// Access is allowed
    Allow,
    /// Access is denied
    Deny,
}

impl fmt::Display for AccessControlType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessControlType::Allow => write!(f, "Allow"),
            AccessControlType::Deny => write!(f, "Deny"),
        }
    }
}

impl PKIObjectACE {
    /// Creates a new PKIObjectACE
    ///
    /// # Arguments
    /// * `access_type` - Allow or Deny
    /// * `rights` - String representation of the rights (e.g., "ReadProperty, WriteProperty")
    /// * `object_type` - Optional GUID for specific property/extended right
    /// * `principal` - SID or name of the principal
    pub fn new(
        access_type: AccessControlType,
        rights: String,
        object_type: Option<uuid::Uuid>,
        principal: String,
    ) -> Self {
        Self {
            access_type,
            rights,
            object_type,
            principal,
        }
    }

    /// Returns the access control type
    pub fn access_type(&self) -> AccessControlType {
        self.access_type
    }

    /// Returns the rights as a string
    pub fn rights(&self) -> &str {
        &self.rights
    }

    /// Returns the object type GUID if present
    pub fn object_type(&self) -> Option<uuid::Uuid> {
        self.object_type
    }

    /// Returns the principal
    pub fn principal(&self) -> &str {
        &self.principal
    }
}

impl fmt::Display for PKIObjectACE {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} for {}",
            self.access_type, self.rights, self.principal
        )?;
        if let Some(guid) = self.object_type {
            write!(f, " (ObjectType: {})", guid)?;
        }
        Ok(())
    }
}

/// Represents a PKI object in Active Directory
///
/// This corresponds to the C# PKIObject class and extends ADObject with
/// PKI-specific properties. In C#, PKIObject inherits from ADObject.
/// In Rust, we use composition - this struct contains an ADObject.
///
/// PKI objects include certificate templates, certification authorities,
/// enrollment services, and other PKI configuration objects.
///
/// # Examples
/// ```
/// use certify::domain::ad_object::{ADObject, SecurityDescriptor};
/// use certify::domain::pki_object::PKIObject;
///
/// let ad_obj = ADObject::new(
///     "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com".to_string(),
///     SecurityDescriptor::new(),
/// );
///
/// let pki_obj = PKIObject::new(
///     ad_obj,
///     "WebServer".to_string(),
///     "contoso.com".to_string(),
/// );
///
/// assert_eq!(pki_obj.name(), "WebServer");
/// assert_eq!(pki_obj.domain_name(), "contoso.com");
/// ```
#[derive(Debug, Clone)]
pub struct PKIObject {
    /// The base AD object containing DN and security descriptor
    base: ADObject,

    /// The friendly name of the PKI object
    name: String,

    /// The domain name where this object resides
    domain_name: String,
}

impl PKIObject {
    /// Creates a new PKI object
    ///
    /// # Arguments
    /// * `base` - The base ADObject with DN and security descriptor
    /// * `name` - The friendly name of the object
    /// * `domain_name` - The domain name (e.g., "contoso.com")
    pub fn new(base: ADObject, name: String, domain_name: String) -> Self {
        Self {
            base,
            name,
            domain_name,
        }
    }

    /// Creates a new PKI object from components
    ///
    /// # Arguments
    /// * `distinguished_name` - The LDAP distinguished name
    /// * `name` - The friendly name
    /// * `domain_name` - The domain name
    /// * `security_descriptor` - The security descriptor
    pub fn from_components(
        distinguished_name: String,
        name: String,
        domain_name: String,
        security_descriptor: SecurityDescriptor,
    ) -> Self {
        let base = ADObject::new(distinguished_name, security_descriptor);
        Self {
            base,
            name,
            domain_name,
        }
    }

    /// Returns a reference to the base AD object
    pub fn base(&self) -> &ADObject {
        &self.base
    }

    /// Returns a mutable reference to the base AD object
    pub fn base_mut(&mut self) -> &mut ADObject {
        &mut self.base
    }

    /// Returns the friendly name of the PKI object
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the domain name
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }

    /// Returns the distinguished name from the base object
    pub fn distinguished_name(&self) -> &str {
        self.base.distinguished_name()
    }

    /// Returns a reference to the security descriptor from the base object
    pub fn security_descriptor(&self) -> &SecurityDescriptor {
        self.base.security_descriptor()
    }

    /// Sets the name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Sets the domain name
    pub fn set_domain_name(&mut self, domain_name: String) {
        self.domain_name = domain_name;
    }
}

impl fmt::Display for PKIObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PKIObject {{ Name: {}, Domain: {}, DN: {} }}",
            self.name,
            self.domain_name,
            self.base.distinguished_name()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_control_type_display() {
        assert_eq!(AccessControlType::Allow.to_string(), "Allow");
        assert_eq!(AccessControlType::Deny.to_string(), "Deny");
    }

    #[test]
    fn test_pki_object_ace_creation() {
        let ace = PKIObjectACE::new(
            AccessControlType::Allow,
            "ReadProperty, WriteProperty".to_string(),
            None,
            "S-1-5-21-123-456-789-1001".to_string(),
        );

        assert_eq!(ace.access_type(), AccessControlType::Allow);
        assert_eq!(ace.rights(), "ReadProperty, WriteProperty");
        assert_eq!(ace.object_type(), None);
        assert_eq!(ace.principal(), "S-1-5-21-123-456-789-1001");
    }

    #[test]
    fn test_pki_object_ace_with_guid() {
        let guid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
        let ace = PKIObjectACE::new(
            AccessControlType::Deny,
            "ExtendedRight".to_string(),
            Some(guid),
            "Domain Admins".to_string(),
        );

        assert_eq!(ace.access_type(), AccessControlType::Deny);
        assert_eq!(ace.object_type(), Some(guid));
    }

    #[test]
    fn test_pki_object_ace_display() {
        let ace = PKIObjectACE::new(
            AccessControlType::Allow,
            "ReadProperty".to_string(),
            None,
            "Domain Users".to_string(),
        );

        let display = format!("{}", ace);
        assert!(display.contains("Allow"));
        assert!(display.contains("ReadProperty"));
        assert!(display.contains("Domain Users"));
    }

    #[test]
    fn test_pki_object_creation() {
        let dn = "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com".to_string();
        let ad_obj = ADObject::new(dn.clone(), SecurityDescriptor::new());

        let pki_obj = PKIObject::new(
            ad_obj,
            "WebServer".to_string(),
            "contoso.com".to_string(),
        );

        assert_eq!(pki_obj.name(), "WebServer");
        assert_eq!(pki_obj.domain_name(), "contoso.com");
        assert_eq!(pki_obj.distinguished_name(), dn);
    }

    #[test]
    fn test_pki_object_from_components() {
        let dn = "CN=Test,DC=example,DC=com".to_string();
        let pki_obj = PKIObject::from_components(
            dn.clone(),
            "Test".to_string(),
            "example.com".to_string(),
            SecurityDescriptor::new(),
        );

        assert_eq!(pki_obj.name(), "Test");
        assert_eq!(pki_obj.domain_name(), "example.com");
        assert_eq!(pki_obj.distinguished_name(), dn);
    }

    #[test]
    fn test_pki_object_setters() {
        let ad_obj = ADObject::new(
            "CN=Test,DC=example,DC=com".to_string(),
            SecurityDescriptor::new(),
        );

        let mut pki_obj = PKIObject::new(
            ad_obj,
            "Test".to_string(),
            "example.com".to_string(),
        );

        pki_obj.set_name("NewName".to_string());
        assert_eq!(pki_obj.name(), "NewName");

        pki_obj.set_domain_name("newdomain.com".to_string());
        assert_eq!(pki_obj.domain_name(), "newdomain.com");
    }

    #[test]
    fn test_pki_object_base_access() {
        let dn = "CN=Test,DC=example,DC=com".to_string();
        let ad_obj = ADObject::new(dn.clone(), SecurityDescriptor::new());

        let mut pki_obj = PKIObject::new(
            ad_obj,
            "Test".to_string(),
            "example.com".to_string(),
        );

        // Test immutable access
        assert_eq!(pki_obj.base().distinguished_name(), dn);

        // Test mutable access
        let new_dn = "CN=NewTest,DC=example,DC=com".to_string();
        pki_obj.base_mut().set_distinguished_name(new_dn.clone());
        assert_eq!(pki_obj.distinguished_name(), new_dn);
    }

    #[test]
    fn test_pki_object_display() {
        let ad_obj = ADObject::new(
            "CN=Test,DC=example,DC=com".to_string(),
            SecurityDescriptor::new(),
        );

        let pki_obj = PKIObject::new(
            ad_obj,
            "Test".to_string(),
            "example.com".to_string(),
        );

        let display = format!("{}", pki_obj);
        assert!(display.contains("PKIObject"));
        assert!(display.contains("Test"));
        assert!(display.contains("example.com"));
        assert!(display.contains("CN=Test,DC=example,DC=com"));
    }

    #[test]
    fn test_pki_object_clone() {
        let ad_obj = ADObject::new(
            "CN=Test,DC=example,DC=com".to_string(),
            SecurityDescriptor::new(),
        );

        let pki_obj = PKIObject::new(
            ad_obj,
            "Test".to_string(),
            "example.com".to_string(),
        );

        let cloned = pki_obj.clone();
        assert_eq!(cloned.name(), pki_obj.name());
        assert_eq!(cloned.domain_name(), pki_obj.domain_name());
        assert_eq!(
            cloned.distinguished_name(),
            pki_obj.distinguished_name()
        );
    }
}
