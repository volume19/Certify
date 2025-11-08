//! Certificate Authority web service endpoints
//!
//! This module defines the CertificateAuthorityWebServices struct which holds
//! URLs for various CA web enrollment services.

/// Represents the web service endpoints for a Certificate Authority
///
/// This corresponds to the C# CertificateAuthorityWebServices class and holds
/// URLs for various web-based certificate enrollment services provided by AD CS.
///
/// # Web Service Types
/// * **Legacy ASP Enrollment** - Classic ASP-based enrollment interface (IIS)
/// * **Enrollment Web Service** - Modern SOAP-based enrollment service (CES)
/// * **Enrollment Policy Web Service** - Policy server for enrollment (CEP)
/// * **Network Device Enrollment Service** - SCEP enrollment for network devices (NDES)
///
/// # Examples
/// ```
/// use certify::domain::ca_web_services::CertificateAuthorityWebServices;
///
/// let mut web_services = CertificateAuthorityWebServices::new();
/// web_services.add_legacy_asp_url("https://ca.contoso.com/certsrv".to_string());
/// web_services.add_enrollment_web_service_url("https://ca.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc".to_string());
///
/// assert_eq!(web_services.legacy_asp_enrollment_urls().len(), 1);
/// ```
#[derive(Debug, Clone, Default)]
pub struct CertificateAuthorityWebServices {
    /// Legacy ASP enrollment URLs (certsrv)
    legacy_asp_enrollment_urls: Vec<String>,

    /// Certificate Enrollment Web Service URLs (CES)
    enrollment_web_service_urls: Vec<String>,

    /// Certificate Enrollment Policy Web Service URLs (CEP)
    enrollment_policy_web_service_urls: Vec<String>,

    /// Network Device Enrollment Service URLs (NDES/SCEP)
    network_device_enrollment_service_urls: Vec<String>,
}

impl CertificateAuthorityWebServices {
    /// Creates a new empty web services collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a slice of legacy ASP enrollment URLs
    pub fn legacy_asp_enrollment_urls(&self) -> &[String] {
        &self.legacy_asp_enrollment_urls
    }

    /// Returns a slice of enrollment web service URLs
    pub fn enrollment_web_service_urls(&self) -> &[String] {
        &self.enrollment_web_service_urls
    }

    /// Returns a slice of enrollment policy web service URLs
    pub fn enrollment_policy_web_service_urls(&self) -> &[String] {
        &self.enrollment_policy_web_service_urls
    }

    /// Returns a slice of network device enrollment service URLs
    pub fn network_device_enrollment_service_urls(&self) -> &[String] {
        &self.network_device_enrollment_service_urls
    }

    /// Adds a legacy ASP enrollment URL
    pub fn add_legacy_asp_url(&mut self, url: String) {
        self.legacy_asp_enrollment_urls.push(url);
    }

    /// Adds an enrollment web service URL
    pub fn add_enrollment_web_service_url(&mut self, url: String) {
        self.enrollment_web_service_urls.push(url);
    }

    /// Adds an enrollment policy web service URL
    pub fn add_enrollment_policy_web_service_url(&mut self, url: String) {
        self.enrollment_policy_web_service_urls.push(url);
    }

    /// Adds a network device enrollment service URL
    pub fn add_network_device_enrollment_service_url(&mut self, url: String) {
        self.network_device_enrollment_service_urls.push(url);
    }

    /// Sets all legacy ASP enrollment URLs at once
    pub fn set_legacy_asp_urls(&mut self, urls: Vec<String>) {
        self.legacy_asp_enrollment_urls = urls;
    }

    /// Sets all enrollment web service URLs at once
    pub fn set_enrollment_web_service_urls(&mut self, urls: Vec<String>) {
        self.enrollment_web_service_urls = urls;
    }

    /// Sets all enrollment policy web service URLs at once
    pub fn set_enrollment_policy_web_service_urls(&mut self, urls: Vec<String>) {
        self.enrollment_policy_web_service_urls = urls;
    }

    /// Sets all network device enrollment service URLs at once
    pub fn set_network_device_enrollment_service_urls(&mut self, urls: Vec<String>) {
        self.network_device_enrollment_service_urls = urls;
    }

    /// Returns true if there are no web service URLs configured
    pub fn is_empty(&self) -> bool {
        self.legacy_asp_enrollment_urls.is_empty()
            && self.enrollment_web_service_urls.is_empty()
            && self.enrollment_policy_web_service_urls.is_empty()
            && self.network_device_enrollment_service_urls.is_empty()
    }

    /// Returns the total number of web service URLs configured
    pub fn total_url_count(&self) -> usize {
        self.legacy_asp_enrollment_urls.len()
            + self.enrollment_web_service_urls.len()
            + self.enrollment_policy_web_service_urls.len()
            + self.network_device_enrollment_service_urls.len()
    }

    /// Returns true if legacy ASP enrollment is available
    pub fn has_legacy_asp_enrollment(&self) -> bool {
        !self.legacy_asp_enrollment_urls.is_empty()
    }

    /// Returns true if modern web enrollment services are available
    pub fn has_modern_enrollment(&self) -> bool {
        !self.enrollment_web_service_urls.is_empty()
            || !self.enrollment_policy_web_service_urls.is_empty()
    }

    /// Returns true if NDES/SCEP enrollment is available
    pub fn has_ndes_enrollment(&self) -> bool {
        !self.network_device_enrollment_service_urls.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_web_services() {
        let ws = CertificateAuthorityWebServices::new();
        assert!(ws.is_empty());
        assert_eq!(ws.total_url_count(), 0);
        assert!(!ws.has_legacy_asp_enrollment());
        assert!(!ws.has_modern_enrollment());
        assert!(!ws.has_ndes_enrollment());
    }

    #[test]
    fn test_add_legacy_asp_url() {
        let mut ws = CertificateAuthorityWebServices::new();
        ws.add_legacy_asp_url("https://ca.contoso.com/certsrv".to_string());

        assert!(!ws.is_empty());
        assert_eq!(ws.legacy_asp_enrollment_urls().len(), 1);
        assert_eq!(ws.total_url_count(), 1);
        assert!(ws.has_legacy_asp_enrollment());
    }

    #[test]
    fn test_add_enrollment_web_service_url() {
        let mut ws = CertificateAuthorityWebServices::new();
        ws.add_enrollment_web_service_url("https://ca.contoso.com/CES/service.svc".to_string());

        assert!(!ws.is_empty());
        assert_eq!(ws.enrollment_web_service_urls().len(), 1);
        assert!(ws.has_modern_enrollment());
    }

    #[test]
    fn test_add_enrollment_policy_web_service_url() {
        let mut ws = CertificateAuthorityWebServices::new();
        ws.add_enrollment_policy_web_service_url(
            "https://ca.contoso.com/CEP/service.svc".to_string(),
        );

        assert!(ws.has_modern_enrollment());
        assert_eq!(ws.enrollment_policy_web_service_urls().len(), 1);
    }

    #[test]
    fn test_add_ndes_url() {
        let mut ws = CertificateAuthorityWebServices::new();
        ws.add_network_device_enrollment_service_url(
            "https://ca.contoso.com/certsrv/mscep".to_string(),
        );

        assert!(ws.has_ndes_enrollment());
        assert_eq!(ws.network_device_enrollment_service_urls().len(), 1);
    }

    #[test]
    fn test_set_urls() {
        let mut ws = CertificateAuthorityWebServices::new();

        ws.set_legacy_asp_urls(vec![
            "https://ca1.contoso.com/certsrv".to_string(),
            "https://ca2.contoso.com/certsrv".to_string(),
        ]);

        assert_eq!(ws.legacy_asp_enrollment_urls().len(), 2);
        assert_eq!(ws.total_url_count(), 2);
    }

    #[test]
    fn test_multiple_url_types() {
        let mut ws = CertificateAuthorityWebServices::new();

        ws.add_legacy_asp_url("https://ca.contoso.com/certsrv".to_string());
        ws.add_enrollment_web_service_url("https://ca.contoso.com/CES/service.svc".to_string());
        ws.add_enrollment_policy_web_service_url(
            "https://ca.contoso.com/CEP/service.svc".to_string(),
        );
        ws.add_network_device_enrollment_service_url(
            "https://ca.contoso.com/certsrv/mscep".to_string(),
        );

        assert_eq!(ws.total_url_count(), 4);
        assert!(ws.has_legacy_asp_enrollment());
        assert!(ws.has_modern_enrollment());
        assert!(ws.has_ndes_enrollment());
    }

    #[test]
    fn test_clone() {
        let mut ws = CertificateAuthorityWebServices::new();
        ws.add_legacy_asp_url("https://ca.contoso.com/certsrv".to_string());

        let cloned = ws.clone();
        assert_eq!(
            cloned.legacy_asp_enrollment_urls(),
            ws.legacy_asp_enrollment_urls()
        );
    }

    #[test]
    fn test_default() {
        let ws: CertificateAuthorityWebServices = Default::default();
        assert!(ws.is_empty());
    }
}
