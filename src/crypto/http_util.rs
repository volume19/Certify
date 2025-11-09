//! HTTP utilities for certificate enrollment operations
//!
//! This module provides HTTP/HTTPS client utilities for interacting with
//! Certificate Authority web enrollment services, including NTLM authentication support.

use crate::error::{CertifyError, Result};
use std::collections::HashMap;

/// HTTP method types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET request
    Get,
    /// POST request
    Post,
    /// PUT request
    Put,
    /// DELETE request
    Delete,
}

impl HttpMethod {
    /// Get the string representation of the HTTP method
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// HTTP authentication type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationType {
    /// No authentication
    None,
    /// Basic authentication (username:password base64-encoded)
    Basic {
        /// Username
        username: String,
        /// Password
        password: String,
    },
    /// NTLM authentication (Windows integrated auth)
    Ntlm {
        /// Domain name
        domain: Option<String>,
        /// Username
        username: String,
        /// Password
        password: String,
    },
    /// Kerberos authentication
    Kerberos {
        /// Service principal name
        spn: String,
    },
}

/// HTTP request configuration
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// URL to request
    pub url: String,
    /// HTTP method
    pub method: HttpMethod,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body (for POST/PUT)
    pub body: Option<Vec<u8>>,
    /// Authentication type
    pub auth: AuthenticationType,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Verify SSL certificates
    pub verify_ssl: bool,
}

impl HttpRequest {
    /// Create a new HTTP request
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method
    /// * `url` - Target URL
    ///
    /// # Returns
    ///
    /// A new `HttpRequest` with default settings
    ///
    /// # Example
    ///
    /// ```
    /// use certify::crypto::http_util::{HttpRequest, HttpMethod};
    ///
    /// let request = HttpRequest::new(HttpMethod::Get, "https://ca.example.com/certsrv");
    /// assert_eq!(request.method, HttpMethod::Get);
    /// ```
    pub fn new(method: HttpMethod, url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method,
            headers: HashMap::new(),
            body: None,
            auth: AuthenticationType::None,
            follow_redirects: true,
            verify_ssl: true,
        }
    }

    /// Set authentication
    pub fn with_auth(mut self, auth: AuthenticationType) -> Self {
        self.auth = auth;
        self
    }

    /// Set request body
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set SSL verification
    pub fn with_ssl_verification(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }
}

/// HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Create a new HTTP response
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Check if response status indicates success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Get response body as string
    pub fn body_as_string(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| CertifyError::Other(format!("Invalid UTF-8 in response: {}", e)))
    }

    /// Get a header value
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }
}

/// HTTP client for CA web enrollment
///
/// This client provides HTTP/HTTPS operations with support for various
/// authentication methods including NTLM.
///
/// # Platform Support
///
/// - **Windows**: Full NTLM support via SSPI
/// - **Other platforms**: Basic and limited NTLM support
#[derive(Debug)]
pub struct HttpClient {
    /// Default timeout in seconds
    pub timeout_seconds: u64,
    /// User agent string
    pub user_agent: String,
}

impl HttpClient {
    /// Create a new HTTP client
    ///
    /// # Example
    ///
    /// ```
    /// use certify::crypto::http_util::HttpClient;
    ///
    /// let client = HttpClient::new();
    /// assert_eq!(client.timeout_seconds, 30);
    /// ```
    pub fn new() -> Self {
        Self {
            timeout_seconds: 30,
            user_agent: format!("Certify/{}", crate::VERSION),
        }
    }

    /// Send an HTTP request
    ///
    /// # Arguments
    ///
    /// * `request` - HTTP request to send
    ///
    /// # Returns
    ///
    /// HTTP response
    ///
    /// # Platform Support
    ///
    /// This is a placeholder that returns NotSupported. In a full implementation:
    /// - **Windows**: Would use reqwest with SSPI/NTLM support
    /// - **Other platforms**: Would use reqwest with basic auth
    ///
    /// # Example
    ///
    /// ```no_run
    /// use certify::crypto::http_util::{HttpClient, HttpRequest, HttpMethod};
    ///
    /// let client = HttpClient::new();
    /// let request = HttpRequest::new(HttpMethod::Get, "https://ca.example.com/certsrv");
    /// // let response = client.send(&request)?;
    /// # Ok::<(), certify::CertifyError>(())
    /// ```
    pub fn send(&self, request: &HttpRequest) -> Result<HttpResponse> {
        // TODO: Implement actual HTTP client using reqwest or similar
        // For Windows with NTLM: Use reqwest with windows-auth feature
        // For cross-platform: Use reqwest with basic auth

        #[cfg(target_os = "windows")]
        {
            self.send_windows(request)
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.send_generic(request)
        }
    }

    /// Send HTTP request on Windows (with NTLM support)
    #[cfg(target_os = "windows")]
    fn send_windows(&self, request: &HttpRequest) -> Result<HttpResponse> {
        // TODO: Implement using reqwest with windows-auth feature
        // This would use SSPI for NTLM authentication
        Err(CertifyError::NotSupported(
            "HTTP client not yet implemented - requires reqwest crate with windows-auth feature"
                .to_string(),
        ))
    }

    /// Send HTTP request on non-Windows platforms
    #[cfg(not(target_os = "windows"))]
    fn send_generic(&self, request: &HttpRequest) -> Result<HttpResponse> {
        // TODO: Implement using reqwest
        // Basic auth supported, limited NTLM support
        Err(CertifyError::NotSupported(
            "HTTP client not yet implemented - requires reqwest crate".to_string(),
        ))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if a URL supports NTLM authentication
///
/// This function makes an unauthenticated request to check if the server
/// responds with a WWW-Authenticate: NTLM challenge.
///
/// # Arguments
///
/// * `url` - URL to test
///
/// # Returns
///
/// `true` if NTLM is supported, `false` otherwise
pub fn supports_ntlm(url: &str) -> Result<bool> {
    let client = HttpClient::new();
    let request = HttpRequest::new(HttpMethod::Get, url);

    match client.send(&request) {
        Ok(response) => {
            // Check for WWW-Authenticate header containing NTLM
            if let Some(auth_header) = response.get_header("WWW-Authenticate") {
                Ok(auth_header.contains("NTLM") || auth_header.contains("Negotiate"))
            } else {
                Ok(false)
            }
        }
        Err(_) => {
            // If we can't connect, assume NTLM is not supported
            Ok(false)
        }
    }
}

/// Checks if a URL requires channel binding (for ESC8 detection)
///
/// Channel binding prevents NTLM relay attacks by binding the authentication
/// to the TLS channel.
///
/// # Arguments
///
/// * `url` - HTTPS URL to test
///
/// # Returns
///
/// `true` if channel binding is enforced, `false` otherwise
pub fn requires_channel_binding(url: &str) -> Result<bool> {
    // TODO: Implement channel binding detection
    // This would require:
    // 1. Establishing TLS connection
    // 2. Attempting NTLM auth without channel binding
    // 3. Checking if auth fails with specific error

    Err(CertifyError::NotSupported(
        "Channel binding detection not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }

    #[test]
    fn test_http_request_new() {
        let request = HttpRequest::new(HttpMethod::Get, "https://example.com");
        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.url, "https://example.com");
        assert!(request.follow_redirects);
        assert!(request.verify_ssl);
    }

    #[test]
    fn test_http_request_with_auth() {
        let auth = AuthenticationType::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let request = HttpRequest::new(HttpMethod::Post, "https://example.com").with_auth(auth);

        match request.auth {
            AuthenticationType::Basic { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
            }
            _ => panic!("Expected Basic auth"),
        }
    }

    #[test]
    fn test_http_request_with_body() {
        let body = vec![1, 2, 3, 4];
        let request = HttpRequest::new(HttpMethod::Post, "https://example.com")
            .with_body(body.clone());

        assert_eq!(request.body, Some(body));
    }

    #[test]
    fn test_http_request_with_header() {
        let request = HttpRequest::new(HttpMethod::Get, "https://example.com")
            .with_header("Content-Type", "application/json");

        assert_eq!(
            request.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn test_http_response_is_success() {
        let success = HttpResponse::new(200);
        assert!(success.is_success());

        let redirect = HttpResponse::new(301);
        assert!(!redirect.is_success());

        let error = HttpResponse::new(404);
        assert!(!error.is_success());
    }

    #[test]
    fn test_http_response_get_header() {
        let mut response = HttpResponse::new(200);
        response
            .headers
            .insert("Content-Type".to_string(), "text/html".to_string());

        assert_eq!(
            response.get_header("Content-Type"),
            Some(&"text/html".to_string())
        );
        assert_eq!(response.get_header("Missing"), None);
    }

    #[test]
    fn test_http_client_new() {
        let client = HttpClient::new();
        assert_eq!(client.timeout_seconds, 30);
        assert!(client.user_agent.contains("Certify"));
    }

    #[test]
    fn test_http_client_default() {
        let client = HttpClient::default();
        assert_eq!(client.timeout_seconds, 30);
    }

    #[test]
    fn test_authentication_types() {
        let none = AuthenticationType::None;
        assert_eq!(none, AuthenticationType::None);

        let basic = AuthenticationType::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        assert!(matches!(basic, AuthenticationType::Basic { .. }));

        let ntlm = AuthenticationType::Ntlm {
            domain: Some("DOMAIN".to_string()),
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        assert!(matches!(ntlm, AuthenticationType::Ntlm { .. }));
    }
}
