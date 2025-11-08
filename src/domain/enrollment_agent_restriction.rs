//! Enrollment Agent Restriction parsing
//!
//! This module handles parsing of enrollment agent restriction data from
//! Active Directory Certificate Services security descriptors.
//!
//! Enrollment agent restrictions control which certificate templates an
//! enrollment agent can request on behalf of other users/computers.

use crate::error::{CertifyError, Result};
use std::fmt;

/// Represents an enrollment agent restriction entry
///
/// This corresponds to the C# EnrollmentAgentRestriction class and is parsed
/// from the opaque data in a CommonAce from a certificate template's security descriptor.
///
/// The binary format is:
/// ```text
/// [DWORD: SID count]
/// [SID 1: Variable length]
/// [SID 2: Variable length]
/// ...
/// [Template name: UTF-16LE string, optional]
/// ```
///
/// # Examples
/// ```
/// use certify::domain::enrollment_agent_restriction::EnrollmentAgentRestriction;
///
/// // Example with agent SID, two target SIDs, and a template
/// let agent_sid = "S-1-5-21-123-456-789-1001".to_string();
/// let targets = vec![
///     "S-1-5-21-123-456-789-1002".to_string(),
///     "S-1-5-21-123-456-789-1003".to_string(),
/// ];
/// let template = "WebServer".to_string();
///
/// let restriction = EnrollmentAgentRestriction::new(agent_sid, targets, template);
/// assert_eq!(restriction.targets().len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct EnrollmentAgentRestriction {
    /// The SID of the enrollment agent
    agent: String,

    /// The certificate template name (or "<All>" if unrestricted)
    template: String,

    /// The SIDs of users/computers the agent can enroll for
    targets: Vec<String>,
}

impl EnrollmentAgentRestriction {
    /// Creates a new enrollment agent restriction
    ///
    /// # Arguments
    /// * `agent` - The enrollment agent's SID
    /// * `targets` - List of target SIDs the agent can enroll for
    /// * `template` - The template name, or "<All>" for unrestricted
    pub fn new(agent: String, targets: Vec<String>, template: String) -> Self {
        Self {
            agent,
            template,
            targets,
        }
    }

    /// Parses an enrollment agent restriction from binary ACE opaque data
    ///
    /// This parses the binary format used in AD CS certificate template
    /// security descriptors for enrollment agent restrictions.
    ///
    /// # Arguments
    /// * `agent_sid` - The SID from the ACE itself (the agent)
    /// * `opaque_data` - The opaque binary data from the CommonAce
    ///
    /// # Binary Format
    /// ```text
    /// Offset | Size | Description
    /// -------|------|------------
    /// 0      | 4    | DWORD: Number of target SIDs
    /// 4      | Var  | SID 1 (binary format)
    /// ...    | Var  | SID N (binary format)
    /// End    | Var  | Template name (UTF-16LE, null-terminated, optional)
    /// ```
    ///
    /// # Errors
    /// Returns an error if the binary data is malformed or truncated
    pub fn from_binary(agent_sid: String, opaque_data: &[u8]) -> Result<Self> {
        if opaque_data.len() < 4 {
            return Err(CertifyError::Other(
                "Enrollment agent restriction data too short".to_string(),
            ));
        }

        let mut index = 0;

        // Read SID count (DWORD, little-endian)
        let sid_count = u32::from_le_bytes([
            opaque_data[index],
            opaque_data[index + 1],
            opaque_data[index + 2],
            opaque_data[index + 3],
        ]);
        index += 4;

        let mut targets = Vec::new();

        // Parse each target SID
        for _ in 0..sid_count {
            if index >= opaque_data.len() {
                return Err(CertifyError::Other(
                    "Truncated SID data in enrollment agent restriction".to_string(),
                ));
            }

            let (sid_string, sid_length) = parse_sid_from_binary(&opaque_data[index..])?;
            targets.push(sid_string);
            index += sid_length;
        }

        // Parse template name (UTF-16LE string at the end, if present)
        let template = if index < opaque_data.len() {
            // Check if there are at least 2 bytes left for null terminator
            if opaque_data.len() - index < 2 {
                return Err(CertifyError::Other(
                    "Invalid template name in enrollment agent restriction".to_string(),
                ));
            }

            // Parse UTF-16LE string, removing null terminators
            let utf16_bytes = &opaque_data[index..];
            let utf16_chars: Vec<u16> = utf16_bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0)
                .collect();

            String::from_utf16(&utf16_chars)
                .map_err(|e| CertifyError::Other(format!("Invalid UTF-16 template name: {}", e)))?
        } else {
            "<All>".to_string()
        };

        Ok(Self {
            agent: agent_sid,
            template,
            targets,
        })
    }

    /// Returns the enrollment agent's SID
    pub fn agent(&self) -> &str {
        &self.agent
    }

    /// Returns the template name
    pub fn template(&self) -> &str {
        &self.template
    }

    /// Returns a slice of target SIDs
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Returns true if the restriction applies to all templates
    pub fn is_all_templates(&self) -> bool {
        self.template == "<All>"
    }
}

impl fmt::Display for EnrollmentAgentRestriction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Agent: {}, Template: {}, Targets: {}",
            self.agent,
            self.template,
            self.targets.len()
        )
    }
}

/// Parses a Windows SID from binary format
///
/// SID binary format:
/// ```text
/// Offset | Size | Description
/// -------|------|------------
/// 0      | 1    | Revision (always 1)
/// 1      | 1    | SubAuthority count (N)
/// 2      | 6    | Identifier Authority (48-bit big-endian)
/// 8      | 4*N  | SubAuthorities (32-bit little-endian each)
/// ```
///
/// # Returns
/// Returns a tuple of (SID string, binary length)
///
/// # Errors
/// Returns an error if the binary data is malformed
fn parse_sid_from_binary(data: &[u8]) -> Result<(String, usize)> {
    if data.len() < 8 {
        return Err(CertifyError::Other("SID data too short".to_string()));
    }

    let revision = data[0];
    if revision != 1 {
        return Err(CertifyError::Other(format!(
            "Invalid SID revision: {}",
            revision
        )));
    }

    let sub_authority_count = data[1] as usize;
    if sub_authority_count > 15 {
        return Err(CertifyError::Other(format!(
            "Invalid SID sub-authority count: {}",
            sub_authority_count
        )));
    }

    let binary_length = 8 + (sub_authority_count * 4);
    if data.len() < binary_length {
        return Err(CertifyError::Other("Truncated SID data".to_string()));
    }

    // Parse identifier authority (6 bytes, big-endian)
    // Usually only the last 4 bytes are used, forming a 32-bit value
    let identifier_authority = u64::from_be_bytes([
        0,
        0,
        data[2],
        data[3],
        data[4],
        data[5],
        data[6],
        data[7],
    ]);

    // Build SID string: S-1-{IA}-{SA1}-{SA2}-...
    let mut sid_string = format!("S-{}-{}", revision, identifier_authority);

    // Parse sub-authorities (32-bit little-endian each)
    let mut index = 8;
    for _ in 0..sub_authority_count {
        let sub_authority = u32::from_le_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]);
        sid_string.push_str(&format!("-{}", sub_authority));
        index += 4;
    }

    Ok((sid_string, binary_length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_agent_restriction_creation() {
        let agent = "S-1-5-21-123-456-789-1001".to_string();
        let targets = vec![
            "S-1-5-21-123-456-789-1002".to_string(),
            "S-1-5-21-123-456-789-1003".to_string(),
        ];
        let template = "WebServer".to_string();

        let restriction = EnrollmentAgentRestriction::new(agent.clone(), targets.clone(), template.clone());

        assert_eq!(restriction.agent(), agent);
        assert_eq!(restriction.template(), template);
        assert_eq!(restriction.targets().len(), 2);
        assert!(!restriction.is_all_templates());
    }

    #[test]
    fn test_enrollment_agent_restriction_all_templates() {
        let restriction = EnrollmentAgentRestriction::new(
            "S-1-5-21-123-456-789-1001".to_string(),
            vec![],
            "<All>".to_string(),
        );

        assert!(restriction.is_all_templates());
    }

    #[test]
    fn test_parse_sid_from_binary() {
        // Example SID: S-1-5-21-123-456-789-1001
        // Revision: 1
        // Sub-authority count: 4
        // Identifier authority: 5 (0x00 00 00 00 00 05)
        // Sub-authorities: 21, 123, 456, 789, 1001 (little-endian)
        let binary_sid = vec![
            0x01, // Revision
            0x04, // Sub-authority count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Identifier authority (5)
            0x15, 0x00, 0x00, 0x00, // Sub-authority 1: 21
            0x7B, 0x00, 0x00, 0x00, // Sub-authority 2: 123
            0xC8, 0x01, 0x00, 0x00, // Sub-authority 3: 456
            0x15, 0x03, 0x00, 0x00, // Sub-authority 4: 789
        ];

        let (sid_string, length) = parse_sid_from_binary(&binary_sid).unwrap();
        assert_eq!(sid_string, "S-1-5-21-123-456-789");
        assert_eq!(length, 24);
    }

    #[test]
    fn test_parse_well_known_sid() {
        // Everyone (S-1-1-0)
        let binary_sid = vec![
            0x01, // Revision
            0x01, // Sub-authority count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Identifier authority (1)
            0x00, 0x00, 0x00, 0x00, // Sub-authority 1: 0
        ];

        let (sid_string, length) = parse_sid_from_binary(&binary_sid).unwrap();
        assert_eq!(sid_string, "S-1-1-0");
        assert_eq!(length, 12);
    }

    #[test]
    fn test_parse_sid_invalid_revision() {
        let binary_sid = vec![
            0x02, // Invalid revision
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_sid_from_binary(&binary_sid);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sid_truncated() {
        let binary_sid = vec![0x01, 0x04, 0x00, 0x00]; // Too short
        let result = parse_sid_from_binary(&binary_sid);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_binary_no_targets() {
        // Binary data: 0 SIDs, no template
        let binary_data = vec![
            0x00, 0x00, 0x00, 0x00, // SID count: 0
        ];

        let agent_sid = "S-1-5-21-123-456-789-1001".to_string();
        let restriction = EnrollmentAgentRestriction::from_binary(agent_sid.clone(), &binary_data).unwrap();

        assert_eq!(restriction.agent(), agent_sid);
        assert_eq!(restriction.targets().len(), 0);
        assert_eq!(restriction.template(), "<All>");
        assert!(restriction.is_all_templates());
    }

    #[test]
    fn test_from_binary_with_targets_and_template() {
        // Binary data: 1 SID (S-1-1-0) + template "Test"
        let mut binary_data = vec![
            0x01, 0x00, 0x00, 0x00, // SID count: 1
            // SID: S-1-1-0
            0x01, // Revision
            0x01, // Sub-authority count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Identifier authority (1)
            0x00, 0x00, 0x00, 0x00, // Sub-authority 1: 0
        ];

        // Add UTF-16LE "Test" with null terminator
        let template_utf16: Vec<u16> = "Test".encode_utf16().collect();
        for &ch in &template_utf16 {
            binary_data.extend_from_slice(&ch.to_le_bytes());
        }
        binary_data.extend_from_slice(&[0x00, 0x00]); // Null terminator

        let agent_sid = "S-1-5-21-123-456-789-1001".to_string();
        let restriction = EnrollmentAgentRestriction::from_binary(agent_sid.clone(), &binary_data).unwrap();

        assert_eq!(restriction.agent(), agent_sid);
        assert_eq!(restriction.targets().len(), 1);
        assert_eq!(restriction.targets()[0], "S-1-1-0");
        assert_eq!(restriction.template(), "Test");
        assert!(!restriction.is_all_templates());
    }

    #[test]
    fn test_from_binary_truncated() {
        let binary_data = vec![0x01]; // Too short
        let agent_sid = "S-1-5-21-123-456-789-1001".to_string();
        let result = EnrollmentAgentRestriction::from_binary(agent_sid, &binary_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        let restriction = EnrollmentAgentRestriction::new(
            "S-1-5-21-123-456-789-1001".to_string(),
            vec!["S-1-5-21-123-456-789-1002".to_string()],
            "WebServer".to_string(),
        );

        let display = format!("{}", restriction);
        assert!(display.contains("S-1-5-21-123-456-789-1001"));
        assert!(display.contains("WebServer"));
        assert!(display.contains("Targets: 1"));
    }
}
