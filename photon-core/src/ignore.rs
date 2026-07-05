use std::path::{Path, PathBuf};
use chrono::{NaiveDate, Utc};

/// A single false-positive suppression rule loaded from `.photon-ignore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreEntry {
    /// Rule ID to ignore (None means all rules).
    pub rule_id: Option<String>,
    /// File path to ignore (None means all files).
    pub file_path: Option<PathBuf>,
    /// Function name to ignore (None means all functions).
    pub function_name: Option<String>,
    /// Optional expiration date for this ignore rule.
    pub expires_at: Option<NaiveDate>,
}

impl IgnoreEntry {
    /// Checks if this ignore entry matches a finding.
    pub fn matches(&self, finding_file: &Path, _finding_line: u32, finding_rule_id: &str, finding_description: Option<&str>, finding_function: Option<&str>) -> bool {
        // 1. Check if the ignore entry has expired
        if let Some(expiry) = self.expires_at {
            let today = Utc::now().date_naive();
            if today > expiry {
                // Ignore entry is expired, so it no longer suppresses
                return false;
            }
        }

        // 2. Check file path match (if specified)
        if let Some(ref path) = self.file_path {
            // Check if the finding file contains or ends with the ignored path suffix
            let finding_str = finding_file.to_string_lossy().replace('\\', "/");
            let path_str = path.to_string_lossy().replace('\\', "/");
            if !finding_str.contains(&path_str) {
                return false;
            }
        }

        // 3. Check rule ID match (if specified)
        if let Some(ref rule) = self.rule_id {
            if rule != finding_rule_id {
                return false;
            }
        }

        // 4. Check function name match (if specified)
        if let Some(ref func) = self.function_name {
            let mut func_matched = false;
            if let Some(f) = finding_function {
                if f == func {
                    func_matched = true;
                }
            }
            if !func_matched {
                if let Some(desc) = finding_description {
                    if desc.contains(&format!("`{}`", func)) || desc.contains(&format!("function `{}`", func)) || desc.contains(func) {
                        func_matched = true;
                    }
                }
            }
            if !func_matched {
                return false;
            }
        }

        true
    }
}

/// Parses the contents of a `.photon-ignore` file.
pub fn parse_ignore_file(content: &str) -> Vec<IgnoreEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse optional expiry date: e.g., "path:rule [2026-12-31]"
        let mut expiry = None;
        let mut main_part = trimmed;

        if let Some(start_idx) = trimmed.find('[') {
            if let Some(end_idx) = trimmed.find(']') {
                if start_idx < end_idx {
                    let date_str = &trimmed[start_idx + 1..end_idx];
                    if let Ok(parsed_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                        expiry = Some(parsed_date);
                    }
                    main_part = trimmed[..start_idx].trim();
                }
            }
        }

        let parts: Vec<&str> = main_part.split(':').map(|s| s.trim()).collect();
        if parts.is_empty() {
            continue;
        }

        let mut entry = IgnoreEntry {
            rule_id: None,
            file_path: None,
            function_name: None,
            expires_at: expiry,
        };

        match parts.len() {
            1 => {
                let part = parts[0];
                if part.starts_with("PHOTON-") {
                    entry.rule_id = Some(part.to_string());
                } else {
                    entry.file_path = Some(PathBuf::from(part));
                }
            }
            2 => {
                entry.file_path = Some(PathBuf::from(parts[0]));
                let part = parts[1];
                if part.starts_with("PHOTON-") {
                    entry.rule_id = Some(part.to_string());
                } else {
                    entry.function_name = Some(part.to_string());
                }
            }
            3 => {
                entry.file_path = Some(PathBuf::from(parts[0]));
                entry.function_name = Some(parts[1].to_string());
                entry.rule_id = Some(parts[2].to_string());
            }
            _ => {
                // Invalid format, skip or log warning
            }
        }

        entries.push(entry);
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ignore_simple() {
        let content = "
            # Comment line
            PHOTON-REENTRANCY-001
            contracts/Vault.sol
            contracts/Vault.sol:PHOTON-ACCESS-001
            contracts/Vault.sol:withdraw
            contracts/Vault.sol:withdraw:PHOTON-REENTRANCY-001 [2026-12-31]
        ";

        let entries = parse_ignore_file(content);
        assert_eq!(entries.len(), 5);

        assert_eq!(entries[0], IgnoreEntry {
            rule_id: Some("PHOTON-REENTRANCY-001".to_string()),
            file_path: None,
            function_name: None,
            expires_at: None,
        });

        assert_eq!(entries[1], IgnoreEntry {
            rule_id: None,
            file_path: Some(PathBuf::from("contracts/Vault.sol")),
            function_name: None,
            expires_at: None,
        });

        assert_eq!(entries[2], IgnoreEntry {
            rule_id: Some("PHOTON-ACCESS-001".to_string()),
            file_path: Some(PathBuf::from("contracts/Vault.sol")),
            function_name: None,
            expires_at: None,
        });

        assert_eq!(entries[3], IgnoreEntry {
            rule_id: None,
            file_path: Some(PathBuf::from("contracts/Vault.sol")),
            function_name: Some("withdraw".to_string()),
            expires_at: None,
        });

        assert_eq!(entries[4], IgnoreEntry {
            rule_id: Some("PHOTON-REENTRANCY-001".to_string()),
            file_path: Some(PathBuf::from("contracts/Vault.sol")),
            function_name: Some("withdraw".to_string()),
            expires_at: Some(NaiveDate::from_ymd_opt(2026, 12, 31).unwrap()),
        });
    }

    #[test]
    fn test_matches() {
        let entry = IgnoreEntry {
            rule_id: Some("PHOTON-REENTRANCY-001".to_string()),
            file_path: Some(PathBuf::from("Vault.sol")),
            function_name: Some("withdraw".to_string()),
            expires_at: Some(NaiveDate::from_ymd_opt(2030, 12, 31).unwrap()),
        };

        // Match case
        assert!(entry.matches(
            Path::new("contracts/Vault.sol"),
            42,
            "PHOTON-REENTRANCY-001",
            None,
            Some("withdraw")
        ));

        // Mismatched function
        assert!(!entry.matches(
            Path::new("contracts/Vault.sol"),
            42,
            "PHOTON-REENTRANCY-001",
            None,
            Some("deposit")
        ));

        // Mismatched rule
        assert!(!entry.matches(
            Path::new("contracts/Vault.sol"),
            42,
            "PHOTON-ACCESS-001",
            None,
            Some("withdraw")
        ));

        // Expired match
        let expired_entry = IgnoreEntry {
            rule_id: Some("PHOTON-REENTRANCY-001".to_string()),
            file_path: Some(PathBuf::from("Vault.sol")),
            function_name: Some("withdraw".to_string()),
            expires_at: Some(NaiveDate::from_ymd_opt(2020, 12, 31).unwrap()),
        };
        assert!(!expired_entry.matches(
            Path::new("contracts/Vault.sol"),
            42,
            "PHOTON-REENTRANCY-001",
            None,
            Some("withdraw")
        ));
    }
}
