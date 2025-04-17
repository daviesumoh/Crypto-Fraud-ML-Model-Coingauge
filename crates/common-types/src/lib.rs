use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid EVM address: {0}")]
pub struct AddressValidationError(pub String);

pub fn validate_and_normalize_address(addr: &str) -> Result<String, AddressValidationError> {
    let trimmed = addr.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_part.len() != 40 {
        return Err(AddressValidationError(format!(
            "expected 40 hex characters, got {}",
            hex_part.len()
        )));
    }
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AddressValidationError(
            "contains non-hexadecimal characters".to_string(),
        ));
    }
    Ok(format!("0x{}", hex_part.to_ascii_lowercase()))
}

pub fn normalize_address(addr: &str) -> String {
    validate_and_normalize_address(addr).unwrap_or_else(|_| {
        let trimmed = addr.trim().to_ascii_lowercase();
        if trimmed.starts_with("0x") {
            trimmed
        } else {
            format!("0x{trimmed}")
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
