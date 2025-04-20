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
pub struct ChainId(pub u64);

impl ChainId {
    pub const ETHEREUM_MAINNET: Self = Self(1);
    pub const OPTIMISM: Self = Self(10);
    pub const BSC: Self = Self(56);
    pub const POLYGON: Self = Self(137);
    pub const BASE: Self = Self(8453);
    pub const ARBITRUM_ONE: Self = Self(42161);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    Pending,
    Safe,
    Finalized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalTransaction {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub tx_hash: String,
    pub timestamp_sec: u64,
    pub finality_status: FinalityStatus,
    pub sender: String,
    pub recipient: Option<String>,
    pub value_wei: u128,
    pub value_usd: f64,
    pub calldata_hex: String,
    pub gas_limit: u64,
    pub max_fee_per_gas_wei: u128,
    pub priority_fee_per_gas_wei: u128,
    pub block_priority_fee_percentile: f64,
    pub nonce: u64,
    pub blocks_since_last_inbound_funding: Option<u64>,
    pub sender_pre_balance_usd: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallType {
    Call,
    DelegateCall,
    StaticCall,
    CallCode,
    Create,
    Create2,
    SelfDestruct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalCallTrace {
    pub depth: u16,
    pub call_type: CallType,
    pub caller: String,
    pub target: String,
    pub value_wei: u128,
    pub selector: String,
    pub reverted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetStandard {
    Native,
    Erc20,
    Erc721,
    Erc1155,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetMovement {
    pub asset_standard: AssetStandard,
    pub token_address: String,
    pub token_symbol: Option<String>,
    pub from_address: String,
    pub to_address: String,
    pub raw_amount: u128,
    pub amount_usd: f64,
    pub recipient_post_balance_usd: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionKind {
    Erc20Approve,
    IncreaseAllowance,
    ApprovalForAll,
    Eip2612Permit,
    UniswapPermit2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionMutation {
    pub kind: PermissionKind,
    pub owner: String,
    pub spender: String,
    pub token_address: String,
    pub is_unlimited: bool,
    pub allowance_usd: f64,
    pub expiration_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractArtifact {
    pub chain_id: u64,
    pub address: String,
    pub bytecode_hash: String,
    pub deployer: String,
    pub age_hours: f64,
    pub is_eoa: bool,
    pub is_verified: bool,
    pub deployed_via_create2: bool,
    pub factory_has_selfdestruct_history: bool,
    pub is_whitelisted_proxy_target: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
