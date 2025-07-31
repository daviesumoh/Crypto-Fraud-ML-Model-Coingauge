use std::collections::VecDeque;

use common_types::{
    normalize_address, CanonicalTransaction, ContractArtifact, EntityCategory, EntityLabel,
    FinalityStatus, GraphTransferEdge,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("RPC transport error: {0}")]
    RpcTransport(String),
    #[error("RPC error response: {0}")]
    RpcProtocol(String),
    #[error("RPC rate limit exceeded (HTTP 429)")]
    RateLimited,
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("non-contiguous block #{got} (expected <= #{expected_max})")]
    BlockGap { got: u64, expected_max: u64 },
    #[error("reorg depth exceeded sliding window capacity ({0} blocks)")]
    DeepReorgExceededWindow(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedBlock {
    pub chain_id: u64,
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp_sec: u64,
    pub transactions: Vec<CanonicalTransaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedBlockMutation {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub sign: i8,
    pub block_version: u64,
    pub finality_status: FinalityStatus,
    pub transactions: Vec<CanonicalTransaction>,
}

#[derive(Debug)]
