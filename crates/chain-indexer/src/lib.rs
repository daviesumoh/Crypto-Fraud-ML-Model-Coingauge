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
pub struct CanonicalChainTracker {
    chain_id: u64,
    max_window: usize,
    safe_confirmations: u64,
    finalized_confirmations: u64,
    version_counter: u64,
    window: VecDeque<(IngestedBlock, u64, FinalityStatus)>,
}

impl CanonicalChainTracker {
    pub fn new(
        chain_id: u64,
        max_window: usize,
        safe_confirmations: u64,
        finalized_confirmations: u64,
    ) -> Self {
        Self {
            chain_id,
            max_window: max_window.max(8),
            safe_confirmations,
            finalized_confirmations,
            version_counter: 0,
            window: VecDeque::new(),
        }
    }

    pub fn head_number(&self) -> Option<u64> {
        self.window.back().map(|(b, _, _)| b.number)
    }

    pub fn canonical_hashes(&self) -> Vec<(u64, String, FinalityStatus)> {
        self.window
            .iter()
            .map(|(b, _, f)| (b.number, b.hash.clone(), *f))
            .collect()
    }

    pub fn apply_block(
        &mut self,
        block: IngestedBlock,
    ) -> Result<Vec<VersionedBlockMutation>, IndexerError> {
        let mut mutations = Vec::new();

        if let Some((head, _, _)) = self.window.back() {
            if block.number > head.number + 1 {
                return Err(IndexerError::BlockGap {
                    got: block.number,
                    expected_max: head.number + 1,
                });
            }

            let is_reorg = block.number <= head.number || block.parent_hash != head.hash;
            if is_reorg {
                let mut rolled_back = 0usize;
                while let Some((tip, tip_ver, tip_finality)) = self.window.back() {
                    if tip.number >= block.number
                        || (tip.number + 1 == block.number && tip.hash != block.parent_hash)
                    {
                        let (uncled, uncled_ver, uncled_fin) =
                            self.window.pop_back().expect("checked back");
                        rolled_back += 1;
                        mutations.push(VersionedBlockMutation {
                            chain_id: self.chain_id,
                            block_number: uncled.number,
                            block_hash: uncled.hash,
                            parent_hash: uncled.parent_hash,
                            sign: -1,
                            block_version: uncled_ver,
                            finality_status: uncled_fin,
                            transactions: uncled.transactions,
                        });
                    } else {
                        let _ = (tip_ver, tip_finality);
                        break;
                    }
                }

                if self.window.is_empty() && rolled_back >= self.max_window {
                    return Err(IndexerError::DeepReorgExceededWindow(self.max_window));
                }
            }
        }

        self.version_counter += 1;
        let ver = self.version_counter;

        mutations.push(VersionedBlockMutation {
            chain_id: self.chain_id,
            block_number: block.number,
            block_hash: block.hash.clone(),
            parent_hash: block.parent_hash.clone(),
            sign: 1,
            block_version: ver,
            finality_status: FinalityStatus::Pending,
            transactions: block.transactions.clone(),
        });

        self.window.push_back((block, ver, FinalityStatus::Pending));
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        if let Some(head_num) = self.head_number() {
            for (blk, _, status) in &mut self.window {
                let depth = head_num.saturating_sub(blk.number);
                if depth >= self.finalized_confirmations {
                    *status = FinalityStatus::Finalized;
                } else if depth >= self.safe_confirmations {
                    *status = FinalityStatus::Safe;
                }
            }
        }

        Ok(mutations)
    }
}

#[derive(Clone)]
