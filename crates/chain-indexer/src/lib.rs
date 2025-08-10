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
pub struct ManagedJsonRpcProvider {
    rpc_url: String,
    http: reqwest::Client,
}

impl ManagedJsonRpcProvider {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, IndexerError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        const MAX_ATTEMPTS: usize = 3;
        let mut last_err = IndexerError::RpcTransport("unattempted".to_string());

        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                let backoff_ms = 120 * (1u64 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }

            let http_resp = match self.http.post(&self.rpc_url).json(&body).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    last_err = IndexerError::RpcTransport(e.to_string());
                    continue;
                }
            };

            let status = http_resp.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                last_err = IndexerError::RateLimited;
                continue;
            }

            let raw_text = match http_resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    last_err = IndexerError::RpcTransport(e.to_string());
                    continue;
                }
            };

            if !status.is_success() {
                let snippet: String = raw_text.chars().take(160).collect();
                let err = IndexerError::RpcProtocol(format!("HTTP {}: {}", status, snippet.trim()));
                if status.is_server_error() {
                    last_err = err;
                    continue;
                }
                return Err(err);
            }

            let resp: serde_json::Value = serde_json::from_str(&raw_text).map_err(|e| {
                let snippet: String = raw_text.chars().take(120).collect();
                IndexerError::RpcProtocol(format!("invalid JSON-RPC response ({e}): {}", snippet.trim()))
            })?;

            if let Some(err) = resp.get("error") {
                let err_msg = err.to_string();
                if err_msg.contains("429") || err_msg.to_ascii_lowercase().contains("rate limit") {
                    last_err = IndexerError::RateLimited;
                    continue;
                }
                return Err(IndexerError::RpcProtocol(err_msg));
            }
            return Ok(resp["result"].clone());
        }

        Err(last_err)
    }

    pub async fn get_latest_block_number(&self) -> Result<u64, IndexerError> {
        let res = self.rpc_call("eth_blockNumber", serde_json::json!([])).await?;
        let hex_str = res.as_str().ok_or_else(|| {
            IndexerError::RpcProtocol("missing hex string in eth_blockNumber result".to_string())
        })?;
        Ok(parse_hex_u64(hex_str))
    }

    pub async fn get_block_by_number(
        &self,
        block_num: u64,
        include_txs: bool,
    ) -> Result<serde_json::Value, IndexerError> {
        let hex_num = format!("0x{:x}", block_num);
        self.rpc_call("eth_getBlockByNumber", serde_json::json!([hex_num, include_txs]))
            .await
    }

    pub async fn fetch_ingested_block(
        &self,
        chain_id: u64,
        block_num: u64,
        eth_price_usd: f64,
    ) -> Result<IngestedBlock, IndexerError> {
        let block_json = self.get_block_by_number(block_num, true).await?;
        parse_rpc_block(chain_id, &block_json, eth_price_usd)
    }

    pub async fn fetch_chainlink_eth_usd_price(&self, chain_id: u64) -> Option<f64> {
        let feed_addr = match chain_id {
            1 => "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
            8453 => "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
            _ => "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
        };
        let call_obj = serde_json::json!({
            "to": feed_addr,
            "data": "0x50d25bcd"
        });
        let res = self
            .rpc_call("eth_call", serde_json::json!([call_obj, "latest"]))
            .await
            .ok()?;
        let hex_str = res.as_str()?;
        let raw_val = parse_hex_u128(hex_str);
        if raw_val == 0 {
            return None;
        }
        let price = (raw_val as f64) / 1e8;
        if (100.0..=100_000.0).contains(&price) {
            Some(price)
        } else {
            None
        }
    }

    pub async fn get_balance(&self, address: &str) -> Result<u128, IndexerError> {
        let norm = common_types::validate_and_normalize_address(address)
            .map_err(|e| IndexerError::InvalidAddress(e.0))?;
        let res = self
            .rpc_call("eth_getBalance", serde_json::json!([norm, "latest"]))
            .await?;
        let hex_str = res.as_str().ok_or_else(|| {
            IndexerError::RpcProtocol("missing hex string in eth_getBalance result".to_string())
        })?;
        Ok(parse_hex_u128(hex_str))
    }

    pub async fn get_transaction_count(&self, address: &str) -> Result<u64, IndexerError> {
        let norm = common_types::validate_and_normalize_address(address)
            .map_err(|e| IndexerError::InvalidAddress(e.0))?;
        let res = self
            .rpc_call(
                "eth_getTransactionCount",
                serde_json::json!([norm, "latest"]),
            )
            .await?;
        let hex_str = res.as_str().ok_or_else(|| {
            IndexerError::RpcProtocol(
                "missing hex string in eth_getTransactionCount result".to_string(),
            )
        })?;
        Ok(parse_hex_u64(hex_str))
    }

    pub async fn get_code(&self, address: &str) -> Result<String, IndexerError> {
        let norm = common_types::validate_and_normalize_address(address)
            .map_err(|e| IndexerError::InvalidAddress(e.0))?;
        let res = self
            .rpc_call("eth_getCode", serde_json::json!([norm, "latest"]))
            .await?;
        let hex_str = res.as_str().ok_or_else(|| {
            IndexerError::RpcProtocol("missing hex string in eth_getCode result".to_string())
        })?;
        Ok(hex_str.to_string())
    }

    pub async fn get_storage_at(&self, address: &str, slot_hex: &str) -> Result<String, IndexerError> {
        let norm = common_types::validate_and_normalize_address(address)
            .map_err(|e| IndexerError::InvalidAddress(e.0))?;
        let res = self
            .rpc_call(
                "eth_getStorageAt",
                serde_json::json!([norm, slot_hex, "latest"]),
            )
            .await?;
        let hex_str = res.as_str().ok_or_else(|| {
            IndexerError::RpcProtocol("missing hex string in eth_getStorageAt result".to_string())
        })?;
        Ok(hex_str.to_string())
    }

    pub async fn fetch_alchemy_asset_transfers(
        &self,
        address: &str,
        eth_price_usd: f64,
    ) -> Vec<GraphTransferEdge> {
        if !self.rpc_url.contains("alchemy.com") {
            return Vec::new();
        }
        let clean = normalize_address(address);
        let mut edges = Vec::new();
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for direction in ["toAddress", "fromAddress"] {
            let mut filter = serde_json::Map::new();
            filter.insert("fromBlock".to_string(), serde_json::json!("0x0"));
            filter.insert("toBlock".to_string(), serde_json::json!("latest"));
            filter.insert(direction.to_string(), serde_json::json!(clean));
            filter.insert(
                "category".to_string(),
                serde_json::json!(["external", "erc20"]),
            );
            filter.insert("maxCount".to_string(), serde_json::json!("0x14"));
            filter.insert("order".to_string(), serde_json::json!("desc"));

            if let Ok(res) = self
                .rpc_call(
                    "alchemy_getAssetTransfers",
                    serde_json::json!([serde_json::Value::Object(filter)]),
                )
                .await
            {
                if let Some(transfers) = res.get("transfers").and_then(|t| t.as_array()) {
                    for tr in transfers {
                        let hash = tr
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0x")
                            .to_string();
                        let from = tr
                            .get("from")
                            .and_then(|v| v.as_str())
                            .map(normalize_address)
                            .unwrap_or_default();
                        let to = tr
                            .get("to")
                            .and_then(|v| v.as_str())
                            .map(normalize_address)
                            .unwrap_or_default();
                        let asset = tr.get("asset").and_then(|v| v.as_str()).unwrap_or("ETH");
                        let val = tr.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let amount_usd = match asset.to_ascii_uppercase().as_str() {
                            "ETH" | "WETH" => val * eth_price_usd,
                            "USDC" | "USDT" | "DAI" | "USDBC" => val,
                            _ => 0.0,
                        };
                        if !from.is_empty() && !to.is_empty() {
                            edges.push(GraphTransferEdge {
                                tx_hash: hash,
                                from,
                                to,
                                amount_usd,
                                recipient_post_balance_usd: amount_usd.max(100.0),
                                timestamp_sec: now_ts,
                                selector: "0x".to_string(),
                                recipient_is_fresh_nonce_zero: false,
                                recipient_has_outbound_cospend: true,
                            });
                        }
                    }
                }
            }
        }
        edges
    }
}

pub fn parse_hex_u64(val: &str) -> u64 {
    let clean = val.trim().strip_prefix("0x").unwrap_or(val.trim());
    u64::from_str_radix(clean, 16).unwrap_or(0)
}

pub fn parse_hex_u128(val: &str) -> u128 {
    let clean = val.trim().strip_prefix("0x").unwrap_or(val.trim());
    if clean.len() > 32 {
        u128::from_str_radix(&clean[clean.len() - 32..], 16).unwrap_or(u128::MAX)
    } else {
        u128::from_str_radix(clean, 16).unwrap_or(0)
    }
}

pub fn decode_method_selector(calldata_hex: &str) -> (String, String) {
    let clean = calldata_hex.trim().strip_prefix("0x").unwrap_or(calldata_hex.trim());
    if clean.len() < 8 {
        return ("0x".to_string(), "Native Transfer".to_string());
    }
    let selector = format!("0x{}", clean[..8].to_ascii_lowercase());
    let name = match selector.as_str() {
        "0xa9059cbb" => "transfer(address,uint256)",
        "0x095ea7b3" => "approve(address,uint256)",
        "0x23b872dd" => "transferFrom(address,address,uint256)",
        "0x39509351" => "increaseAllowance(address,uint256)",
        "0xa22cb465" => "setApprovalForAll(address,bool)",
        "0xd505accf" => "permit(address,address,uint256,...)",
        "0x87517c45" => "Permit2.approve(address,address,uint160,uint48)",
        "0x2b67b570" => "Permit2.permit(address,PermitSingle,bytes)",
        "0x3593564c" => "UniversalRouter.execute(bytes,bytes[],uint256)",
        "0x24856bc3" => "UniversalRouter.execute(bytes,bytes[])",
        "0x5ae401dc" | "0xac9650d8" => "multicall(bytes[])",
        "0x04e45aaf" => "exactInputSingle(ExactInputSingleParams)",
        "0xb858183f" => "exactInput(ExactInputParams)",
        "0x38ed1739" => "swapExactTokensForTokens(...)",
        "0x7ff36ab5" => "swapExactETHForTokens(...)",
        "0x18cbafe5" => "swapExactTokensForETH(...)",
        "0xd0e30db0" => "deposit()",
        "0x2e1a7d4d" => "withdraw(uint256)",
        "0x617ba037" => "supply(address,uint256,address,uint16)",
        "0x69328dec" => "withdraw(address,uint256,address)",
        "0x1249c58b" => "mint()",
        "0x40c10f19" => "mint(address,uint256)",
        "0x42842e0e" => "safeTransferFrom(address,address,uint256)",
        "0xfb0f3ee1" => "Seaport.fulfillBasicOrder(...)",
        "0xb2267a7b" => "Tornado.deposit(bytes32)",
        "0x21a0adb6" => "Tornado.withdraw(bytes,bytes32,bytes32,address,address,uint256)",
        _ => "Contract Call",
    };
    (selector, name.to_string())
}

