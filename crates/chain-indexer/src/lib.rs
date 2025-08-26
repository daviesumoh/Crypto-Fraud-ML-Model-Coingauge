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

fn estimate_erc20_calldata_usd(
    target_address: Option<&str>,
    calldata_hex: &str,
    eth_price_usd: f64,
) -> Option<f64> {
    let target = normalize_address(target_address?);
    let clean = calldata_hex.trim().strip_prefix("0x").unwrap_or(calldata_hex.trim());
    if clean.len() < 8 {
        return None;
    }
    let selector = &clean[..8].to_ascii_lowercase();
    let amount_hex = match selector.as_str() {
        "a9059cbb" if clean.len() >= 136 => &clean[72..136],
        "23b872dd" if clean.len() >= 200 => &clean[136..200],
        _ => return None,
    };
    let raw = parse_hex_u128(amount_hex);
    if raw == 0 || raw == u128::MAX {
        return None;
    }

    match target.as_str() {
        // USDT (6 decimals), USDC Ethereum (6 decimals), USDC Base (6 decimals)
        "0xdac17f958d2ee523a2206206994597c13d831ec7"
        | "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        | "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" => {
            let usd = (raw as f64) / 1e6;
            if usd <= 1_000_000_000.0 {
                Some(usd)
            } else {
                None
            }
        }
        // DAI (18 decimals)
        "0x6b175474e89094c44da98b954eedeac495271d0f"
        | "0x50c5725949a6f0c72e6c4a641f24049a917db0cb" => {
            let usd = (raw as f64) / 1e18;
            if usd <= 1_000_000_000.0 {
                Some(usd)
            } else {
                None
            }
        }
        // WETH Ethereum & Base (18 decimals)
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        | "0x4200000000000000000000000000000000000006"
        | "0xae7ab96520de3a18e5e111b5eaab095312d7fe84" => {
            let eth = (raw as f64) / 1e18;
            if eth <= 500_000.0 {
                Some(eth * eth_price_usd)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn parse_rpc_transaction(
    chain_id: u64,
    block_number: u64,
    block_hash: &str,
    parent_hash: &str,
    block_timestamp_sec: u64,
    tx: &serde_json::Value,
    eth_price_usd: f64,
) -> Option<CanonicalTransaction> {
    let hash = tx.get("hash")?.as_str()?.to_string();
    let from = tx.get("from")?.as_str()?.to_string();
    let to = tx.get("to").and_then(|v| v.as_str()).map(|s| s.to_string());
    let value_hex = tx.get("value").and_then(|v| v.as_str()).unwrap_or("0x0");
    let calldata_hex = tx
        .get("input")
        .and_then(|v| v.as_str())
        .unwrap_or("0x")
        .to_string();
    let gas_hex = tx.get("gas").and_then(|v| v.as_str()).unwrap_or("0x5208");
    let max_fee_hex = tx
        .get("maxFeePerGas")
        .or_else(|| tx.get("gasPrice"))
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");
    let prio_fee_hex = tx
        .get("maxPriorityFeePerGas")
        .or_else(|| tx.get("gasPrice"))
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");
    let nonce_hex = tx.get("nonce").and_then(|v| v.as_str()).unwrap_or("0x0");

    let value_wei = parse_hex_u128(value_hex);
    let gas_limit = parse_hex_u64(gas_hex);
    let max_fee_wei = parse_hex_u128(max_fee_hex);
    let prio_fee_wei = parse_hex_u128(prio_fee_hex);
    let nonce = parse_hex_u64(nonce_hex);

    let native_usd = (value_wei as f64 / 1e18) * eth_price_usd;
    let value_usd = if native_usd > 0.0 {
        native_usd
    } else {
        estimate_erc20_calldata_usd(to.as_deref(), &calldata_hex, eth_price_usd).unwrap_or(0.0)
    };

    Some(CanonicalTransaction {
        chain_id,
        block_number,
        block_hash: block_hash.to_string(),
        parent_hash: parent_hash.to_string(),
        tx_hash: hash,
        timestamp_sec: block_timestamp_sec,
        finality_status: FinalityStatus::Pending,
        sender: from,
        recipient: to,
        value_wei,
        value_usd,
        calldata_hex,
        gas_limit,
        max_fee_per_gas_wei: max_fee_wei,
        priority_fee_per_gas_wei: prio_fee_wei,
        block_priority_fee_percentile: 50.0,
        nonce,
        blocks_since_last_inbound_funding: None,
        sender_pre_balance_usd: (value_usd * 4.0).max(500.0),
    })
}

pub fn parse_rpc_block(
    chain_id: u64,
    block_json: &serde_json::Value,
    eth_price_usd: f64,
) -> Result<IngestedBlock, IndexerError> {
    let number_hex = block_json
        .get("number")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IndexerError::RpcProtocol("missing block number".to_string()))?;
    let hash = block_json
        .get("hash")
        .and_then(|v| v.as_str())
        .unwrap_or("0x")
        .to_string();
    let parent_hash = block_json
        .get("parentHash")
        .and_then(|v| v.as_str())
        .unwrap_or("0x")
        .to_string();
    let ts_hex = block_json
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");

    let block_number = parse_hex_u64(number_hex);
    let timestamp_sec = parse_hex_u64(ts_hex);

    let mut transactions = Vec::new();
    if let Some(txs_array) = block_json.get("transactions").and_then(|t| t.as_array()) {
        for tx_val in txs_array {
            if tx_val.is_object() {
                if let Some(canonical) = parse_rpc_transaction(
                    chain_id,
                    block_number,
                    &hash,
                    &parent_hash,
                    timestamp_sec,
                    tx_val,
                    eth_price_usd,
                ) {
                    transactions.push(canonical);
                }
            }
        }
    }

    if transactions.len() > 1 {
        let mut sorted_fees: Vec<u128> = transactions
            .iter()
            .map(|t| t.priority_fee_per_gas_wei.max(t.max_fee_per_gas_wei))
            .collect();
        sorted_fees.sort_unstable();
        let n = (sorted_fees.len() - 1) as f64;
        for tx in &mut transactions {
            let fee = tx.priority_fee_per_gas_wei.max(tx.max_fee_per_gas_wei);
            let rank = sorted_fees.partition_point(|&f| f < fee) as f64;
            tx.block_priority_fee_percentile = ((rank / n) * 100.0).clamp(1.0, 99.9);
        }
    }

    Ok(IngestedBlock {
        chain_id,
        number: block_number,
        hash,
        parent_hash,
        timestamp_sec,
        transactions,
    })
}

pub fn canonical_entity_registry() -> (Vec<EntityLabel>, Vec<ContractArtifact>) {
    let labels = vec![
        EntityLabel {
            address: "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b".to_string(),
            entity_name: "Tornado Cash: Router".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x722122df12d4e14e13ac3b6895a86e84145b6967".to_string(),
            entity_name: "Tornado Cash: Proxy".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc".to_string(),
            entity_name: "Tornado Cash: 0.1 ETH Pool".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936".to_string(),
            entity_name: "Tornado Cash: 1 ETH Pool".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf".to_string(),
            entity_name: "Tornado Cash: 10 ETH Pool".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0xa160cdab225685da1d56aa342ad8841c3b53f291".to_string(),
            entity_name: "Tornado Cash: 100 ETH Pool".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x098b716b8aaf21512996dc57eb0615e2383e2f96".to_string(),
            entity_name: "Lazarus Group (Ronin Exploiter)".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x19a71f0084365774a95db95781a7044f51e18663".to_string(),
            entity_name: "Lazarus Group (Horizon Bridge)".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x3cffd56b47b7b41c56258d9c7731abdc360e0738".to_string(),
            entity_name: "Lazarus Group (FixedFloat Sinks)".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc".to_string(),
            entity_name: "Tornado Cash: 0.1 ETH Pool".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936".to_string(),
            entity_name: "Tornado Cash: 1 ETH Pool".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0xfd30c04f21c2170988334ec41f17b3551aa010f2".to_string(),
            entity_name: "Tornado Cash: 1000 DAI Pool".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        },
        EntityLabel {
            address: "0x41249b6b78d2b272f3e8f601b084e588fb71e626".to_string(),
            entity_name: "Angel Drainer: Primary Sweep".to_string(),
            category: EntityCategory::WalletDrainer,
            source_feed: "SCAMSNIFFER".to_string(),
            severity_weight: 0.99,
            is_omnibus_sink: false,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x0000db5c8b030ae20308ac975898e09741e70000".to_string(),
            entity_name: "Inferno Drainer Coordinator".to_string(),
            category: EntityCategory::WalletDrainer,
            source_feed: "SCAMSNIFFER".to_string(),
            severity_weight: 0.98,
            is_omnibus_sink: false,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x59abf3837fa962d6853b4cc0a19513aa031fd32b".to_string(),
            entity_name: "FTX Accounts Drainer".to_string(),
            category: EntityCategory::Exploiter,
            source_feed: "ETHERSCAN_LABELS".to_string(),
            severity_weight: 0.95,
            is_omnibus_sink: false,
            is_sanctioned: false,
        },
        // Verified Protocols, Tokens & CEX Omnibus Wallets
        EntityLabel {
            address: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            entity_name: "Tether USD (USDT)".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
            entity_name: "USD Coin (USDC)".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string(),
            entity_name: "Base USD Coin (USDC)".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string(),
            entity_name: "Wrapped Ether (WETH)".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x4200000000000000000000000000000000000006".to_string(),
            entity_name: "Base Wrapped Ether (WETH)".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x6b175474e89094c44da98b954eedeac495271d0f".to_string(),
            entity_name: "Dai Stablecoin (DAI)".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad".to_string(),
            entity_name: "Uniswap Universal Router".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b".to_string(),
            entity_name: "Uniswap Universal Router V1".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45".to_string(),
            entity_name: "Uniswap SwapRouter02".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x2626664c2603336e57b271c5c0b26f421741e481".to_string(),
            entity_name: "Base Uniswap SwapRouter02".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x000000000022d473030f116ddee9f6b43ac78ba3".to_string(),
            entity_name: "Uniswap Permit2".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x1111111254eeb25477b68fb85ed929f73a960582".to_string(),
            entity_name: "1inch Aggregation Router V5".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x0000000000000068f116a894984e2db1123eb395".to_string(),
            entity_name: "OpenSea Seaport 1.6".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2".to_string(),
            entity_name: "Aave V3 Pool".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0xae7ab96520de3a18e5e111b5eaab095312d7fe84".to_string(),
            entity_name: "Lido stETH".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x28c6c06298d514db089934071355e5743bf21d60".to_string(),
            entity_name: "Binance Hot Wallet 14".to_string(),
            category: EntityCategory::CexOmnibus,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0xdfd5293d8e347dfe59e90efd55b2956a1343963d".to_string(),
            entity_name: "Binance Hot Wallet 16".to_string(),
            category: EntityCategory::CexOmnibus,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0x71660c4005ba85c37ccec55d0c4493e66fe775d3".to_string(),
            entity_name: "Coinbase Omnibus 1".to_string(),
            category: EntityCategory::CexOmnibus,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43".to_string(),
            entity_name: "Coinbase Omnibus 10".to_string(),
            category: EntityCategory::CexOmnibus,
            source_feed: "CANONICAL_REGISTRY".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: true,
            is_sanctioned: false,
        },
        EntityLabel {
            address: "0xd8da6bf26964af9d7eed9e03e53415d37aa96045".to_string(),
            entity_name: "vitalik.eth".to_string(),
            category: EntityCategory::VerifiedProtocol,
            source_feed: "ENS_VERIFIED".to_string(),
            severity_weight: 0.0,
            is_omnibus_sink: false,
            is_sanctioned: false,
        },
    ];

    let contracts: Vec<ContractArtifact> = labels
        .iter()
        .filter(|l| {
            matches!(
                l.category,
                EntityCategory::VerifiedProtocol
                    | EntityCategory::DexPool
                    | EntityCategory::CanonicalBridge
            )
        })
        .map(|l| ContractArtifact {
            chain_id: 1,
            address: l.address.clone(),
            bytecode_hash: "0xverified".to_string(),
            deployer: "0x0000000000000000000000000000000000000000".to_string(),
            age_hours: 24_000.0,
            is_eoa: false,
            is_verified: true,
            deployed_via_create2: false,
            factory_has_selfdestruct_history: false,
            is_whitelisted_proxy_target: true,
        })
        .collect();

    (labels, contracts)
}

#[derive(Deserialize)]
struct RawThreatIntelEntry {
    address: String,
    name: String,
    category: String,
    source: String,
}

pub fn load_threat_intel_map() -> std::collections::HashMap<String, EntityLabel> {
    let raw_json = include_str!("../data/threat_intel.json");
    let entries: Vec<RawThreatIntelEntry> = serde_json::from_str(raw_json).unwrap_or_default();
    let mut map = std::collections::HashMap::with_capacity(entries.len() + 32);

    let (canonical, _) = canonical_entity_registry();
    for lbl in canonical {
        map.insert(normalize_address(&lbl.address), lbl);
    }

    for entry in entries {
        let addr = normalize_address(&entry.address);
        let cat = match entry.category.as_str() {
            "WalletDrainer" => EntityCategory::WalletDrainer,
            "Exploiter" => EntityCategory::Exploiter,
            "Sanctioned" => EntityCategory::Sanctioned,
            _ => EntityCategory::Phishing,
        };
        let is_sanc = matches!(cat, EntityCategory::Sanctioned);
        map.entry(addr.clone()).or_insert(EntityLabel {
            address: addr,
            entity_name: entry.name,
            category: cat,
            source_feed: entry.source,
            severity_weight: 0.96,
            is_omnibus_sink: false,
            is_sanctioned: is_sanc,
        });
    }
    map
}

pub fn lookup_entity_name(address: &str, labels: &[EntityLabel]) -> Option<String> {
    let norm = normalize_address(address);
    labels
        .iter()
        .find(|l| normalize_address(&l.address) == norm)
        .map(|l| l.entity_name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mk_block(num: u64, hash: &str, parent: &str) -> IngestedBlock {
        IngestedBlock {
            chain_id: 1,
            number: num,
            hash: hash.to_string(),
            parent_hash: parent.to_string(),
            timestamp_sec: 1_730_000_000 + num * 12,
            transactions: Vec::new(),
        }
    }

    #[test]
    fn handles_three_block_reorg_with_exact_collapsing_state_convergence() {
        let mut tracker = CanonicalChainTracker::new(1, 64, 4, 8);
        let mut clickhouse_collapsed: HashMap<(u64, String), i64> = HashMap::new();

        let mut apply_to_olap = |muts: Vec<VersionedBlockMutation>| {
            for m in muts {
                *clickhouse_collapsed
                    .entry((m.block_number, m.block_hash))
                    .or_insert(0) += m.sign as i64;
            }
        };

        apply_to_olap(tracker.apply_block(mk_block(100, "0xh100", "0xh99")).unwrap());
        apply_to_olap(
            tracker
                .apply_block(mk_block(101, "0xh101a", "0xh100"))
                .unwrap(),
        );
        apply_to_olap(
            tracker
                .apply_block(mk_block(102, "0xh102a", "0xh101a"))
                .unwrap(),
        );
        apply_to_olap(
            tracker
                .apply_block(mk_block(103, "0xh103a", "0xh102a"))
                .unwrap(),
        );

        let reorg_muts = tracker
            .apply_block(mk_block(101, "0xh101b", "0xh100"))
            .unwrap();
        assert_eq!(reorg_muts.iter().filter(|m| m.sign == -1).count(), 3);
        assert_eq!(reorg_muts.iter().filter(|m| m.sign == 1).count(), 1);
        apply_to_olap(reorg_muts);

        apply_to_olap(
            tracker
                .apply_block(mk_block(102, "0xh102b", "0xh101b"))
                .unwrap(),
        );
        apply_to_olap(
            tracker
                .apply_block(mk_block(103, "0xh103b", "0xh102b"))
                .unwrap(),
        );
        apply_to_olap(
            tracker
                .apply_block(mk_block(104, "0xh104b", "0xh103b"))
                .unwrap(),
        );

        let active_blocks: Vec<(u64, String)> = clickhouse_collapsed
            .into_iter()
            .filter(|(_, net_sign)| *net_sign > 0)
            .map(|(k, _)| k)
            .collect();

        assert_eq!(active_blocks.len(), 5);
        assert!(active_blocks.contains(&(100, "0xh100".to_string())));
        assert!(active_blocks.contains(&(101, "0xh101b".to_string())));
        assert!(active_blocks.contains(&(104, "0xh104b".to_string())));
        assert!(!active_blocks.iter().any(|(_, h)| h.ends_with('a')));
    }

    async fn spawn_mock_http_sequence(responses: Vec<&'static str>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for raw_http in responses {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(raw_http.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn rpc_call_retries_transient_503_and_returns_result() {
        let url = spawn_mock_http_sequence(vec![
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\n\r\nunavailable",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x10\"}",
        ])
        .await;
        let provider = ManagedJsonRpcProvider::new(url);
        let latest = provider.get_latest_block_number().await.unwrap();
        assert_eq!(latest, 16);
    }

    #[tokio::test]
    async fn rpc_call_returns_rate_limited_after_exhausting_429_retries() {
        let resp429 = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 10\r\n\r\nrate_limit";
        let url = spawn_mock_http_sequence(vec![resp429, resp429, resp429]).await;
        let provider = ManagedJsonRpcProvider::new(url);
        let err = provider.get_latest_block_number().await.unwrap_err();
        assert!(matches!(err, IndexerError::RateLimited));
    }

    #[tokio::test]
