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
pub enum EntityCategory {
    Sanctioned,
    WalletDrainer,
    Exploiter,
    Mixer,
    Phishing,
    HoneypotToken,
    SybilCluster,
    CexOmnibus,
    CanonicalBridge,
    DexPool,
    VerifiedProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityLabel {
    pub address: String,
    pub entity_name: String,
    pub category: EntityCategory,
    pub source_feed: String,
    pub severity_weight: f64,
    pub is_omnibus_sink: bool,
    pub is_sanctioned: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub revert_reason: Option<String>,
    pub gas_used: u64,
    pub internal_traces: Vec<InternalCallTrace>,
    pub asset_movements: Vec<AssetMovement>,
    pub permission_mutations: Vec<PermissionMutation>,
    pub env_evasion_opcode_detected: bool,
    pub honeypot_sell_reverted: bool,
    pub observed_sell_tax_pct: f64,
    pub simulation_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphTransferEdge {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub amount_usd: f64,
    pub recipient_post_balance_usd: f64,
    pub timestamp_sec: u64,
    pub selector: String,
    pub recipient_is_fresh_nonce_zero: bool,
    pub recipient_has_outbound_cospend: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalletHistoryContext {
    pub total_tx_count: u64,
    pub frequent_counterparties: Vec<String>,
    pub prior_zero_or_dust_senders: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 0.20,
            Self::Medium => 0.45,
            Self::High => 0.85,
            Self::Critical => 1.60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicFinding {
    pub rule_id: String,
    pub rule_version: String,
    pub title: String,
    pub severity: Severity,
    pub triggers_critical_veto: bool,
    pub description: String,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapAttribution {
    pub feature_name: String,
    pub feature_value: f64,
    pub shap_impact: f64,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPredictionBundle {
    pub anomaly_score: f64,
    pub supervised_fraud_prob: f64,
    #[serde(default, alias = "gnn_cluster_prob")]
    pub bytecode_risk_score: f64,
    pub nearest_bytecode_family: Option<String>,
    pub bytecode_similarity: Option<f64>,
    pub top_shap_features: Vec<ShapAttribution>,
    pub inference_latency_ms: f64,
}

impl Default for ModelPredictionBundle {
    fn default() -> Self {
        Self {
            anomaly_score: 0.04,
            supervised_fraud_prob: 0.02,
            bytecode_risk_score: 0.0,
            nearest_bytecode_family: None,
            bytecode_similarity: None,
            top_shap_features: Vec::new(),
            inference_latency_ms: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyAction {
    Allow,
    Warn,
    Hold,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicBrief {
    pub executive_summary: String,
    pub technical_forensics: String,
    pub recommended_action: String,
    pub evidence_citations: Vec<String>,
    pub prompt_injection_sanitized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleBreakdown {
    pub heuristic_signal: f64,
    pub taint_exposure_signal: f64,
    pub supervised_ml_signal: f64,
    pub bytecode_risk_signal: f64,
    pub anomaly_signal: f64,
    pub raw_ensemble_score: f64,
    pub calibrated_probability: f64,
    pub critical_veto_applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeRiskReport {
    pub evaluation_id: Uuid,
    pub evaluated_at: DateTime<Utc>,
    pub evaluation_mode: String,
    pub chain_id: u64,
    #[serde(default)]
    pub block_number: Option<u64>,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub method_selector: Option<String>,
    #[serde(default)]
    pub decoded_function: Option<String>,
    #[serde(default)]
    pub tx_value_native: Option<f64>,
    #[serde(default)]
    pub tx_value_usd: Option<f64>,
    #[serde(default)]
    pub gas_price_gwei: Option<f64>,
    pub subject_address: String,
    #[serde(default)]
    pub subject_label: Option<String>,
    pub counterparty_address: Option<String>,
    #[serde(default)]
    pub counterparty_label: Option<String>,
    pub risk_score: u8,
    pub risk_tier: RiskTier,
    pub confidence_score: f64,
    pub policy_action: PolicyAction,
    pub ensemble_breakdown: EnsembleBreakdown,
    pub heuristic_findings: Vec<HeuristicFinding>,
    pub simulation_summary: Option<SimulationResult>,
    pub ml_predictions: ModelPredictionBundle,
    pub forensic_brief: Option<ForensicBrief>,
    pub total_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateTransactionRequest {
    pub transaction: CanonicalTransaction,
    #[serde(default)]
    pub wallet_history: WalletHistoryContext,
    #[serde(default)]
    pub recent_graph_edges: Vec<GraphTransferEdge>,
    #[serde(default)]
    pub contract_artifacts: Vec<ContractArtifact>,
    #[serde(default)]
    pub entity_labels: Vec<EntityLabel>,
    #[serde(default)]
    pub untrusted_metadata_note: Option<String>,
    #[serde(default)]
    pub mock_simulation_override: Option<SimulationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateWalletRequest {
    pub chain_id: u64,
    pub wallet_address: String,
    pub current_timestamp_sec: u64,
    #[serde(default)]
    pub wallet_history: WalletHistoryContext,
    #[serde(default)]
    pub recent_transactions: Vec<CanonicalTransaction>,
    #[serde(default)]
    pub graph_edges: Vec<GraphTransferEdge>,
    #[serde(default)]
    pub contract_artifacts: Vec<ContractArtifact>,
    #[serde(default)]
    pub entity_labels: Vec<EntityLabel>,
    #[serde(default)]
    pub target_bytecode_hex: Option<String>,
}

