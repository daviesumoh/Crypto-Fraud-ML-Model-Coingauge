pub mod storage;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, patch, post},
    Json, Router,
};
use chain_indexer::{
    canonical_entity_registry, decode_method_selector, load_threat_intel_map, lookup_entity_name,
    CanonicalChainTracker, ManagedJsonRpcProvider,
};
use chrono::Utc;
use common_types::{
    CanonicalTransaction, CompositeRiskReport, ContractArtifact, EntityLabel,
    EvaluateTransactionRequest, EvaluateWalletRequest, ForensicBrief, HeuristicFinding,
    ModelPredictionBundle, ShapAttribution,
};
use evm_simulator::EvmStateSimulator;
use heuristics_engine::{
    CompositeRiskScorer, HeuristicEvaluationContext, HeuristicsEngine, TaintExposureSummary,
};
use serde::{Deserialize, Serialize};
use storage::{
    AlertRecord, DisputeRecord, JsonlStore, MAX_PERSISTED_ALERTS, MAX_PERSISTED_DISPUTES,
};
use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeSubmission {
    pub evaluation_id: Option<Uuid>,
    pub chain_id: u64,
    pub address: String,
    pub proposed_label: String,
    pub analyst_notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    pub chain_id: u64,
    pub chain_name: String,
    pub provider_type: String,
    pub endpoint_masked: String,
    pub latest_block: u64,
    pub txs_evaluated: usize,
    pub threats_flagged: usize,
    pub last_update_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MlSidecarTelemetry {
    pub connected: bool,
    pub onnx_active: bool,
    pub model_artifact: String,
    pub bytecode_signature_count: usize,
    pub holdout_metrics: std::collections::HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamStatusResponse {
    pub live_connected: bool,
    pub eth_price_usd: f64,
    pub total_evaluated: usize,
    pub total_threats: usize,
    pub threat_intel_count: usize,
    pub verified_contract_count: usize,
    pub dispute_count: usize,
    pub ml_telemetry: MlSidecarTelemetry,
    pub chains: Vec<ChainStatus>,
}

#[derive(Clone)]
pub struct LiveStreamHub {
    pub chains: Arc<RwLock<Vec<ChainStatus>>>,
    pub recent_live_reports: Arc<RwLock<VecDeque<CompositeRiskReport>>>,
    pub persistent_alerts: Arc<RwLock<VecDeque<AlertRecord>>>,
    pub broadcast_tx: tokio::sync::broadcast::Sender<CompositeRiskReport>,
}

impl LiveStreamHub {
    pub fn new(initial_alerts: VecDeque<AlertRecord>) -> Self {
        let (broadcast_tx, _) = tokio::sync::broadcast::channel(200);
        Self {
            chains: Arc::new(RwLock::new(Vec::new())),
            recent_live_reports: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            persistent_alerts: Arc::new(RwLock::new(initial_alerts)),
            broadcast_tx,
        }
    }
}

impl Default for LiveStreamHub {
    fn default() -> Self {
        Self::new(VecDeque::with_capacity(MAX_PERSISTED_ALERTS))
    }
}

#[derive(Debug, Clone)]
pub struct CachedWalletState {
    pub balance_wei: u128,
    pub tx_count: u64,
    pub bytecode: String,
    pub cached_at: Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub simulator: EvmStateSimulator,
    pub heuristics: HeuristicsEngine,
    pub scorer: CompositeRiskScorer,
    pub ml_service_url: String,
    pub http_client: reqwest::Client,
    pub entity_labels: Arc<Vec<EntityLabel>>,
    pub threat_intel_map: Arc<std::collections::HashMap<String, EntityLabel>>,
    pub verified_contracts: Arc<Vec<ContractArtifact>>,
    pub eth_price_usd: Arc<RwLock<f64>>,
    pub last_eth_price_fetch: Arc<RwLock<Option<Instant>>>,
    pub audit_log: Arc<RwLock<VecDeque<CompositeRiskReport>>>,
    pub wallet_cache: Arc<RwLock<std::collections::HashMap<String, CachedWalletState>>>,
    pub code_cache: Arc<RwLock<std::collections::HashMap<String, (String, u128, Instant)>>>,
    pub ml_health_cache: Arc<RwLock<Option<(MlSidecarTelemetry, Instant)>>>,
    pub disputes: Arc<RwLock<Vec<DisputeRecord>>>,
    pub live_stream: Arc<LiveStreamHub>,
    pub store: JsonlStore,
    pub persist_lock: Arc<Mutex<()>>,
}

impl AppState {
    pub fn new(ml_service_url: impl Into<String>) -> Self {
        load_dotenv();
        let data_dir = std::env::var("SENTINEL_DATA_DIR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data"));
        Self::new_with_store(ml_service_url, JsonlStore::new(data_dir))
    }

    pub fn new_with_data_dir(ml_service_url: impl Into<String>, data_dir: PathBuf) -> Self {
        Self::new_with_store(ml_service_url, JsonlStore::new(data_dir))
    }

    pub fn new_ephemeral(ml_service_url: impl Into<String>) -> Self {
        Self::new_with_store(ml_service_url, JsonlStore::ephemeral())
    }

    pub fn new_with_store(ml_service_url: impl Into<String>, store: JsonlStore) -> Self {
        load_dotenv();
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_millis(1500))
            .build()
            .unwrap_or_default();
        let (labels, contracts) = canonical_entity_registry();
        let threat_intel = load_threat_intel_map();
        let initial_alerts = store.load_alerts();
        let initial_disputes = store.load_disputes();

        Self {
            simulator: EvmStateSimulator::new(2650.0),
            heuristics: HeuristicsEngine::new(),
            scorer: CompositeRiskScorer::default(),
            ml_service_url: ml_service_url.into(),
            http_client,
            entity_labels: Arc::new(labels),
            threat_intel_map: Arc::new(threat_intel),
            verified_contracts: Arc::new(contracts),
            eth_price_usd: Arc::new(RwLock::new(2650.0)),
            last_eth_price_fetch: Arc::new(RwLock::new(None)),
            audit_log: Arc::new(RwLock::new(VecDeque::with_capacity(200))),
            wallet_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            code_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            ml_health_cache: Arc::new(RwLock::new(None)),
            disputes: Arc::new(RwLock::new(initial_disputes)),
            live_stream: Arc::new(LiveStreamHub::new(initial_alerts)),
            store,
            persist_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn refresh_eth_price_if_stale(
        &self,
        provider: &ManagedJsonRpcProvider,
        chain_id: u64,
    ) {
        {
            let guard = self.last_eth_price_fetch.read().await;
            if let Some(ts) = *guard {
                if ts.elapsed() < Duration::from_secs(60) {
                    return;
                }
            }
        }
        if let Some(live_price) = provider.fetch_chainlink_eth_usd_price(chain_id).await {
            *self.eth_price_usd.write().await = live_price;
            *self.last_eth_price_fetch.write().await = Some(Instant::now());
        }
    }

    pub async fn cached_ml_telemetry(&self) -> MlSidecarTelemetry {
        {
            let guard = self.ml_health_cache.read().await;
            if let Some((cached, ts)) = guard.as_ref() {
                if ts.elapsed() < Duration::from_secs(10) {
                    return cached.clone();
                }
            }
        }

        #[derive(Deserialize)]
        struct HealthResp {
            onnx_active: Option<bool>,
            model_artifact: Option<String>,
            bytecode_signature_count: Option<usize>,
            holdout_metrics: Option<std::collections::HashMap<String, f64>>,
        }

        let endpoint = format!("{}/healthz", self.ml_service_url.trim_end_matches('/'));
        let telemetry = match self
            .http_client
            .get(&endpoint)
            .timeout(Duration::from_millis(400))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<HealthResp>().await {
                Ok(parsed) => MlSidecarTelemetry {
                    connected: true,
                    onnx_active: parsed.onnx_active.unwrap_or(false),
                    model_artifact: parsed
                        .model_artifact
                        .unwrap_or_else(|| "unknown".to_string()),
                    bytecode_signature_count: parsed.bytecode_signature_count.unwrap_or(0),
                    holdout_metrics: parsed.holdout_metrics.unwrap_or_default(),
                },
                Err(_) => MlSidecarTelemetry {
                    connected: false,
                    model_artifact: "unavailable".to_string(),
                    ..Default::default()
                },
            },
            _ => MlSidecarTelemetry {
                connected: false,
                model_artifact: "offline".to_string(),
                ..Default::default()
            },
        };

        let mut guard = self.ml_health_cache.write().await;
        *guard = Some((telemetry.clone(), Instant::now()));
        telemetry
    }

    pub async fn cached_target_code(
        &self,
        chain_id: u64,
        provider: &ManagedJsonRpcProvider,
        addr: &str,
    ) -> Option<(String, u128)> {
        let key = format!("{}:{}", chain_id, common_types::normalize_address(addr));
        {
            let guard = self.code_cache.read().await;
            if let Some((c, bal, ts)) = guard.get(&key) {
                if ts.elapsed() < Duration::from_secs(300) {
                    return Some((c.clone(), *bal));
                }
            }
        }
        let code = provider.get_code(addr).await.ok()?;
        let bal = if code.len() > 2 {
            provider.get_balance(addr).await.unwrap_or(0)
        } else {
            0
        };
        let mut guard = self.code_cache.write().await;
        if guard.len() >= 4000 {
            guard.clear();
        }
        guard.insert(key, (code.clone(), bal, Instant::now()));
        Some((code, bal))
    }

    pub fn resolve_entity_name(&self, address: &str) -> Option<String> {
        let norm = common_types::normalize_address(address);
        self.threat_intel_map
            .get(&norm)
            .map(|l| l.entity_name.clone())
            .or_else(|| lookup_entity_name(address, &self.entity_labels))
    }

    pub fn labels_for_addresses(
        &self,
        addresses: &[&str],
        extra: &[EntityLabel],
    ) -> Vec<EntityLabel> {
        let mut combined = (*self.entity_labels).clone();
        for addr in addresses {
            let norm = common_types::normalize_address(addr);
            if let Some(lbl) = self.threat_intel_map.get(&norm) {
                if !combined.iter().any(|existing| common_types::normalize_address(&existing.address) == norm) {
                    combined.push(lbl.clone());
                }
            }
        }
        combined.extend(extra.iter().cloned());
        combined
    }
}

pub fn mask_endpoint(url: &str) -> String {
    if let Some((base, key)) = url.rsplit_once("/v2/") {
        if key.len() > 8 {
            return format!("{}/v2/{}...{}", base, &key[..4], &key[key.len() - 4..]);
        }
    }
    if let Some((base, key)) = url.rsplit_once('/') {
        if key.len() > 16 {
            return format!("{}/{}...{}", base, &key[..4], &key[key.len() - 4..]);
        }
    }
    url.to_string()
}

pub fn load_dotenv() {
    let mut candidates = vec![
        std::path::PathBuf::from("env/.env"),
        std::path::PathBuf::from(".env"),
        std::path::PathBuf::from("../env/.env"),
        std::path::PathBuf::from("../.env"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(std::path::PathBuf::from(home).join(".env"));
    }
    for path in candidates {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    if std::env::var(key).is_err() && !val.is_empty() {
                        std::env::set_var(key, val);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct MlSidecarRequest<'a> {
    subject_address: &'a str,
    chain_id: u64,
    tx_value_usd: f64,
    sender_pre_balance_usd: f64,
    priority_fee_percentile: f64,
    wallet_tx_count: u64,
    young_contract_touch: bool,
    unverified_contract_touch: bool,
    unlimited_approval: bool,
    taint_score: f64,
    peel_or_sybil_flag: bool,
    graph_edge_count: usize,
    calldata_bytes: usize,
    is_contract_interaction: bool,
    triggered_rule_ids: Vec<String>,
    untrusted_metadata_note: Option<&'a str>,
    target_bytecode_hex: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct MlSidecarResponse {
    predictions: ModelPredictionBundle,
    forensic_brief: ForensicBrief,
}

pub fn build_cors_layer() -> CorsLayer {
    let raw = std::env::var("ALLOWED_ORIGINS").unwrap_or_else(|_| {
        "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001"
            .to_string()
    });
    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE])
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/evaluate/transaction", post(evaluate_transaction))
        .route("/v1/evaluate/wallet", post(evaluate_wallet))
        .route("/v1/wallet/inspect", get(inspect_wallet))
        .route("/v1/audit-log", get(get_audit_log))
        .route(
            "/v1/feedback/disputes",
            get(list_disputes).post(submit_dispute),
        )
        .route("/v1/stream/status", get(get_stream_status))
        .route("/v1/stream/latest", get(get_latest_stream))
        .route("/v1/stream/alerts", get(get_stream_alerts))
        .route(
            "/v1/stream/alerts/:evaluation_id",
            patch(update_alert_status),
        )
        .route("/v1/stream/events", get(stream_events))
        .layer(build_cors_layer())
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Json<serde_json::Value> {
    let audit_len = state.audit_log.read().await.len();
    let alerts_len = state.live_stream.persistent_alerts.read().await.len();
    let eth_price = *state.eth_price_usd.read().await;
    Json(serde_json::json!({
        "status": "ok",
        "service": "crypto-risk-analyzer-gateway",
        "eth_price_usd": eth_price,
        "evaluations_served": audit_len,
        "alerts_stored": alerts_len,
    }))
}

async fn evaluate_transaction(
    State(state): State<AppState>,
    Json(req): Json<EvaluateTransactionRequest>,
) -> Result<Json<CompositeRiskReport>, (StatusCode, String)> {
    let start = Instant::now();
    let _sender_clean = common_types::validate_and_normalize_address(&req.transaction.sender)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid sender address: {e}")))?;
    if let Some(rcpt) = &req.transaction.recipient {
        let _ = common_types::validate_and_normalize_address(rcpt)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid recipient address: {e}")))?;
    }

    let mut fetched_bytecode: Option<String> = None;
    let sim = match req.mock_simulation_override.clone() {
        Some(override_sim) => override_sim,
        None => {
            let mut sim_engine = state.simulator.clone();
            let configs = get_chain_configs();
            if let Some(cfg) = configs.iter().find(|c| c.chain_id == req.transaction.chain_id) {
                let provider = ManagedJsonRpcProvider::new(&cfg.rpc_url);
                if let Some(rcpt) = &req.transaction.recipient {
                    if let Some((code, bal)) = state
                        .cached_target_code(req.transaction.chain_id, &provider, rcpt)
                        .await
                    {
                        if code.len() > 2 {
                            fetched_bytecode = Some(code.chars().take(24_576).collect());
                            sim_engine.seed_account(
                                rcpt,
                                evm_simulator::SeededAccount {
                                    balance_wei: bal,
                                    nonce: 1,
                                    bytecode_hex: Some(code),
                                    storage_slots: std::collections::HashMap::new(),
                                },
                            );
                        }
                    }
                }
            }
            sim_engine
                .simulate_transaction(&req.transaction)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        }
    };

    let mut lookup_addrs = vec![req.transaction.sender.as_str()];
    if let Some(r) = &req.transaction.recipient {
        lookup_addrs.push(r.as_str());
    }
    let combined_labels = state.labels_for_addresses(&lookup_addrs, &req.entity_labels);

    let mut combined_contracts = (*state.verified_contracts).clone();
    combined_contracts.extend(req.contract_artifacts.clone());

    let (findings, taint) = state.heuristics.evaluate_all(&HeuristicEvaluationContext {
        subject_address: &req.transaction.sender,
        current_timestamp_sec: req.transaction.timestamp_sec,
        transaction: Some(&req.transaction),
        simulation: Some(&sim),
        wallet_history: &req.wallet_history,
        graph_edges: &req.recent_graph_edges,
        contracts: &combined_contracts,
        entity_labels: &combined_labels,
    });

    let young_touch = req.contract_artifacts.iter().any(|c| c.age_hours < 72.0);
    let unverified_touch = req.contract_artifacts.iter().any(|c| !c.is_verified);
    let unlimited_app = sim.permission_mutations.iter().any(|p| p.is_unlimited);
    let calldata_bytes = req
        .transaction
        .calldata_hex
        .trim_start_matches("0x")
        .len()
        / 2;

    let (ml_preds, brief) = query_ml_or_fallback(
        &state,
        MlSidecarRequest {
            subject_address: &req.transaction.sender,
            chain_id: req.transaction.chain_id,
            tx_value_usd: req.transaction.value_usd,
            sender_pre_balance_usd: req.transaction.sender_pre_balance_usd,
            priority_fee_percentile: req.transaction.block_priority_fee_percentile,
            wallet_tx_count: req.wallet_history.total_tx_count.max(req.transaction.nonce),
            young_contract_touch: young_touch,
            unverified_contract_touch: unverified_touch,
            unlimited_approval: unlimited_app,
            taint_score: taint.max_taint_score,
            peel_or_sybil_flag: findings
                .iter()
                .any(|f| f.rule_id == "H-GRF-01" || f.rule_id == "H-GRF-02"),
            graph_edge_count: req.recent_graph_edges.len(),
            calldata_bytes,
            is_contract_interaction: calldata_bytes > 0,
            triggered_rule_ids: findings.iter().map(|f| f.rule_id.clone()).collect(),
            untrusted_metadata_note: req.untrusted_metadata_note.as_deref(),
            target_bytecode_hex: fetched_bytecode.as_deref(),
        },
        &findings,
        &taint,
    )
    .await;

    let (selector, decoded_fn) = decode_method_selector(&req.transaction.calldata_hex);
    let total_latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut report = state.scorer.score(
        "PRE_SIGN_TX",
        req.transaction.chain_id,
        &req.transaction.sender,
        req.transaction.recipient.clone(),
        req.wallet_history.total_tx_count.max(req.transaction.nonce),
        findings,
        &taint,
        Some(sim),
        ml_preds,
        Some(brief),
        total_latency_ms,
    );
    report.block_number = Some(req.transaction.block_number);
    report.tx_hash = Some(req.transaction.tx_hash.clone());
    report.method_selector = Some(selector);
    report.decoded_function = Some(decoded_fn);
    report.tx_value_native = Some(req.transaction.value_wei as f64 / 1e18);
    report.tx_value_usd = Some(req.transaction.value_usd);
    report.gas_price_gwei = Some(req.transaction.max_fee_per_gas_wei as f64 / 1e9);
    report.subject_label = lookup_entity_name(&req.transaction.sender, &combined_labels);
    report.counterparty_label = req
        .transaction
        .recipient
        .as_deref()
        .and_then(|r| lookup_entity_name(r, &combined_labels));

    append_audit(&state, report.clone()).await;
    Ok(Json(report))
}

#[derive(Debug, Deserialize)]
pub struct InspectWalletQuery {
    pub address: String,
    pub chain_id: Option<u64>,
}

async fn inspect_wallet(
    State(state): State<AppState>,
    Query(query): Query<InspectWalletQuery>,
) -> Result<Json<CompositeRiskReport>, (StatusCode, String)> {
    let start = Instant::now();
    let clean_addr = common_types::validate_and_normalize_address(&query.address)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid address: {e}")))?;

    let target_chain_id = query.chain_id.unwrap_or(1);
    let configs = get_chain_configs();
    let rpc_config = configs
        .iter()
        .find(|c| c.chain_id == target_chain_id)
        .or_else(|| configs.first())
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "No RPC configured".to_string()))?;

    let provider = ManagedJsonRpcProvider::new(&rpc_config.rpc_url);

    state
        .refresh_eth_price_if_stale(&provider, target_chain_id)
        .await;
    let eth_price = *state.eth_price_usd.read().await;

    let cache_key = format!("{}:{}", target_chain_id, clean_addr);
    let cached_state = {
        let cache = state.wallet_cache.read().await;
        cache.get(&cache_key).and_then(|entry| {
            if entry.cached_at.elapsed() < Duration::from_secs(30) {
                Some((entry.balance_wei, entry.tx_count, entry.bytecode.clone()))
            } else {
                None
            }
        })
    };

    let (balance_wei, tx_count, bytecode) = match cached_state {
        Some(cached) => cached,
        None => {
            let b = provider.get_balance(&clean_addr).await.map_err(|e| match e {
                chain_indexer::IndexerError::RateLimited => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Upstream RPC provider rate limit exceeded (HTTP 429)".to_string(),
                ),
                _ => (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to retrieve balance from RPC: {e}"),
                ),
            })?;

            let c = provider
                .get_transaction_count(&clean_addr)
                .await
                .map_err(|e| match e {
                    chain_indexer::IndexerError::RateLimited => (
                        StatusCode::TOO_MANY_REQUESTS,
                        "Upstream RPC provider rate limit exceeded (HTTP 429)".to_string(),
                    ),
                    _ => (
                        StatusCode::BAD_GATEWAY,
                        format!("Failed to retrieve transaction count from RPC: {e}"),
                    ),
                })?;

            let code = provider
                .get_code(&clean_addr)
                .await
                .unwrap_or_else(|_| "0x".to_string());

            {
                let mut cache = state.wallet_cache.write().await;
                if cache.len() >= 1000 {
                    cache.clear();
                }
                cache.insert(
                    cache_key,
                    CachedWalletState {
                        balance_wei: b,
                        tx_count: c,
                        bytecode: code.clone(),
                        cached_at: Instant::now(),
                    },
                );
            }
            (b, c, code)
        }
    };

    let is_contract = bytecode.trim().len() > 2;
    let graph_edges = provider
        .fetch_alchemy_asset_transfers(&clean_addr, eth_price)
        .await;

    let balance_eth = (balance_wei as f64) / 1e18;
    let balance_usd = balance_eth * eth_price;

    let mut contracts = (*state.verified_contracts).clone();
    let is_known_verified = state
        .verified_contracts
        .iter()
        .any(|c| common_types::normalize_address(&c.address) == clean_addr);

    if is_contract && !is_known_verified {
        contracts.push(ContractArtifact {
            chain_id: target_chain_id,
            address: clean_addr.clone(),
            bytecode_hash: format!("0x{:x}", bytecode.len()),
            deployer: "0x0000000000000000000000000000000000000000".to_string(),
            age_hours: if tx_count > 50 { 720.0 } else { 24.0 },
            is_eoa: false,
            is_verified: false,
            deployed_via_create2: false,
            factory_has_selfdestruct_history: false,
            is_whitelisted_proxy_target: false,
        });
    }

    let mut inspect_addrs: Vec<&str> = vec![clean_addr.as_str()];
    for edge in &graph_edges {
        inspect_addrs.push(edge.from.as_str());
        inspect_addrs.push(edge.to.as_str());
    }
    let inspect_labels = state.labels_for_addresses(&inspect_addrs, &[]);

    let (findings, taint) = state.heuristics.evaluate_all(&HeuristicEvaluationContext {
        subject_address: &clean_addr,
        current_timestamp_sec: Utc::now().timestamp() as u64,
        transaction: None,
        simulation: None,
        wallet_history: &common_types::WalletHistoryContext {
            total_tx_count: tx_count,
            frequent_counterparties: Vec::new(),
            prior_zero_or_dust_senders: Vec::new(),
        },
        graph_edges: &graph_edges,
        contracts: &contracts,
        entity_labels: &inspect_labels,
    });

    let truncated_code: Option<String> = if is_contract {
        Some(bytecode.chars().take(24_576).collect())
    } else {
        None
    };

    let (ml_preds, brief) = query_ml_or_fallback(
        &state,
        MlSidecarRequest {
            subject_address: &clean_addr,
            chain_id: target_chain_id,
            tx_value_usd: 0.0,
            sender_pre_balance_usd: balance_usd.max(100.0),
            priority_fee_percentile: 45.0,
            wallet_tx_count: tx_count.max(1),
            young_contract_touch: is_contract && !is_known_verified && tx_count <= 5,
            unverified_contract_touch: is_contract && !is_known_verified,
            unlimited_approval: false,
            taint_score: taint.max_taint_score,
            peel_or_sybil_flag: findings
                .iter()
                .any(|f| f.rule_id == "H-GRF-01" || f.rule_id == "H-GRF-02"),
            graph_edge_count: graph_edges.len(),
            calldata_bytes: 0,
            is_contract_interaction: is_contract,
            triggered_rule_ids: findings.iter().map(|f| f.rule_id.clone()).collect(),
            untrusted_metadata_note: None,
            target_bytecode_hex: truncated_code.as_deref(),
        },
        &findings,
        &taint,
    )
    .await;

    let total_latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut report = state.scorer.score(
        "WALLET_INSPECTION",
        target_chain_id,
        &clean_addr,
        taint.nearest_illicit_address.clone(),
        tx_count.max(1),
        findings,
        &taint,
        None,
        ml_preds,
        Some(brief),
        total_latency_ms,
    );
    report.tx_value_native = Some(balance_eth);
    report.tx_value_usd = Some(balance_usd);
    report.decoded_function = Some(if is_contract {
        format!("Contract ({} bytes)", bytecode.len().saturating_sub(2) / 2)
    } else {
        format!("EOA (nonce {})", tx_count)
    });
    report.subject_label = state.resolve_entity_name(&clean_addr);
    report.counterparty_label = report
        .counterparty_address
        .as_deref()
        .and_then(|c| state.resolve_entity_name(c));

    append_audit(&state, report.clone()).await;
    Ok(Json(report))
}

async fn evaluate_wallet(
    State(state): State<AppState>,
    Json(req): Json<EvaluateWalletRequest>,
) -> Result<Json<CompositeRiskReport>, (StatusCode, String)> {
    let start = Instant::now();
    let _wallet_clean = common_types::validate_and_normalize_address(&req.wallet_address)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid wallet address: {e}")))?;
    let latest_tx = req.recent_transactions.last();

    let mut w_addrs: Vec<&str> = vec![req.wallet_address.as_str()];
    for edge in &req.graph_edges {
        w_addrs.push(edge.from.as_str());
        w_addrs.push(edge.to.as_str());
    }
    let combined_labels = state.labels_for_addresses(&w_addrs, &req.entity_labels);

    let mut combined_contracts = (*state.verified_contracts).clone();
    combined_contracts.extend(req.contract_artifacts.clone());

    let (findings, taint) = state.heuristics.evaluate_all(&HeuristicEvaluationContext {
        subject_address: &req.wallet_address,
        current_timestamp_sec: req.current_timestamp_sec,
        transaction: latest_tx,
        simulation: None,
        wallet_history: &req.wallet_history,
        graph_edges: &req.graph_edges,
        contracts: &combined_contracts,
        entity_labels: &combined_labels,
    });

    let total_vol: f64 = req.recent_transactions.iter().map(|t| t.value_usd).sum();
    let max_prio = req
        .recent_transactions
        .iter()
        .map(|t| t.block_priority_fee_percentile)
        .fold(45.0, f64::max);

    let (ml_preds, brief) = query_ml_or_fallback(
        &state,
        MlSidecarRequest {
            subject_address: &req.wallet_address,
            chain_id: req.chain_id,
            tx_value_usd: total_vol,
            sender_pre_balance_usd: latest_tx
                .map(|t| t.sender_pre_balance_usd)
                .unwrap_or(10_000.0),
            priority_fee_percentile: max_prio,
            wallet_tx_count: req.wallet_history.total_tx_count,
            young_contract_touch: req.contract_artifacts.iter().any(|c| c.age_hours < 72.0),
            unverified_contract_touch: req.contract_artifacts.iter().any(|c| !c.is_verified),
            unlimited_approval: false,
            taint_score: taint.max_taint_score,
            peel_or_sybil_flag: findings
                .iter()
                .any(|f| f.rule_id == "H-GRF-01" || f.rule_id == "H-GRF-02"),
            graph_edge_count: req.graph_edges.len(),
            calldata_bytes: 0,
            is_contract_interaction: req.target_bytecode_hex.is_some(),
            triggered_rule_ids: findings.iter().map(|f| f.rule_id.clone()).collect(),
            untrusted_metadata_note: None,
            target_bytecode_hex: req.target_bytecode_hex.as_deref(),
        },
        &findings,
        &taint,
    )
    .await;

    let total_latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut report = state.scorer.score(
        "POST_TX_KYT",
        req.chain_id,
        &req.wallet_address,
        None,
        req.wallet_history.total_tx_count,
        findings,
        &taint,
        None,
        ml_preds,
        Some(brief),
        total_latency_ms,
    );
    report.subject_label = lookup_entity_name(&req.wallet_address, &combined_labels);

    append_audit(&state, report.clone()).await;
    Ok(Json(report))
}

async fn get_audit_log(State(state): State<AppState>) -> Json<Vec<CompositeRiskReport>> {
    let guard = state.audit_log.read().await;
    Json(guard.iter().rev().take(50).cloned().collect())
}

async fn list_disputes(State(state): State<AppState>) -> Json<Vec<DisputeRecord>> {
    let guard = state.disputes.read().await;
    Json(guard.iter().rev().cloned().collect())
}

async fn submit_dispute(
    State(state): State<AppState>,
    Json(sub): Json<DisputeSubmission>,
) -> Result<Json<DisputeRecord>, (StatusCode, String)> {
    let address = common_types::validate_and_normalize_address(&sub.address)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid dispute address: {e}")))?;

    let proposed_label = sub.proposed_label.trim().to_string();
    if proposed_label.is_empty() || proposed_label.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proposed_label must be between 1 and 64 characters".to_string(),
        ));
    }

    let analyst_notes = sub.analyst_notes.trim().to_string();
    if analyst_notes.is_empty() || analyst_notes.len() > 1000 {
        return Err((
            StatusCode::BAD_REQUEST,
            "analyst_notes must be between 1 and 1000 characters".to_string(),
        ));
    }

    let record = DisputeRecord {
        dispute_id: Uuid::new_v4(),
        evaluation_id: sub.evaluation_id,
        chain_id: sub.chain_id,
        address,
        proposed_label,
        analyst_notes,
        status: "PENDING".to_string(),
        created_at: Utc::now(),
    };

    {
        let mut guard = state.disputes.write().await;
        if guard.len() >= MAX_PERSISTED_DISPUTES {
            let overflow = guard.len() + 1 - MAX_PERSISTED_DISPUTES;
            guard.drain(0..overflow);
        }
        guard.push(record.clone());
    }
    persist_disputes(&state).await;
    Ok(Json(record))
}

async fn persist_disputes(state: &AppState) {
    let _guard = state.persist_lock.lock().await;
    let snapshot: Vec<DisputeRecord> = state.disputes.read().await.clone();
    let store = state.store.clone();
    if let Err(err) = tokio::task::spawn_blocking(move || store.save_disputes(&snapshot)).await {
        tracing::warn!("Failed to persist disputes task: {err}");
    }
}

async fn persist_alerts(state: &AppState) {
    let _guard = state.persist_lock.lock().await;
    let snapshot: Vec<AlertRecord> = state
        .live_stream
        .persistent_alerts
        .read()
        .await
        .iter()
        .cloned()
        .collect();
    let store = state.store.clone();
    if let Err(err) = tokio::task::spawn_blocking(move || store.save_alerts(&snapshot)).await {
        tracing::warn!("Failed to persist alerts task: {err}");
    }
}

pub async fn record_persistent_alert(state: &AppState, report: CompositeRiskReport) {
    if report.risk_score < 25 {
        return;
    }
    let record = AlertRecord {
        evaluation_id: report.evaluation_id,
        triage_status: "OPEN".to_string(),
        updated_at: Utc::now(),
        report,
    };

    {
        let mut guard = state.live_stream.persistent_alerts.write().await;
        if let Some(txh) = &record.report.tx_hash {
            if guard
                .iter()
                .any(|existing| existing.report.tx_hash.as_deref() == Some(txh.as_str()))
            {
                return;
            }
        }
        if guard.len() >= MAX_PERSISTED_ALERTS {
            guard.pop_back();
        }
        guard.push_front(record);
    }
    persist_alerts(state).await;
}

async fn append_audit(state: &AppState, report: CompositeRiskReport) {
    let mut guard = state.audit_log.write().await;
    if guard.len() >= 200 {
        guard.pop_front();
    }
    guard.push_back(report);
}

async fn get_stream_status(State(state): State<AppState>) -> Json<StreamStatusResponse> {
    let chains = state.live_stream.chains.read().await.clone();
    let total_eval: usize = chains.iter().map(|c| c.txs_evaluated).sum();
    let total_threats: usize = chains.iter().map(|c| c.threats_flagged).sum();
    let live_connected = !chains.is_empty();
    let eth_price_usd = *state.eth_price_usd.read().await;
    let dispute_count = state.disputes.read().await.len();
    let ml_telemetry = state.cached_ml_telemetry().await;
    Json(StreamStatusResponse {
        live_connected,
        eth_price_usd,
        total_evaluated: total_eval,
        total_threats,
        threat_intel_count: state.threat_intel_map.len(),
        verified_contract_count: state.verified_contracts.len(),
        dispute_count,
        ml_telemetry,
        chains,
    })
}

async fn get_latest_stream(State(state): State<AppState>) -> Json<Vec<CompositeRiskReport>> {
    let guard = state.live_stream.recent_live_reports.read().await;
    Json(guard.iter().take(100).cloned().collect())
}

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub chain_id: Option<u64>,
    pub tier: Option<String>,
    pub status: Option<String>,
}

async fn get_stream_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertsQuery>,
) -> Json<Vec<AlertRecord>> {
    let guard = state.live_stream.persistent_alerts.read().await;
    let tier_filter = query.tier.map(|t| t.trim().to_ascii_uppercase());
    let status_filter = query.status.map(|s| s.trim().to_ascii_uppercase());

    let filtered: Vec<AlertRecord> = guard
        .iter()
        .filter(|alert| {
            if let Some(cid) = query.chain_id {
                if alert.report.chain_id != cid {
                    return false;
                }
            }
            if let Some(ref tier) = tier_filter {
                if !tier.is_empty() && tier != "ALL" {
                    let report_tier = format!("{:?}", alert.report.risk_tier).to_ascii_uppercase();
                    if report_tier != *tier {
                        return false;
                    }
                }
            }
            if let Some(ref st) = status_filter {
                if !st.is_empty() && st != "ALL" && alert.triage_status != *st {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();
    Json(filtered)
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertStatusRequest {
    pub triage_status: String,
}

async fn update_alert_status(
    State(state): State<AppState>,
    Path(evaluation_id): Path<Uuid>,
    Json(req): Json<UpdateAlertStatusRequest>,
) -> Result<Json<AlertRecord>, (StatusCode, String)> {
    let status_norm = req.triage_status.trim().to_ascii_uppercase();
    if !matches!(
        status_norm.as_str(),
        "OPEN" | "ACKNOWLEDGED" | "FALSE_POSITIVE" | "CONFIRMED"
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "triage_status must be one of OPEN, ACKNOWLEDGED, FALSE_POSITIVE, CONFIRMED"
                .to_string(),
        ));
    }

    let updated_record = {
        let mut guard = state.live_stream.persistent_alerts.write().await;
        let item = guard
            .iter_mut()
            .find(|a| a.evaluation_id == evaluation_id)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("Alert {evaluation_id} not found"),
                )
            })?;
        item.triage_status = status_norm;
        item.updated_at = Utc::now();
        item.clone()
    };

    persist_alerts(&state).await;
    Ok(Json(updated_record))
}

async fn stream_events(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.live_stream.broadcast_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(report) => {
            let data = serde_json::to_string(&report).ok()?;
            Some(Ok(Event::default().data(data)))
        }
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Debug, Clone)]
pub struct ChainWorkerConfig {
    pub chain_id: u64,
    pub chain_name: &'static str,
    pub provider_type: String,
    pub rpc_url: String,
    pub poll_interval: Duration,
}

fn classify_provider(url: &str) -> String {
    if url.contains("alchemy.com") {
        "Alchemy".to_string()
    } else if url.contains("quiknode.pro") || url.contains("quicknode") {
        "QuickNode".to_string()
    } else {
        "Custom JSON-RPC".to_string()
    }
}

pub fn get_chain_configs() -> Vec<ChainWorkerConfig> {
    let env_non_empty = |k: &str| {
        std::env::var(k)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let alchemy_key = env_non_empty("ALCHEMY_API_KEY");

    let eth_config = if let Some(custom) = env_non_empty("ETHEREUM_RPC_URL") {
        ChainWorkerConfig {
            chain_id: 1,
            chain_name: "Ethereum Mainnet",
            provider_type: classify_provider(&custom),
            rpc_url: custom,
            poll_interval: Duration::from_secs(6),
        }
    } else if let Some(qn) = env_non_empty("QUICKNODE_ETHEREUM_URL").or_else(|| env_non_empty("QUICKNODE_URL")) {
        ChainWorkerConfig {
            chain_id: 1,
            chain_name: "Ethereum Mainnet",
            provider_type: "QuickNode".to_string(),
            rpc_url: qn,
            poll_interval: Duration::from_secs(6),
        }
    } else if let Some(key) = &alchemy_key {
        ChainWorkerConfig {
            chain_id: 1,
            chain_name: "Ethereum Mainnet",
            provider_type: "Alchemy".to_string(),
            rpc_url: format!("https://eth-mainnet.g.alchemy.com/v2/{}", key),
            poll_interval: Duration::from_secs(6),
        }
    } else {
        ChainWorkerConfig {
            chain_id: 1,
            chain_name: "Ethereum Mainnet",
            provider_type: "Public JSON-RPC".to_string(),
            rpc_url: "https://ethereum-rpc.publicnode.com".to_string(),
            poll_interval: Duration::from_secs(10),
        }
    };

    let base_config = if let Some(custom) = env_non_empty("BASE_RPC_URL") {
        ChainWorkerConfig {
            chain_id: 8453,
            chain_name: "Base Mainnet",
            provider_type: classify_provider(&custom),
            rpc_url: custom,
            poll_interval: Duration::from_millis(2500),
        }
    } else if let Some(qn) = env_non_empty("QUICKNODE_BASE_URL") {
        ChainWorkerConfig {
            chain_id: 8453,
            chain_name: "Base Mainnet",
            provider_type: "QuickNode".to_string(),
            rpc_url: qn,
            poll_interval: Duration::from_millis(2500),
        }
    } else if let Some(key) = &alchemy_key {
        ChainWorkerConfig {
            chain_id: 8453,
            chain_name: "Base Mainnet",
            provider_type: "Alchemy".to_string(),
            rpc_url: format!("https://base-mainnet.g.alchemy.com/v2/{}", key),
            poll_interval: Duration::from_millis(2500),
        }
    } else {
        ChainWorkerConfig {
            chain_id: 8453,
            chain_name: "Base Mainnet",
            provider_type: "Public JSON-RPC".to_string(),
            rpc_url: "https://mainnet.base.org".to_string(),
            poll_interval: Duration::from_millis(2500),
        }
    };

    vec![base_config, eth_config]
}

pub fn spawn_live_chain_streamers(state: AppState) {
    let configs = get_chain_configs();
    let init_statuses: Vec<ChainStatus> = configs
        .iter()
        .map(|cfg| ChainStatus {
            chain_id: cfg.chain_id,
            chain_name: cfg.chain_name.to_string(),
            provider_type: cfg.provider_type.clone(),
            endpoint_masked: mask_endpoint(&cfg.rpc_url),
            latest_block: 0,
            txs_evaluated: 0,
            threats_flagged: 0,
            last_update_ts: Utc::now().timestamp() as u64,
        })
        .collect();

    let state_for_init = state.clone();
    tokio::spawn(async move {
        *state_for_init.live_stream.chains.write().await = init_statuses;
        for cfg in configs {
            let state_worker = state_for_init.clone();
            tokio::spawn(async move {
                run_chain_poller(state_worker, cfg).await;
            });
        }
    });
}

async fn evaluate_single_stream_transaction(
    state: &AppState,
    cfg: &ChainWorkerConfig,
    provider: &ManagedJsonRpcProvider,
    mut tx: CanonicalTransaction,
) -> CompositeRiskReport {
    let start_tx = Instant::now();
    let mut sim_engine = state.simulator.clone();

    let mut fetched_bytecode: Option<String> = None;
    let mut is_contract_target = false;
    // On-demand bytecode and balance forking from live chain
    if let Some(rcpt) = &tx.recipient {
        if let Some((code, bal)) = state.cached_target_code(cfg.chain_id, provider, rcpt).await {
            if code.len() > 2 {
                is_contract_target = true;
                fetched_bytecode = Some(code.chars().take(24_576).collect());
                sim_engine.seed_account(
                    rcpt,
                    evm_simulator::SeededAccount {
                        balance_wei: bal,
                        nonce: 1,
                        bytecode_hex: Some(code),
                        storage_slots: std::collections::HashMap::new(),
                    },
                );
            }
        }
    }

    let sim_opt = sim_engine.simulate_transaction(&tx).ok();

    if tx.value_usd == 0.0 {
        if let Some(sim) = &sim_opt {
            let sim_usd: f64 = sim
                .asset_movements
                .iter()
                .map(|m| m.amount_usd)
                .fold(0.0, f64::max);
            if sim_usd > 0.0 && sim_usd <= 500_000_000.0 {
                tx.value_usd = sim_usd;
                tx.sender_pre_balance_usd = (sim_usd * 4.0).max(500.0);
            }
        }
    }

    let unlimited_app = sim_opt
        .as_ref()
        .map(|s| s.permission_mutations.iter().any(|p| p.is_unlimited))
        .unwrap_or(false);

    let mut lookup_addrs = vec![tx.sender.as_str()];
    if let Some(r) = &tx.recipient {
        lookup_addrs.push(r.as_str());
    }
    let stream_labels = state.labels_for_addresses(&lookup_addrs, &[]);
    let is_known_verified_rcpt = tx.recipient.as_deref().map(|r| {
        let norm = common_types::normalize_address(r);
        state.verified_contracts.iter().any(|c| common_types::normalize_address(&c.address) == norm)
    }).unwrap_or(false);

    let (findings, taint) = state.heuristics.evaluate_all(&HeuristicEvaluationContext {
        subject_address: &tx.sender,
        current_timestamp_sec: tx.timestamp_sec,
        transaction: Some(&tx),
        simulation: sim_opt.as_ref(),
        wallet_history: &common_types::WalletHistoryContext {
            total_tx_count: tx.nonce.max(1),
            frequent_counterparties: Vec::new(),
            prior_zero_or_dust_senders: Vec::new(),
        },
        graph_edges: &[],
        contracts: &state.verified_contracts,
        entity_labels: &stream_labels,
    });

    let calldata_bytes = tx.calldata_hex.trim_start_matches("0x").len() / 2;

    let (ml_preds, brief) = query_ml_or_fallback(
        state,
        MlSidecarRequest {
            subject_address: &tx.sender,
            chain_id: cfg.chain_id,
            tx_value_usd: tx.value_usd,
            sender_pre_balance_usd: tx.sender_pre_balance_usd,
            priority_fee_percentile: tx.block_priority_fee_percentile,
            wallet_tx_count: tx.nonce.max(1),
            young_contract_touch: false,
            unverified_contract_touch: is_contract_target && !is_known_verified_rcpt,
            unlimited_approval: unlimited_app,
            taint_score: taint.max_taint_score,
            peel_or_sybil_flag: findings
                .iter()
                .any(|f| f.rule_id == "H-GRF-01" || f.rule_id == "H-GRF-02"),
            graph_edge_count: 0,
            calldata_bytes,
            is_contract_interaction: calldata_bytes > 0 || is_contract_target,
            triggered_rule_ids: findings.iter().map(|f| f.rule_id.clone()).collect(),
            untrusted_metadata_note: None,
            target_bytecode_hex: fetched_bytecode.as_deref(),
        },
        &findings,
        &taint,
    )
    .await;

    let (selector, decoded_fn) = decode_method_selector(&tx.calldata_hex);
    let total_tx_latency = start_tx.elapsed().as_secs_f64() * 1000.0;
    let mut report = state.scorer.score(
        "LIVE_STREAM_TX",
        cfg.chain_id,
        &tx.sender,
        tx.recipient.clone(),
        tx.nonce.max(1),
        findings,
        &taint,
        sim_opt,
        ml_preds,
        Some(brief),
        total_tx_latency,
    );
    report.block_number = Some(tx.block_number);
    report.tx_hash = Some(tx.tx_hash.clone());
    report.method_selector = Some(selector);
    report.decoded_function = Some(decoded_fn);
    report.tx_value_native = Some(tx.value_wei as f64 / 1e18);
    report.tx_value_usd = Some(tx.value_usd);
    report.gas_price_gwei = Some(tx.max_fee_per_gas_wei as f64 / 1e9);
    report.subject_label = state.resolve_entity_name(&tx.sender);
    report.counterparty_label = tx
        .recipient
        .as_deref()
        .and_then(|r| state.resolve_entity_name(r));

    report
}

async fn run_chain_poller(state: AppState, cfg: ChainWorkerConfig) {
    let provider = ManagedJsonRpcProvider::new(&cfg.rpc_url);
    let mut last_seen_block: u64 = 0;
    let mut chain_tracker = CanonicalChainTracker::new(cfg.chain_id, 32, 2, 12);

    tracing::info!(
        "Live poller active for {} (id={}) via {} ({})",
        cfg.chain_name,
        cfg.chain_id,
        cfg.provider_type,
        mask_endpoint(&cfg.rpc_url)
    );

    loop {
        state
            .refresh_eth_price_if_stale(&provider, cfg.chain_id)
            .await;
        let eth_price = *state.eth_price_usd.read().await;

        match provider.get_latest_block_number().await {
            Ok(latest) => {
                if last_seen_block == 0 {
                    last_seen_block = latest;
                }

                if latest >= last_seen_block {
                    let fetch_block = last_seen_block;
                    last_seen_block += 1;

                    if latest > last_seen_block + 3 {
                        last_seen_block = latest;
                    }

                    match provider
                        .fetch_ingested_block(cfg.chain_id, fetch_block, eth_price)
                        .await
                    {
                        Ok(block) => {
                            match chain_tracker.apply_block(block.clone()) {
                                Ok(muts) => {
                                    let rolled_back = muts.iter().filter(|m| m.sign < 0).count();
                                    if rolled_back > 0 {
                                        tracing::warn!(
                                            "Chain reorg detected on {} (id={}): rolled back {} block(s)",
                                            cfg.chain_name,
                                            cfg.chain_id,
                                            rolled_back
                                        );
                                    }
                                }
                                Err(chain_indexer::IndexerError::BlockGap { .. })
                                | Err(chain_indexer::IndexerError::DeepReorgExceededWindow(_)) => {
                                    chain_tracker =
                                        CanonicalChainTracker::new(cfg.chain_id, 32, 2, 12);
                                    let _ = chain_tracker.apply_block(block.clone());
                                }
                                Err(e) => {
                                    tracing::debug!("Chain tracker note on {}: {e}", cfg.chain_name);
                                }
                            }

                            let tx_count = block.transactions.len();
                            let mut threats_in_block = 0;

                            let candidates: Vec<_> = block
                                .transactions
                                .into_iter()
                                .filter(|t| t.value_usd > 0.1 || t.calldata_hex.len() >= 10)
                                .collect();

                            let semaphore = Arc::new(tokio::sync::Semaphore::new(16));
                            let mut join_set = tokio::task::JoinSet::new();

                            for tx in candidates {
                                let sem_c = semaphore.clone();
                                let state_c = state.clone();
                                let cfg_c = cfg.clone();
                                let prov_c = provider.clone();
                                join_set.spawn(async move {
                                    let _permit = sem_c.acquire().await.ok()?;
                                    Some(evaluate_single_stream_transaction(&state_c, &cfg_c, &prov_c, tx).await)
                                });
                            }

                            while let Some(res) = join_set.join_next().await {
                                if let Ok(Some(report)) = res {
                                    if report.risk_score >= 25 {
                                        threats_in_block += 1;
                                        record_persistent_alert(&state, report.clone()).await;
                                    }
                                    let _ = state.live_stream.broadcast_tx.send(report.clone());
                                    let mut buffer =
                                        state.live_stream.recent_live_reports.write().await;
                                    if buffer.len() >= 100 {
                                        buffer.pop_back();
                                    }
                                    buffer.push_front(report);
                                }
                            }

                            {
                                let mut chains = state.live_stream.chains.write().await;
                                if let Some(item) =
                                    chains.iter_mut().find(|c| c.chain_id == cfg.chain_id)
                                {
                                    item.latest_block = fetch_block;
                                    item.txs_evaluated += tx_count;
                                    item.threats_flagged += threats_in_block;
                                    item.last_update_ts = Utc::now().timestamp() as u64;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                "Fetch block #{} on {} failed: {}",
                                fetch_block,
                                cfg.chain_name,
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("RPC poll error on {}: {}", cfg.chain_name, e);
            }
        }

        tokio::time::sleep(cfg.poll_interval).await;
    }
}

async fn query_ml_or_fallback(
    state: &AppState,
    payload: MlSidecarRequest<'_>,
    findings: &[HeuristicFinding],
    taint: &TaintExposureSummary,
) -> (ModelPredictionBundle, ForensicBrief) {
    let endpoint = format!("{}/v1/ml/infer", state.ml_service_url.trim_end_matches('/'));
    if let Ok(resp) = state.http_client.post(&endpoint).json(&payload).send().await {
        if resp.status().is_success() {
            if let Ok(parsed) = resp.json::<MlSidecarResponse>().await {
                return (parsed.predictions, parsed.forensic_brief);
            }
        }
    }

    let mut sup: f64 = 0.02;
    let mut anom: f64 = 0.04;
    let mut shap = Vec::new();

    if payload.unlimited_approval && payload.unverified_contract_touch {
        sup += 0.72;
        shap.push(ShapAttribution {
            feature_name: "unlimited_approval_flag".to_string(),
            feature_value: 1.0,
            shap_impact: 0.45,
            direction: "risk_increasing".to_string(),
        });
    }
    if payload.taint_score > 0.1 {
        sup += 0.55 * payload.taint_score;
        shap.push(ShapAttribution {
            feature_name: "multi_hop_haircut_taint".to_string(),
            feature_value: payload.taint_score,
            shap_impact: 0.38 * payload.taint_score,
            direction: "risk_increasing".to_string(),
        });
    }
    if payload.priority_fee_percentile >= 95.0 {
        anom += 0.48;
        shap.push(ShapAttribution {
            feature_name: "priority_fee_percentile_norm".to_string(),
            feature_value: payload.priority_fee_percentile / 100.0,
            shap_impact: 0.25,
            direction: "risk_increasing".to_string(),
        });
    }

    let citations: Vec<String> = findings.iter().map(|f| f.rule_id.clone()).collect();
    let summary = if findings.is_empty() {
        "No deterministic threat rules triggered.".to_string()
    } else {
        format!(
            "Triggered {} security rule(s): {}.",
            findings.len(),
            citations.join(", ")
        )
    };

    let preds = ModelPredictionBundle {
        anomaly_score: anom.clamp(0.01, 0.99),
        supervised_fraud_prob: sup.clamp(0.01, 0.99),
        bytecode_risk_score: 0.0,
        nearest_bytecode_family: None,
        bytecode_similarity: None,
        top_shap_features: shap,
        inference_latency_ms: 0.5,
    };

    let brief = ForensicBrief {
        executive_summary: summary,
        technical_forensics: format!(
            "Max haircut taint={:.2}%, omnibus terminations={}.",
            taint.max_taint_score * 100.0,
            taint.terminated_at_omnibus_sinks
        ),
        recommended_action: if findings.iter().any(|f| f.triggers_critical_veto) {
            "BLOCK_AND_REVOKE".to_string()
        } else if !findings.is_empty() {
            "STEP_UP_WARNING".to_string()
        } else {
            "ALLOW_WITH_MONITORING".to_string()
        },
        evidence_citations: citations,
        prompt_injection_sanitized: false,
    };

    (preds, brief)
}

