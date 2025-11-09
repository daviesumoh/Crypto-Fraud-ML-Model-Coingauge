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

