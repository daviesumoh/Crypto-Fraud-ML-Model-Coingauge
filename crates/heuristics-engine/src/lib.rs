//! Deterministic blockchain heuristics (`H-SIM-01` .. `H-MEM-01`), bounded haircut taint
//! propagation with omnibus-sink termination & dust quarantine, and calibrated `[0, 100]`
//! composite risk scoring.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use common_types::{
    normalize_address, CallType, CanonicalTransaction, CompositeRiskReport, ContractArtifact,
    EnsembleBreakdown, EntityCategory, EntityLabel, ForensicBrief, GraphTransferEdge,
    HeuristicFinding, ModelPredictionBundle, PolicyAction, RiskTier, Severity, SimulationResult,
    WalletHistoryContext,
};
use uuid::Uuid;

/// Taint propagation hyperparameters matching Section 6.1 of the architecture spec.
#[derive(Debug, Clone, Copy)]
pub struct TaintConfig {
    pub max_hops: usize,
    /// Per-hop attenuation factor `\gamma` (default `0.65`).
    pub hop_gamma: f64,
    /// Temporal decay rate `\lambda` per day for non-sanctioned taint (`ln(2)/90` ~ 90d half-life).
    pub daily_decay_lambda: f64,
    /// Minimum USD value required for unsolicited inbound transfers without co-spend (`$5.0`).
    pub dust_quarantine_usd: f64,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            max_hops: 5,
            hop_gamma: 0.65,
            daily_decay_lambda: 0.0077, // ~90-day half-life
            dust_quarantine_usd: 5.0,
        }
    }
}

/// Detailed taint exposure result for an evaluated wallet.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TaintExposureSummary {
    pub max_taint_score: f64,
    pub nearest_illicit_address: Option<String>,
    pub nearest_category: Option<EntityCategory>,
    pub hop_distance: Option<usize>,
    pub direct_sanctioned_touch: bool,
    pub quarantined_dust_edges: usize,
    pub terminated_at_omnibus_sinks: usize,
}

/// Evaluation input bundle shared across Pre-Sign and Post-Tx KYT modes.
pub struct HeuristicEvaluationContext<'a> {
    pub subject_address: &'a str,
    pub current_timestamp_sec: u64,
    pub transaction: Option<&'a CanonicalTransaction>,
    pub simulation: Option<&'a SimulationResult>,
    pub wallet_history: &'a WalletHistoryContext,
    pub graph_edges: &'a [GraphTransferEdge],
    pub contracts: &'a [ContractArtifact],
    pub entity_labels: &'a [EntityLabel],
}

/// Core deterministic heuristics and taint evaluation engine.
#[derive(Debug, Clone, Default)]
pub struct HeuristicsEngine {
    pub taint_config: TaintConfig,
}

impl HeuristicsEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute bounded `k <= 5` hop haircut taint exposure with omnibus-sink termination
    /// and unsolicited inbound dust quarantine.
    pub fn compute_taint_exposure(
        &self,
        subject: &str,
        counterparty: Option<&str>,
        current_ts: u64,
        edges: &[GraphTransferEdge],
        labels: &[EntityLabel],
    ) -> TaintExposureSummary {
        let subject_norm = normalize_address(subject);
        let counterparty_norm = counterparty.map(normalize_address);

        let mut label_map: HashMap<String, &EntityLabel> = HashMap::new();
        for lbl in labels {
            label_map.insert(normalize_address(&lbl.address), lbl);
        }

        let mut summary = TaintExposureSummary::default();

        // Check direct interaction with labeled entity (distance = 0 or 1)
        for candidate in [Some(subject_norm.as_str()), counterparty_norm.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(lbl) = label_map.get(candidate) {
                if lbl.severity_weight > 0.0 && !lbl.is_omnibus_sink {
                    let hop = if candidate == subject_norm { 0 } else { 1 };
                    let score = if hop == 0 {
                        lbl.severity_weight
                    } else {
                        lbl.severity_weight * self.taint_config.hop_gamma.max(0.85)
                    };
                    if score > summary.max_taint_score {
                        summary.max_taint_score = score;
                        summary.nearest_illicit_address = Some(lbl.address.clone());
                        summary.nearest_category = Some(lbl.category);
                        summary.hop_distance = Some(hop);
                    }
                    if lbl.is_sanctioned || lbl.category == EntityCategory::WalletDrainer {
                        summary.direct_sanctioned_touch = true;
                    }
                }
            }
        }

        if edges.is_empty() {
            return summary;
        }

