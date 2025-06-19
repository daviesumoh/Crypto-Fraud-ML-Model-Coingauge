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

        // Build forward adjacency list for multi-hop path search from malicious sources `v -> ... -> subject`
        let mut adj: HashMap<String, Vec<&GraphTransferEdge>> = HashMap::new();
        for edge in edges {
            adj.entry(normalize_address(&edge.from))
                .or_default()
                .push(edge);
        }

        // Bounded DFS seeded only from malicious sources present in the subgraph edges
        for (src_addr, _) in &adj {
            let Some(src_lbl) = label_map.get(src_addr.as_str()) else {
                continue;
            };
            if src_lbl.severity_weight <= 0.0 || src_lbl.is_omnibus_sink {
                continue;
            }

            let mut stack: Vec<(String, usize, f64, u64, HashSet<String>)> = Vec::new();
            let mut visited_init = HashSet::new();
            visited_init.insert(src_addr.clone());
            stack.push((src_addr.clone(), 0, 1.0, current_ts, visited_init));

            while let Some((curr, hops, flow_product, earliest_ts, visited)) = stack.pop() {
                if hops >= self.taint_config.max_hops {
                    continue;
                }
                if let Some(out_edges) = adj.get(&curr) {
                    for edge in out_edges {
                        let next = normalize_address(&edge.to);
                        if visited.contains(&next) {
                            continue;
                        }

                        // Quarantine unsolicited inbound dust to target when there is zero co-spend
                        if next == subject_norm
                            && edge.amount_usd < self.taint_config.dust_quarantine_usd
                            && !edge.recipient_has_outbound_cospend
                        {
                            summary.quarantined_dust_edges += 1;
                            continue;
                        }

                        let haircut = if edge.recipient_post_balance_usd > 0.0 {
                            (edge.amount_usd / edge.recipient_post_balance_usd).clamp(0.0, 1.0)
                        } else {
                            1.0
                        };
                        let next_flow = flow_product * haircut;
                        let next_hops = hops + 1;
                        let path_ts = earliest_ts.min(edge.timestamp_sec);

                        if next == subject_norm
                            || counterparty_norm.as_deref() == Some(next.as_str())
                        {
                            let age_days =
                                (current_ts.saturating_sub(path_ts) as f64) / 86_400.0;
                            let time_decay = if src_lbl.is_sanctioned {
                                1.0 // Sanctioned exposure does not expire via short time decay
                            } else {
                                (-self.taint_config.daily_decay_lambda * age_days).exp()
                            };
                            let hop_atten = self.taint_config.hop_gamma.powi(next_hops as i32);
                            let candidate_taint =
                                src_lbl.severity_weight * hop_atten * time_decay * next_flow;

                            if candidate_taint > summary.max_taint_score {
                                summary.max_taint_score = candidate_taint;
                                summary.nearest_illicit_address = Some(src_lbl.address.clone());
                                summary.nearest_category = Some(src_lbl.category);
                                summary.hop_distance = Some(next_hops);
                            }
                            if next_hops == 1 && src_lbl.is_sanctioned {
                                summary.direct_sanctioned_touch = true;
                            }
                            continue;
                        }

                        // Terminate traversal at verified CEX omnibus wallets, canonical bridges & DEX pools
                        if let Some(inter_lbl) = label_map.get(&next) {
                            if inter_lbl.is_omnibus_sink {
                                summary.terminated_at_omnibus_sinks += 1;
                                continue;
                            }
                        }

                        let mut next_visited = visited.clone();
                        next_visited.insert(next.clone());
                        stack.push((next, next_hops, next_flow, path_ts, next_visited));
                    }
                }
            }
        }

        summary
    }

    /// Evaluate all 9 production blockchain heuristics (`H-SIM-01` .. `H-MEM-01`).
    pub fn evaluate_all(
        &self,
        ctx: &HeuristicEvaluationContext<'_>,
    ) -> (Vec<HeuristicFinding>, TaintExposureSummary) {
        let mut findings = Vec::new();
        let subject = normalize_address(ctx.subject_address);

        let contract_map: HashMap<String, &ContractArtifact> = ctx
            .contracts
            .iter()
            .map(|c| (normalize_address(&c.address), c))
            .collect();
        let label_map: HashMap<String, &EntityLabel> = ctx
            .entity_labels
            .iter()
            .map(|l| (normalize_address(&l.address), l))
            .collect();

        let counterparty = ctx
            .transaction
            .and_then(|tx| tx.recipient.as_deref())
            .map(normalize_address);

        // ---------------------------------------------------------------------
        // 1. Pre-Sign Simulation Heuristics (`H-SIM-01`, `H-APP-01`, `H-EVM-01`, `H-TOK-01`)
        // ---------------------------------------------------------------------
        if let Some(sim) = ctx.simulation {
