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
            // H-SIM-01: Asymmetric Outflow Drainer
            let mut outbound_usd = 0.0;
            let mut inbound_usd = 0.0;
            let mut suspicious_sink: Option<String> = None;

            for mov in &sim.asset_movements {
                let from = normalize_address(&mov.from_address);
                let to = normalize_address(&mov.to_address);
                if from == subject && to != subject {
                    outbound_usd += mov.amount_usd;
                    let is_trusted = label_map
                        .get(&to)
                        .map(|l| {
                            matches!(
                                l.category,
                                EntityCategory::VerifiedProtocol
                                    | EntityCategory::DexPool
                                    | EntityCategory::CanonicalBridge
                                    | EntityCategory::CexOmnibus
                            )
                        })
                        .unwrap_or(false);
                    let is_unverified_or_young = contract_map
                        .get(&to)
                        .map(|c| c.is_eoa || !c.is_verified || c.age_hours < 72.0)
                        .unwrap_or(true);

                    if !is_trusted && is_unverified_or_young {
                        suspicious_sink = Some(to);
                    }
                } else if to == subject && from != subject {
                    inbound_usd += mov.amount_usd;
                }
            }

            if outbound_usd >= 100.0 && inbound_usd == 0.0 {
                if let Some(sink) = &suspicious_sink {
                    let is_known_drainer = label_map
                        .get(sink)
                        .map(|l| l.category == EntityCategory::WalletDrainer)
                        .unwrap_or(false);
                    let is_young_contract = contract_map
                        .get(sink)
                        .map(|c| !c.is_eoa && (!c.is_verified || c.age_hours < 72.0))
                        .unwrap_or(false);

                    if is_known_drainer || is_young_contract {
                        findings.push(HeuristicFinding {
                            rule_id: "H-SIM-01".to_string(),
                            rule_version: "1.2.0".to_string(),
                            title: "Asymmetric Asset Drain Detected".to_string(),
                            severity: Severity::Critical,
                            triggers_critical_veto: true,
                            description: format!(
                                "Simulated execution drains ${outbound_usd:.2} in assets to unverified/malicious target {sink} with $0.00 inbound consideration."
                            ),
                            evidence: serde_json::json!({
                                "outbound_usd": outbound_usd,
                                "inbound_usd": inbound_usd,
                                "destination": sink,
                            }),
                        });
                    }
                }
            }

            // H-APP-01: EOA / Unverified Spender Unlimited Approval or Permit2 Phishing
            for perm in &sim.permission_mutations {
                let spender = normalize_address(&perm.spender);
                let trusted_protocol = label_map
                    .get(&spender)
                    .map(|l| {
                        matches!(
                            l.category,
                            EntityCategory::VerifiedProtocol
                                | EntityCategory::DexPool
                                | EntityCategory::CanonicalBridge
                        )
                    })
                    .unwrap_or(false);
                if trusted_protocol {
                    continue;
                }

                let (is_eoa, is_verified) = contract_map
                    .get(&spender)
                    .map(|c| (c.is_eoa, c.is_verified))
                    .unwrap_or((true, false));

                let tx_val = ctx.transaction.map(|t| t.value_usd).unwrap_or(0.0);
                let excessive =
                    perm.is_unlimited || (tx_val > 0.0 && perm.allowance_usd > tx_val * 10.0);

                if excessive && (is_eoa || !is_verified) {
                    findings.push(HeuristicFinding {
                        rule_id: "H-APP-01".to_string(),
                        rule_version: "1.3.0".to_string(),
                        title: "High-Risk Token Approval / Permit2 Phishing".to_string(),
                        severity: Severity::Critical,
                        triggers_critical_veto: true,
                        description: format!(
                            "{:?} grants {} allowance on token {} to {} spender {}.",
                            perm.kind,
                            if perm.is_unlimited {
                                "UNLIMITED"
                            } else {
                                "excessive (>10x)"
                            },
                            perm.token_address,
                            if is_eoa { "EOA wallet" } else { "unverified contract" },
                            spender
                        ),
                        evidence: serde_json::json!({
                            "permission_kind": perm.kind,
                            "spender": spender,
                            "token": perm.token_address,
                            "is_eoa_spender": is_eoa,
                            "is_unlimited": perm.is_unlimited,
                        }),
                    });
                }
            }

            // H-EVM-01: Untrusted Delegatecall / Metamorphic Factory / Env Evasion Branching
            let untrusted_delegatecall = sim.internal_traces.iter().find(|tr| {
                let target_norm = normalize_address(&tr.target);
                let is_zero_or_precompile =
                    target_norm.starts_with("0x000000000000000000000000000000000000000");
                tr.call_type == CallType::DelegateCall
                    && !is_zero_or_precompile
                    && !contract_map
                        .get(&target_norm)
                        .map(|c| c.is_whitelisted_proxy_target)
                        .unwrap_or(false)
            });

            let metamorphic_target = counterparty
                .as_ref()
                .and_then(|rcpt| contract_map.get(rcpt))
                .filter(|c| c.deployed_via_create2 && c.factory_has_selfdestruct_history);

            if untrusted_delegatecall.is_some()
                || metamorphic_target.is_some()
                || sim.env_evasion_opcode_detected
            {
                findings.push(HeuristicFinding {
                    rule_id: "H-EVM-01".to_string(),
                    rule_version: "1.1.0".to_string(),
                    title: "Obfuscated Execution / Simulation Evasion Pattern".to_string(),
                    severity: Severity::High,
                    triggers_critical_veto: metamorphic_target.is_some(),
                    description: "Execution invokes untrusted DELEGATECALL, metamorphic CREATE2/SELFDESTRUCT lineage, or COINBASE/GASPRICE conditional branching.".to_string(),
                    evidence: serde_json::json!({
                        "untrusted_delegatecall_target": untrusted_delegatecall.map(|t| &t.target),
                        "metamorphic_contract": metamorphic_target.map(|c| &c.address),
                        "env_evasion_opcode_detected": sim.env_evasion_opcode_detected,
                    }),
                });
            }

