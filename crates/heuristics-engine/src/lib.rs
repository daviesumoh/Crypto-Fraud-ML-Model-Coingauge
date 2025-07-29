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

            // H-TOK-01: Asymmetric Transfer Trap (Honeypot)
            if sim.honeypot_sell_reverted || sim.observed_sell_tax_pct > 25.0 {
                findings.push(HeuristicFinding {
                    rule_id: "H-TOK-01".to_string(),
                    rule_version: "1.0.0".to_string(),
                    title: "Token Honeypot / Transfer Trap".to_string(),
                    severity: Severity::High,
                    triggers_critical_veto: sim.honeypot_sell_reverted,
                    description: if sim.honeypot_sell_reverted {
                        "Dual-simulation buy/sell probe reverted on outbound transfer (unsellable honeypot token).".to_string()
                    } else {
                        format!(
                            "Outbound sell probe incurred {:.1}% hidden transfer tax (>25% threshold).",
                            sim.observed_sell_tax_pct
                        )
                    },
                    evidence: serde_json::json!({
                        "sell_reverted": sim.honeypot_sell_reverted,
                        "observed_sell_tax_pct": sim.observed_sell_tax_pct,
                    }),
                });
            }
        }

        // ---------------------------------------------------------------------
        // 2. Social Engineering & Mempool Urgency (`H-SOC-01`, `H-MEM-01`)
        // ---------------------------------------------------------------------
        if let Some(tx) = ctx.transaction {
            // Look up transfer destination (either native recipient or ERC-20 transfer target)
            let transfer_targets: Vec<String> = {
                let mut targets = Vec::new();
                if let Some(rcpt) = &tx.recipient {
                    targets.push(normalize_address(rcpt));
                }
                if let Some(sim) = ctx.simulation {
                    for mov in &sim.asset_movements {
                        if normalize_address(&mov.from_address) == subject {
                            targets.push(normalize_address(&mov.to_address));
                        }
                    }
                }
                targets
            };

            let dust_senders: HashSet<String> = ctx
                .wallet_history
                .prior_zero_or_dust_senders
                .iter()
                .map(|s| normalize_address(s))
                .collect();

            // H-SOC-01: Address Poisoning Lookalike Detection
            for target in &transfer_targets {
                if target.len() == 42 {
                    for trusted in &ctx.wallet_history.frequent_counterparties {
                        let trusted_norm = normalize_address(trusted);
                        if trusted_norm.len() == 42
                            && &trusted_norm != target
                            && trusted_norm[2..6] == target[2..6]
                            && trusted_norm[38..42] == target[38..42]
                            && dust_senders.contains(target)
                        {
                            findings.push(HeuristicFinding {
                                rule_id: "H-SOC-01".to_string(),
                                rule_version: "1.1.0".to_string(),
                                title: "Address Poisoning Lookalike Detected".to_string(),
                                severity: Severity::Critical,
                                triggers_critical_veto: true,
                                description: format!(
                                    "Recipient {target} mimics frequent counterparty {trusted_norm} (matching 4-hex prefix & suffix) and previously sent a 0-value/dust spoof transfer."
                                ),
                                evidence: serde_json::json!({
                                    "spoof_address": target,
                                    "legitimate_counterparty": trusted_norm,
                                    "matched_prefix": &target[0..6],
                                    "matched_suffix": &target[38..42],
                                }),
                            });
                            break;
                        }
                    }
                }
            }

            // H-MEM-01: Compromised Private Key Sweeper Bot Gas Profile
            let sweeps_full_balance = tx.sender_pre_balance_usd > 50.0
                && tx.value_usd >= tx.sender_pre_balance_usd * 0.92;
            let immediate_after_funding = tx
                .blocks_since_last_inbound_funding
                .map(|b| b <= 2)
                .unwrap_or(false);

            if sweeps_full_balance
                && tx.block_priority_fee_percentile >= 99.0
                && immediate_after_funding
            {
                findings.push(HeuristicFinding {
                    rule_id: "H-MEM-01".to_string(),
                    rule_version: "1.0.0".to_string(),
                    title: "Automated Key-Sweeper Gas & Balance Profile".to_string(),
                    severity: Severity::High,
                    triggers_critical_veto: false,
                    description: format!(
                        "Full-balance sweep (${:.2}) at {:.2}th percentile priority fee within <= 2 blocks of inbound funding.",
                        tx.value_usd, tx.block_priority_fee_percentile
                    ),
                    evidence: serde_json::json!({
                        "swept_usd": tx.value_usd,
                        "priority_fee_percentile": tx.block_priority_fee_percentile,
                        "blocks_since_funding": tx.blocks_since_last_inbound_funding,
                    }),
                });
            }
        }

        // ---------------------------------------------------------------------
        // 3. Multi-Hop Taint, Peel Chains & Sybil Topologies (`H-AML-01`, `H-GRF-01`, `H-GRF-02`)
        // ---------------------------------------------------------------------
        let taint = self.compute_taint_exposure(
            &subject,
            counterparty.as_deref(),
            ctx.current_timestamp_sec,
            ctx.graph_edges,
            ctx.entity_labels,
        );

        if taint.max_taint_score >= 0.15 || taint.direct_sanctioned_touch {
            let severity = if taint.direct_sanctioned_touch || taint.max_taint_score >= 0.55 {
                Severity::Critical
            } else if taint.max_taint_score >= 0.30 {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(HeuristicFinding {
                rule_id: "H-AML-01".to_string(),
                rule_version: "1.4.0".to_string(),
                title: "Sanctioned / Illicit Taint Exposure".to_string(),
                severity,
                triggers_critical_veto: taint.direct_sanctioned_touch,
                description: format!(
                    "Haircut taint exposure {:.1}% from {:?} ({}) at {} hop(s).",
                    taint.max_taint_score * 100.0,
                    taint.nearest_category,
                    taint
                        .nearest_illicit_address
                        .as_deref()
                        .unwrap_or("unknown"),
                    taint.hop_distance.unwrap_or(0)
                ),
                evidence: serde_json::to_value(&taint).unwrap_or_default(),
            });
        }

        // H-GRF-01: Peel Chain Detection (>= 4 sequential hops in <= 2h forwarding 85-98% to fresh wallets)
        if let Some((chain_len, peel_start_ts, peel_end_ts)) =
            detect_peel_chain(ctx.graph_edges)
        {
            if chain_len >= 4 && peel_end_ts.saturating_sub(peel_start_ts) <= 7_200 {
                findings.push(HeuristicFinding {
                    rule_id: "H-GRF-01".to_string(),
                    rule_version: "1.1.0".to_string(),
                    title: "Sequential Peel-Chain Laundering Topology".to_string(),
                    severity: Severity::High,
                    triggers_critical_veto: false,
                    description: format!(
                        "Detected {chain_len}-hop peel chain within {} minutes repeatedly forwarding 85%-98% to fresh nonce-0 wallets while peeling 2%-15% off.",
                        peel_end_ts.saturating_sub(peel_start_ts) / 60
                    ),
                    evidence: serde_json::json!({
                        "peel_hops": chain_len,
                        "duration_sec": peel_end_ts.saturating_sub(peel_start_ts),
                    }),
                });
            }
        }

        // H-GRF-02: Sybil Star Funding / Coordinated Selector Fan-Out
        if let Some((faucet, fanout_count, common_selector)) =
            detect_sybil_star_cluster(ctx.graph_edges)
        {
            findings.push(HeuristicFinding {
                rule_id: "H-GRF-02".to_string(),
                rule_version: "1.0.0".to_string(),
                title: "Coordinated Sybil Star-Funding Cluster".to_string(),
                severity: Severity::High,
                triggers_critical_veto: false,
                description: format!(
                    "Faucet wallet {faucet} dispersed gas to {fanout_count} fresh wallets within 30 minutes executing synchronized selector {common_selector}."
                ),
                evidence: serde_json::json!({
                    "faucet_address": faucet,
                    "fresh_wallet_count": fanout_count,
                    "selector": common_selector,
                }),
            });
        }

        (findings, taint)
    }
}

/// Detect linear peel-chain hops where a wallet splits `[85%, 98%]` to a fresh wallet
/// and peels `[2%, 15%]` to another counterparty.
fn detect_peel_chain(edges: &[GraphTransferEdge]) -> Option<(usize, u64, u64)> {
    let mut by_sender: HashMap<String, Vec<&GraphTransferEdge>> = HashMap::new();
    for e in edges {
        by_sender
            .entry(normalize_address(&e.from))
            .or_default()
            .push(e);
    }

    let mut best: Option<(usize, u64, u64)> = None;

    for start_sender in by_sender.keys() {
        let mut curr = start_sender.clone();
        let mut hops = 0usize;
        let mut min_ts = u64::MAX;
        let mut max_ts = 0u64;
        let mut visited = HashSet::new();

        while visited.insert(curr.clone()) {
            let Some(out) = by_sender.get(&curr) else {
                break;
            };
            if out.len() < 2 {
                break;
            }
            let total_out: f64 = out.iter().map(|e| e.amount_usd).sum();
            if total_out <= 0.0 {
                break;
            }
            let continuation = out.iter().find(|e| {
                let share = e.amount_usd / total_out;
                e.recipient_is_fresh_nonce_zero && (0.85..=0.985).contains(&share)
            });

            if let Some(next_edge) = continuation {
                hops += 1;
                min_ts = min_ts.min(next_edge.timestamp_sec);
                max_ts = max_ts.max(next_edge.timestamp_sec);
                curr = normalize_address(&next_edge.to);
            } else {
                break;
            }
        }

        if hops >= 4 && best.map(|b| hops > b.0).unwrap_or(true) {
            best = Some((hops, min_ts, max_ts));
        }
    }

    best
}

/// Detect a single funding EOA dispersing funds to `>= 15` fresh wallets within `30m`
/// sharing an identical calldata selector.
fn detect_sybil_star_cluster(edges: &[GraphTransferEdge]) -> Option<(String, usize, String)> {
    let mut by_faucet: HashMap<(String, String), Vec<&GraphTransferEdge>> = HashMap::new();
    for e in edges {
        if e.recipient_is_fresh_nonce_zero {
            by_faucet
                .entry((normalize_address(&e.from), e.selector.clone()))
                .or_default()
                .push(e);
        }
    }

    for ((faucet, selector), group) in by_faucet {
        if group.len() < 15 {
            continue;
        }
        let min_ts = group.iter().map(|e| e.timestamp_sec).min().unwrap_or(0);
        let max_ts = group.iter().map(|e| e.timestamp_sec).max().unwrap_or(0);
        let unique_recipients: HashSet<String> =
            group.iter().map(|e| normalize_address(&e.to)).collect();

        if unique_recipients.len() >= 15 && max_ts.saturating_sub(min_ts) <= 1_800 {
            return Some((faucet, unique_recipients.len(), selector));
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct CompositeRiskScorer {
    pub w_heuristics: f64,
    pub w_taint: f64,
    pub w_supervised: f64,
    pub w_bytecode: f64,
    pub w_anomaly: f64,
}

impl Default for CompositeRiskScorer {
    fn default() -> Self {
        Self {
            w_heuristics: 0.35,
            w_taint: 0.25,
            w_supervised: 0.20,
            w_bytecode: 0.12,
            w_anomaly: 0.08,
        }
    }
}

impl CompositeRiskScorer {
    pub fn calibrate_isotonic(raw: f64) -> f64 {
        let x = raw.clamp(0.0, 1.0);
        const KNOTS: [(f64, f64); 6] = [
            (0.00, 0.01),
            (0.12, 0.14),
            (0.28, 0.42),
            (0.48, 0.72),
            (0.70, 0.90),
            (1.00, 0.99),
        ];
        for window in KNOTS.windows(2) {
            let (x0, y0) = window[0];
            let (x1, y1) = window[1];
            if x <= x1 {
                let t = (x - x0) / (x1 - x0);
                return y0 + t * (y1 - y0);
            }
        }
        0.99
    }

    pub fn score(
        &self,
        evaluation_mode: &str,
        chain_id: u64,
        subject_address: &str,
        counterparty_address: Option<String>,
        tx_history_count: u64,
        findings: Vec<HeuristicFinding>,
        taint: &TaintExposureSummary,
        simulation: Option<SimulationResult>,
        ml: ModelPredictionBundle,
        forensic_brief: Option<ForensicBrief>,
        total_latency_ms: f64,
    ) -> CompositeRiskReport {
        let total_rule_weight: f64 = findings.iter().map(|f| f.severity.weight()).sum();
        let h_signal = 1.0 - (-total_rule_weight).exp();
        let t_signal = taint.max_taint_score.clamp(0.0, 1.0);
        let s_signal = ml.supervised_fraud_prob.clamp(0.0, 1.0);
        let b_signal = ml.bytecode_risk_score.clamp(0.0, 1.0);
        let a_signal = ml.anomaly_score.clamp(0.0, 1.0);

        let raw_ensemble = self.w_heuristics * h_signal
            + self.w_taint * t_signal
            + self.w_supervised * s_signal
            + self.w_bytecode * b_signal
            + self.w_anomaly * a_signal;

        let calibrated = Self::calibrate_isotonic(raw_ensemble);
        let critical_veto = findings.iter().any(|f| f.triggers_critical_veto);

        let final_prob = if critical_veto {
            calibrated.max(0.95)
        } else {
            calibrated
        };

        let risk_score = (final_prob * 100.0).round().clamp(0.0, 100.0) as u8;

        let (risk_tier, policy_action) = match risk_score {
            0..=24 => (RiskTier::Low, PolicyAction::Allow),
            25..=54 => (RiskTier::Medium, PolicyAction::Warn),
            55..=79 => (
                RiskTier::High,
                if evaluation_mode == "PRE_SIGN_TX" {
                    PolicyAction::Warn
                } else {
                    PolicyAction::Hold
                },
            ),
            _ => (RiskTier::Critical, PolicyAction::Block),
        };

        let has_sim = if simulation.is_some() { 1.0 } else { 0.0 };
        let confidence_score =
            (1.0 - (-(tx_history_count as f64) / 25.0).exp() * (1.0 - has_sim * 0.65))
                .clamp(0.15, 0.99);

        CompositeRiskReport {
            evaluation_id: Uuid::new_v4(),
            evaluated_at: Utc::now(),
            evaluation_mode: evaluation_mode.to_string(),
            chain_id,
            block_number: None,
            tx_hash: None,
            method_selector: None,
            decoded_function: None,
            tx_value_native: None,
            tx_value_usd: None,
            gas_price_gwei: None,
            subject_address: normalize_address(subject_address),
            subject_label: None,
            counterparty_address: counterparty_address.map(|c| normalize_address(&c)),
            counterparty_label: None,
            risk_score,
            risk_tier,
            confidence_score,
            policy_action,
            ensemble_breakdown: EnsembleBreakdown {
                heuristic_signal: h_signal,
                taint_exposure_signal: t_signal,
                supervised_ml_signal: s_signal,
                bytecode_risk_signal: b_signal,
                anomaly_signal: a_signal,
                raw_ensemble_score: raw_ensemble,
                calibrated_probability: calibrated,
                critical_veto_applied: critical_veto,
            },
            heuristic_findings: findings,
            simulation_summary: simulation,
            ml_predictions: ml,
            forensic_brief,
            total_latency_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::{FinalityStatus, PermissionKind, PermissionMutation};

    #[test]
    fn quarantines_unsolicited_tornado_dust_attack_on_innocent_wallet() {
        let engine = HeuristicsEngine::new();
        let tornado = "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf";
        let vitalik = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";

        let labels = vec![EntityLabel {
            address: tornado.to_string(),
            entity_name: "Tornado.Cash: 10 ETH".to_string(),
            category: EntityCategory::Sanctioned,
            source_feed: "OFAC_SDN".to_string(),
            severity_weight: 1.0,
            is_omnibus_sink: false,
            is_sanctioned: true,
        }];

        // Attacker sends $0.45 dust from Tornado Cash to innocent wallet; recipient never co-spends it
        let edges = vec![GraphTransferEdge {
            tx_hash: "0xdust".to_string(),
            from: tornado.to_string(),
            to: vitalik.to_string(),
            amount_usd: 0.45,
            recipient_post_balance_usd: 500_000.0,
            timestamp_sec: 1_730_000_000,
            selector: "0x".to_string(),
            recipient_is_fresh_nonce_zero: false,
            recipient_has_outbound_cospend: false,
        }];

        let taint = engine.compute_taint_exposure(vitalik, None, 1_730_010_000, &edges, &labels);
        assert_eq!(taint.max_taint_score, 0.0);
        assert_eq!(taint.quarantined_dust_edges, 1);
    }

    #[test]
    fn terminates_taint_at_cex_omnibus_hot_wallet() {
        let engine = HeuristicsEngine::new();
        let hacker = "0x1111111111111111111111111111111111111111";
        let binance_hot = "0x28c6c06298d514db089934071355e5743bf21d60";
        let retail_user = "0x3333333333333333333333333333333333333333";

        let labels = vec![
            EntityLabel {
                address: hacker.to_string(),
                entity_name: "Bridge Exploiter".to_string(),
                category: EntityCategory::Exploiter,
                source_feed: "CHAINABUSE".to_string(),
                severity_weight: 1.0,
                is_omnibus_sink: false,
                is_sanctioned: false,
            },
            EntityLabel {
                address: binance_hot.to_string(),
                entity_name: "Binance Hot Wallet 14".to_string(),
                category: EntityCategory::CexOmnibus,
                source_feed: "INTERNAL_ATTRIBUTION".to_string(),
                severity_weight: 0.0,
                is_omnibus_sink: true,
                is_sanctioned: false,
            },
        ];

        let edges = vec![
            GraphTransferEdge {
                tx_hash: "0xhop1".to_string(),
                from: hacker.to_string(),
                to: binance_hot.to_string(),
                amount_usd: 100_000.0,
                recipient_post_balance_usd: 50_000_000.0,
                timestamp_sec: 1_730_000_000,
                selector: "0x".to_string(),
                recipient_is_fresh_nonce_zero: false,
                recipient_has_outbound_cospend: true,
            },
            GraphTransferEdge {
                tx_hash: "0xhop2".to_string(),
                from: binance_hot.to_string(),
                to: retail_user.to_string(),
                amount_usd: 2_500.0,
                recipient_post_balance_usd: 2_500.0,
                timestamp_sec: 1_730_001_000,
                selector: "0x".to_string(),
                recipient_is_fresh_nonce_zero: false,
                recipient_has_outbound_cospend: true,
            },
        ];

        let taint =
            engine.compute_taint_exposure(retail_user, None, 1_730_002_000, &edges, &labels);
        assert_eq!(taint.max_taint_score, 0.0);
        assert_eq!(taint.terminated_at_omnibus_sinks, 1);
    }

    #[test]
    fn blocks_permit2_eoa_drainer_and_address_poisoning_with_critical_veto() {
        let engine = HeuristicsEngine::new();
        let scorer = CompositeRiskScorer::default();

        let victim = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let trusted = "0x1234567890abcdef1234567890abcdef12349abc";
        let poison = "0x1234000000000000000000000000000000009abc";

        let tx = CanonicalTransaction {
            chain_id: 1,
            block_number: 21_200_000,
            block_hash: "0x01".to_string(),
            parent_hash: "0x00".to_string(),
            tx_hash: "0x02".to_string(),
            timestamp_sec: 1_730_500_000,
            finality_status: FinalityStatus::Pending,
            sender: victim.to_string(),
            recipient: Some(poison.to_string()),
            value_wei: 1_000_000_000_000_000_000,
            value_usd: 3200.0,
            calldata_hex: "0x".to_string(),
            gas_limit: 21_000,
            max_fee_per_gas_wei: 25_000_000_000,
            priority_fee_per_gas_wei: 1_000_000_000,
            block_priority_fee_percentile: 40.0,
            nonce: 42,
            blocks_since_last_inbound_funding: Some(500),
            sender_pre_balance_usd: 15_000.0,
        };

        let sim = SimulationResult {
            success: true,
            permission_mutations: vec![PermissionMutation {
                kind: PermissionKind::UniswapPermit2,
                owner: victim.to_string(),
                spender: poison.to_string(),
                token_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
                is_unlimited: true,
                allowance_usd: 1_000_000_000.0,
                expiration_sec: None,
            }],
            ..Default::default()
        };

        let history = WalletHistoryContext {
            total_tx_count: 80,
            frequent_counterparties: vec![trusted.to_string()],
            prior_zero_or_dust_senders: vec![poison.to_string()],
        };

        let (findings, taint) = engine.evaluate_all(&HeuristicEvaluationContext {
            subject_address: victim,
            current_timestamp_sec: 1_730_500_000,
            transaction: Some(&tx),
            simulation: Some(&sim),
            wallet_history: &history,
            graph_edges: &[],
            contracts: &[],
            entity_labels: &[],
        });

        assert!(findings.iter().any(|f| f.rule_id == "H-APP-01"));
        assert!(findings.iter().any(|f| f.rule_id == "H-SOC-01"));

        let report = scorer.score(
            "PRE_SIGN_TX",
            1,
            victim,
            Some(poison.to_string()),
            80,
            findings,
            &taint,
            Some(sim),
            ModelPredictionBundle::default(),
            None,
            14.2,
        );

        assert!(report.risk_score >= 95);
        assert_eq!(report.risk_tier, RiskTier::Critical);
        assert_eq!(report.policy_action, PolicyAction::Block);
        assert!(report.ensemble_breakdown.critical_veto_applied);
    }

    #[test]
    fn ignores_unseeded_zero_delegatecall_but_flags_nonzero_untrusted_delegatecall() {
        let engine = HeuristicsEngine::new();
        let caller = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let proxy = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let unseeded_sim = SimulationResult {
            success: true,
            internal_traces: vec![common_types::InternalCallTrace {
                depth: 1,
                call_type: CallType::DelegateCall,
                caller: caller.to_string(),
                target: "0x0000000000000000000000000000000000000000".to_string(),
                value_wei: 0,
                selector: "0x12345678".to_string(),
                reverted: false,
            }],
            ..Default::default()
        };

        let (findings_zero, _) = engine.evaluate_all(&HeuristicEvaluationContext {
            subject_address: caller,
            current_timestamp_sec: 1_730_500_000,
            transaction: None,
            simulation: Some(&unseeded_sim),
            wallet_history: &WalletHistoryContext::default(),
            graph_edges: &[],
            contracts: &[],
            entity_labels: &[],
        });
        assert!(!findings_zero.iter().any(|f| f.rule_id == "H-EVM-01"));

        let nonzero_sim = SimulationResult {
            success: true,
            internal_traces: vec![common_types::InternalCallTrace {
                depth: 1,
                call_type: CallType::DelegateCall,
                caller: proxy.to_string(),
                target: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                value_wei: 0,
                selector: "0x12345678".to_string(),
                reverted: false,
            }],
            ..Default::default()
        };

        let (findings_nonzero, _) = engine.evaluate_all(&HeuristicEvaluationContext {
            subject_address: caller,
            current_timestamp_sec: 1_730_500_000,
            transaction: None,
            simulation: Some(&nonzero_sim),
            wallet_history: &WalletHistoryContext::default(),
            graph_edges: &[],
            contracts: &[],
            entity_labels: &[],
        });
        assert!(findings_nonzero.iter().any(|f| f.rule_id == "H-EVM-01"));
    }
}

