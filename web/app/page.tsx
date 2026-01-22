"use client";

import React, { useEffect, useState, useMemo, useRef } from "react";

const GATEWAY_URL = process.env.NEXT_PUBLIC_GATEWAY_URL || "http://127.0.0.1:8090";

interface ShapAttribution {
  feature_name: string;
  feature_value: number;
  shap_impact: number;
  direction: string;
}

interface HeuristicFinding {
  rule_id: string;
  rule_version?: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  triggers_critical_veto: boolean;
  description: string;
}

interface PermissionMutation {
  kind: string;
  owner: string;
  spender: string;
  token_address: string;
  is_unlimited: boolean;
  allowance_usd: number;
}

interface RiskReport {
  evaluation_id: string;
  evaluated_at: string;
  evaluation_mode: string;
  chain_id: number;
  block_number?: number | null;
  tx_hash?: string | null;
  method_selector?: string | null;
  decoded_function?: string | null;
  tx_value_native?: number | null;
  tx_value_usd?: number | null;
  gas_price_gwei?: number | null;
  subject_address: string;
  subject_label?: string | null;
  counterparty_address?: string | null;
  counterparty_label?: string | null;
  risk_score: number;
  risk_tier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence_score: number;
  policy_action: "ALLOW" | "WARN" | "HOLD" | "BLOCK";
  ensemble_breakdown: {
    heuristic_signal: number;
    taint_exposure_signal: number;
    supervised_ml_signal: number;
    bytecode_risk_signal: number;
    anomaly_signal: number;
    raw_ensemble_score: number;
    calibrated_probability: number;
    critical_veto_applied: boolean;
  };
  heuristic_findings: HeuristicFinding[];
  simulation_summary?: {
    success: boolean;
    revert_reason?: string | null;
    gas_used: number;
    permission_mutations: PermissionMutation[];
    simulation_latency_ms: number;
  } | null;
  ml_predictions: {
    anomaly_score: number;
    supervised_fraud_prob: number;
    bytecode_risk_score: number;
    nearest_bytecode_family: string | null;
    bytecode_similarity: number | null;
    top_shap_features: ShapAttribution[];
    inference_latency_ms: number;
  };
  forensic_brief?: {
    executive_summary: string;
    technical_forensics: string;
    recommended_action: string;
    evidence_citations: string[];
    prompt_injection_sanitized: boolean;
  } | null;
  total_latency_ms: number;
}

interface ChainStatus {
  chain_id: number;
  chain_name: string;
  provider_type: string;
  endpoint_masked: string;
  latest_block: number;
  txs_evaluated: number;
  threats_flagged: number;
  last_update_ts: number;
}

interface MlSidecarTelemetry {
  connected: boolean;
  onnx_active: boolean;
  model_artifact: string;
  bytecode_signature_count: number;
  holdout_metrics: Record<string, number>;
}

interface StreamStatusResponse {
  live_connected: boolean;
  eth_price_usd: number;
  total_evaluated: number;
  total_threats: number;
  threat_intel_count: number;
  verified_contract_count: number;
  dispute_count: number;
  ml_telemetry?: MlSidecarTelemetry;
  chains: ChainStatus[];
}

interface DisputeRecord {
  dispute_id: string;
  evaluation_id?: string | null;
  chain_id: number;
  address: string;
  proposed_label: string;
  analyst_notes: string;
  status: string;
  created_at: string;
}

interface AlertRecord {
  evaluation_id: string;
  triage_status: "OPEN" | "ACKNOWLEDGED" | "FALSE_POSITIVE" | "CONFIRMED" | string;
  updated_at: string;
  report: RiskReport;
}

function formatCompactCount(n?: number | null): string {
  if (n == null) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function truncateHex(hex?: string | null, chars = 4): string {
  if (!hex) return "—";
  if (hex.length <= chars * 2 + 2) return hex;
  return `${hex.slice(0, chars + 2)}...${hex.slice(-chars)}`;
}

function getExplorerTxUrl(chainId: number, txHash: string): string {
  return chainId === 8453
    ? `https://basescan.org/tx/${txHash}`
    : `https://etherscan.io/tx/${txHash}`;
}

function getExplorerAddressUrl(chainId: number, address: string): string {
  return chainId === 8453
    ? `https://basescan.org/address/${address}`
    : `https://etherscan.io/address/${address}`;
}

const HEURISTIC_RULES = [
  {
    id: "H-SIM-01",
    name: "Asymmetric Asset Outflow",
    severity: "CRITICAL",
    desc: "Simulated execution transfers assets to an unverified recipient with zero inbound consideration.",
  },
  {
    id: "H-APP-01",
    name: "Permit2 & Unlimited Approval",
    severity: "CRITICAL",
    desc: "Grants unlimited ERC-20 allowance or Permit2 authority to an EOA or unverified contract.",
  },
  {
    id: "H-EVM-01",
    name: "Simulation Evasion & Delegatecall",
    severity: "HIGH",
    desc: "Bytecode branches on COINBASE/GASPRICE/PREVRANDAO or calls untrusted DELEGATECALL.",
  },
  {
    id: "H-SOC-01",
    name: "Address Poisoning Lookalike",
    severity: "CRITICAL",
    desc: "Recipient spoofs prefix/suffix of a frequent counterparty with prior zero/dust transfers.",
  },
  {
    id: "H-AML-01",
    name: "OFAC, Forta & ScamSniffer Threat",
    severity: "CRITICAL",
    desc: "Direct or multi-hop taint exposure to OFAC SDN, Forta exploiters, or ScamSniffer drainers.",
  },
  {
    id: "H-GRF-01",
    name: "Sequential Peel-Chain Topology",
    severity: "HIGH",
    desc: "Graph exhibits rapid sequential splits forwarding 85–98% of funds to fresh nonce-0 accounts.",
  },
  {
    id: "H-GRF-02",
    name: "Coordinated Sybil Cluster",
    severity: "HIGH",
    desc: "Single funder disperses gas to >=15 fresh accounts running identical selectors within 30m.",
  },
  {
    id: "H-TOK-01",
    name: "Asymmetric Transfer Trap",
    severity: "HIGH",
    desc: "Simulated token transfer reverts or incurs outbound transfer tax exceeding 25%.",
  },
  {
    id: "H-MEM-01",
    name: "Automated Key-Sweeper Profile",
    severity: "HIGH",
    desc: "Full-balance outflow at >=99th priority fee percentile within two blocks of inbound funding.",
  },
];

