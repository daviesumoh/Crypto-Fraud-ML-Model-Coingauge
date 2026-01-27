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

export default function CryptoRiskConsole() {
  const [activeTab, setActiveTab] = useState<"stream" | "alerts" | "inspector" | "rules" | "chains">("stream");
  const [streamStatus, setStreamStatus] = useState<StreamStatusResponse | null>(null);
  const [sseStatus, setSseStatus] = useState<"connecting" | "connected" | "reconnecting" | "offline">("connecting");
  const [streamError, setStreamError] = useState<string | null>(null);
  const [liveReports, setLiveReports] = useState<RiskReport[]>([]);
  const [alertRecords, setAlertRecords] = useState<AlertRecord[]>([]);
  const [selectedReport, setSelectedReport] = useState<RiskReport | null>(null);
  const [disputes, setDisputes] = useState<DisputeRecord[]>([]);

  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [chainFilter, setChainFilter] = useState<"all" | "1" | "8453">("all");
  const [tierFilter, setTierFilter] = useState<"all" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL">("all");
  const [valueFilter, setValueFilter] = useState<"all" | "gt0" | "gte100" | "gte1000" | "gte10000">("all");
  const [triageFilter, setTriageFilter] = useState<"all" | "OPEN" | "ACKNOWLEDGED" | "CONFIRMED" | "FALSE_POSITIVE">("all");
  const [threatsOnly, setThreatsOnly] = useState<boolean>(false);
  const [tableFilter, setTableFilter] = useState<string>("");
  const [isUpdatingAlert, setIsUpdatingAlert] = useState<boolean>(false);

  const [inspectorMode, setInspectorMode] = useState<"address" | "tx">("address");
  const [searchAddr, setSearchAddr] = useState<string>("");
  const [searchChainId, setSearchChainId] = useState<number>(1);
  const [isSearching, setIsSearching] = useState<boolean>(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [scannedReport, setScannedReport] = useState<RiskReport | null>(null);

  const [txChainId, setTxChainId] = useState<number>(1);
  const [txFrom, setTxFrom] = useState<string>("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
  const [txTo, setTxTo] = useState<string>("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
  const [txValueEth, setTxValueEth] = useState<string>("0");
  const [txCalldata, setTxCalldata] = useState<string>("0x");
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simError, setSimError] = useState<string | null>(null);
  const [simReport, setSimReport] = useState<RiskReport | null>(null);

  const [showSignals, setShowSignals] = useState<boolean>(false);
  const [showDisputeForm, setShowDisputeForm] = useState<boolean>(false);
  const [disputeLabel, setDisputeLabel] = useState<string>("BenignProtocol");
  const [disputeNotes, setDisputeNotes] = useState<string>("");
  const [isSubmittingDispute, setIsSubmittingDispute] = useState<boolean>(false);
  const [disputeFeedback, setDisputeFeedback] = useState<string | null>(null);

  const [copiedText, setCopiedText] = useState<string | null>(null);
  const filterInputRef = useRef<HTMLInputElement | null>(null);
  const inspectorInputRef = useRef<HTMLInputElement | null>(null);
  const isPausedRef = useRef<boolean>(isPaused);
  const activeTabRef = useRef<"stream" | "alerts" | "inspector" | "rules" | "chains">(activeTab);

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  useEffect(() => {
    activeTabRef.current = activeTab;
  }, [activeTab]);

  async function refreshStatusAndLatest(signal?: AbortSignal) {
    try {
      const [statusRes, latestRes, alertsRes] = await Promise.all([
        fetch(`${GATEWAY_URL}/v1/stream/status`, { signal }),
        fetch(`${GATEWAY_URL}/v1/stream/latest`, { signal }),
        fetch(`${GATEWAY_URL}/v1/stream/alerts`, { signal }),
      ]);

      if (!statusRes.ok) {
        throw new Error(`Gateway status HTTP ${statusRes.status}`);
      }
      const statusData: StreamStatusResponse = await statusRes.json();
      setStreamStatus(statusData);
      setStreamError(null);

      if (latestRes.ok) {
        const reports: RiskReport[] = await latestRes.json();
        if (reports.length > 0) {
          setLiveReports((prev) => {
            if (prev.length === 0) return reports;
            const seen = new Set(prev.map((r) => r.tx_hash || r.evaluation_id));
            const merged = [...reports.filter((r) => !seen.has(r.tx_hash || r.evaluation_id)), ...prev];
            return merged.slice(0, 100);
          });
        }
      }

      if (alertsRes.ok) {
        const alerts: AlertRecord[] = await alertsRes.json();
        setAlertRecords(alerts);
      }
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setStreamError(
        err instanceof Error
          ? `Unable to reach Gateway (${GATEWAY_URL}): ${err.message}`
          : `Unable to reach Gateway (${GATEWAY_URL})`
      );
      setSseStatus("offline");
    }
  }

  async function fetchAlerts() {
    try {
      const res = await fetch(`${GATEWAY_URL}/v1/stream/alerts`);
      if (res.ok) {
        setAlertRecords(await res.json());
      }
    } catch {
      // Ignore transient alerts fetch error
    }
  }

  async function updateAlertTriage(evaluationId: string, triageStatus: string) {
    setIsUpdatingAlert(true);
    try {
      const res = await fetch(`${GATEWAY_URL}/v1/stream/alerts/${encodeURIComponent(evaluationId)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ triage_status: triageStatus }),
      });
      if (res.ok) {
        const updated: AlertRecord = await res.json();
        setAlertRecords((prev) =>
          prev.map((item) => (item.evaluation_id === updated.evaluation_id ? updated : item))
        );
      }
    } catch {
      // Ignore transient triage error
    } finally {
      setIsUpdatingAlert(false);
    }
  }

  async function fetchDisputes() {
    try {
      const res = await fetch(`${GATEWAY_URL}/v1/feedback/disputes`);
      if (res.ok) {
        setDisputes(await res.json());
      }
    } catch {
      // Ignore transient dispute fetch error
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    let mounted = true;
    let eventSource: EventSource | null = null;

    refreshStatusAndLatest(controller.signal);

    try {
      eventSource = new EventSource(`${GATEWAY_URL}/v1/stream/events`);
      eventSource.onopen = () => {
        if (!mounted) return;
        setSseStatus("connected");
        setStreamError(null);
      };
      eventSource.onmessage = (e) => {
        if (!mounted) return;
        setSseStatus("connected");
        if (isPausedRef.current) return;
        try {
          const report: RiskReport = JSON.parse(e.data);
          setLiveReports((prev) => {
            const key = report.tx_hash || report.evaluation_id;
            if (prev.some((r) => (r.tx_hash || r.evaluation_id) === key)) return prev;
            return [report, ...prev.slice(0, 99)];
          });
          if (report.risk_score >= 25) {
            setAlertRecords((prev) => {
              const key = report.tx_hash || report.evaluation_id;
              if (prev.some((a) => (a.report.tx_hash || a.evaluation_id) === key)) return prev;
              const rec: AlertRecord = {
                evaluation_id: report.evaluation_id,
                triage_status: "OPEN",
                updated_at: report.evaluated_at,
                report,
              };
              return [rec, ...prev.slice(0, 499)];
            });
          }
        } catch {
          // Ignore malformed frame
        }
      };
      eventSource.onerror = () => {
        if (!mounted) return;
        setSseStatus("reconnecting");
      };
    } catch {
      setSseStatus("offline");
    }

    const statusTimer = setInterval(async () => {
      try {
        const res = await fetch(`${GATEWAY_URL}/v1/stream/status`);
        if (res.ok && mounted) {
          setStreamStatus(await res.json());
          setStreamError(null);
        } else if (mounted) {
          setStreamError(`Gateway status returned HTTP ${res.status}`);
        }
      } catch {
        if (mounted) {
          setStreamError(`Gateway disconnected (${GATEWAY_URL})`);
          setSseStatus("offline");
        }
      }
    }, 4000);

    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName;
      const inInput =
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        Boolean(target?.isContentEditable);
      const onInteractive = inInput || tag === "BUTTON" || tag === "A";

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setActiveTab("inspector");
        setInspectorMode("address");
        setTimeout(() => inspectorInputRef.current?.focus(), 40);
        return;
      }

      if (e.key === "/" && !inInput) {
        e.preventDefault();
        if (activeTabRef.current === "stream" || activeTabRef.current === "alerts") {
          filterInputRef.current?.focus();
        } else {
          setActiveTab("inspector");
          setInspectorMode("address");
          setTimeout(() => inspectorInputRef.current?.focus(), 40);
        }
        return;
      }

      if (e.key === "Escape") {
        setSelectedReport(null);
        setShowDisputeForm(false);
        return;
      }

      if (e.code === "Space" && !onInteractive && (activeTabRef.current === "stream" || activeTabRef.current === "alerts")) {
        e.preventDefault();
        setIsPaused((p) => !p);
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    return () => {
      mounted = false;
      controller.abort();
      if (eventSource) eventSource.close();
      clearInterval(statusTimer);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  useEffect(() => {
    if (activeTab === "chains") {
      fetchDisputes();
    } else if (activeTab === "alerts") {
      fetchAlerts();
    }
  }, [activeTab]);

  useEffect(() => {
    setShowDisputeForm(false);
    setDisputeFeedback(null);
  }, [selectedReport?.evaluation_id, scannedReport?.evaluation_id]);

  const alertStatusById = useMemo(() => {
    const map = new Map<string, AlertRecord>();
    for (const rec of alertRecords) {
      map.set(rec.evaluation_id, rec);
    }
    return map;
  }, [alertRecords]);

  const displayedReports = useMemo(() => {
    let list =
      activeTab === "alerts"
        ? alertRecords
            .filter((a) => triageFilter === "all" || a.triage_status === triageFilter)
            .map((a) => a.report)
        : liveReports;

    if (chainFilter !== "all") {
      const cid = Number(chainFilter);
      list = list.filter((r) => r.chain_id === cid);
    }
    if (tierFilter !== "all") {
      list = list.filter((r) => r.risk_tier === tierFilter);
    }
    if (valueFilter !== "all") {
      list = list.filter((r) => {
        const usd = r.tx_value_usd ?? 0;
        if (valueFilter === "gt0") return usd > 0;
        if (valueFilter === "gte100") return usd >= 100;
        if (valueFilter === "gte1000") return usd >= 1_000;
        if (valueFilter === "gte10000") return usd >= 10_000;
        return true;
      });
    }
    if (activeTab === "stream" && threatsOnly) {
      list = list.filter((r) => r.risk_tier !== "LOW" || r.risk_score >= 25);
    }
    const q = tableFilter.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (r) =>
          r.subject_address.toLowerCase().includes(q) ||
          (r.counterparty_address && r.counterparty_address.toLowerCase().includes(q)) ||
          (r.tx_hash && r.tx_hash.toLowerCase().includes(q)) ||
          (r.decoded_function && r.decoded_function.toLowerCase().includes(q)) ||
          (r.subject_label && r.subject_label.toLowerCase().includes(q)) ||
          (r.counterparty_label && r.counterparty_label.toLowerCase().includes(q))
      );
    }
    return list;
  }, [activeTab, alertRecords, liveReports, chainFilter, tierFilter, valueFilter, triageFilter, threatsOnly, tableFilter]);

  async function inspectAddress(addrOverride?: string, chainOverride?: number) {
    const targetAddr = (addrOverride ?? searchAddr).trim();
    const targetChain = chainOverride ?? searchChainId;
    if (!targetAddr) return;

    if (addrOverride !== undefined) setSearchAddr(addrOverride);
    if (chainOverride !== undefined) setSearchChainId(chainOverride);
    setActiveTab("inspector");
    setInspectorMode("address");
    setIsSearching(true);
    setSearchError(null);

    try {
      const res = await fetch(
        `${GATEWAY_URL}/v1/wallet/inspect?address=${encodeURIComponent(targetAddr)}&chain_id=${targetChain}`
      );
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(errText || `HTTP ${res.status}`);
      }
      const report: RiskReport = await res.json();
      setScannedReport(report);
    } catch (err: unknown) {
      setSearchError(err instanceof Error ? err.message : "Failed to inspect address");
    } finally {
      setIsSearching(false);
    }
  }

  async function simulateTransaction(overrides?: {
    chainId?: number;
    from?: string;
    to?: string;
    valueEth?: string;
    calldata?: string;
  }) {
    const chainId = overrides?.chainId ?? txChainId;
    const from = (overrides?.from ?? txFrom).trim();
    const to = (overrides?.to ?? txTo).trim();
    const valueEthNum = Math.max(0, Number(overrides?.valueEth ?? txValueEth) || 0);
    const calldata = (overrides?.calldata ?? txCalldata).trim() || "0x";

    if (!from) {
      setSimError("Sender address is required.");
      return;
    }

    setIsSimulating(true);
    setSimError(null);

    const ethUsd = streamStatus?.eth_price_usd || 2650;
    const valueWei = BigInt(Math.round(valueEthNum * 1e9)) * BigInt(1_000_000_000);
    const valueUsd = Number((valueEthNum * ethUsd).toFixed(2));
    const blockNum =
      streamStatus?.chains.find((c) => c.chain_id === chainId)?.latest_block ||
      (chainId === 8453 ? 25_000_000 : 21_500_000);

    try {
      const bodyStr = JSON.stringify({
        transaction: {
          chain_id: chainId,
          block_number: blockNum,
          block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
          parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
          tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
          timestamp_sec: Math.floor(Date.now() / 1000),
          finality_status: "pending",
          sender: from,
          recipient: to || null,
          value_wei: "__VALUE_WEI__",
          value_usd: valueUsd,
          calldata_hex: calldata.startsWith("0x") ? calldata : `0x${calldata}`,
          gas_limit: 250_000,
          max_fee_per_gas_wei: 20_000_000_000,
          priority_fee_per_gas_wei: 1_000_000_000,
          block_priority_fee_percentile: 45.0,
          nonce: 10,
          blocks_since_last_inbound_funding: 200,
          sender_pre_balance_usd: Math.max(50_000, valueUsd * 2),
        },
      }).replace('"__VALUE_WEI__"', valueWei.toString());

      const res = await fetch(`${GATEWAY_URL}/v1/evaluate/transaction`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: bodyStr,
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(errText || `HTTP ${res.status}`);
      }
      const report: RiskReport = await res.json();
      setSimReport(report);
    } catch (err: unknown) {
      setSimError(err instanceof Error ? err.message : "Pre-sign simulation failed");
    } finally {
      setIsSimulating(false);
    }
  }

  async function submitDispute(report: RiskReport, targetAddr: string) {
    if (!disputeNotes.trim()) return;
    setIsSubmittingDispute(true);
    setDisputeFeedback(null);
    try {
      const res = await fetch(`${GATEWAY_URL}/v1/feedback/disputes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          evaluation_id: report.evaluation_id,
          chain_id: report.chain_id,
          address: targetAddr,
          proposed_label: disputeLabel.trim() || "BenignProtocol",
          analyst_notes: disputeNotes.trim(),
        }),
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const record: DisputeRecord = await res.json();
      setDisputes((prev) => [record, ...prev]);
      setDisputeFeedback(`Recorded dispute ${truncateHex(record.dispute_id, 4)}`);
      setDisputeNotes("");
      setShowDisputeForm(false);
      refreshStatusAndLatest();
    } catch (err: unknown) {
      setDisputeFeedback(err instanceof Error ? `Failed: ${err.message}` : "Failed to submit dispute");
    } finally {
      setIsSubmittingDispute(false);
    }
  }

  function copyToClipboard(text: string) {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 1500);
  }

  const ethChain = streamStatus?.chains.find((c) => c.chain_id === 1);
  const baseChain = streamStatus?.chains.find((c) => c.chain_id === 8453);
  const primaryProvider = ethChain?.provider_type || baseChain?.provider_type || "Connecting";
  const mlTelemetry = streamStatus?.ml_telemetry;
  const mlMetrics = mlTelemetry?.holdout_metrics;
  const openAlertsCount = alertRecords.filter((a) => a.triage_status === "OPEN").length;

  const statusDotClass =
    sseStatus === "offline" || (!streamStatus && streamError)
      ? "offline"
      : isPaused || sseStatus === "reconnecting"
      ? "paused"
      : "";
  const rpcStateSuffix =
    sseStatus === "offline" || (!streamStatus && streamError)
      ? "Offline"
      : isPaused
      ? "Paused"
      : sseStatus === "reconnecting"
      ? "Reconnecting"
      : null;

  return (
    <div className="shell-root">
      {/* Top Global Utility Bar */}
      <header className="topbar">
        <div className="topbar-brand">
          <span>Crypto Risk Analyzer</span>
        </div>

        <div className="topbar-actions">
          <div
            className="topbar-pill"
            title={
              streamStatus
                ? `Connected to ${streamStatus.chains.length} network(s) via ${primaryProvider}`
                : "Connecting to Gateway JSON-RPC stream"
            }
          >
            <span className={`status-dot ${statusDotClass}`} />
            {streamStatus ? (
              <>
                <strong>{primaryProvider}</strong>
                <span style={{ color: "var(--text-tertiary)" }}>Live</span>
                {rpcStateSuffix && (
                  <>
                    <span style={{ color: "var(--text-dim)" }}>·</span>
                    <span>{rpcStateSuffix}</span>
                  </>
                )}
              </>
            ) : (
              <span>{rpcStateSuffix || "Connecting RPC"}</span>
            )}
          </div>

          <div className="topbar-pill mono" title="Live Chainlink ETH/USD spot reference price">
            <span style={{ color: "var(--text-tertiary)" }}>ETH</span>
            <strong>
              {streamStatus?.eth_price_usd
                ? `USD ${streamStatus.eth_price_usd.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
                : "—"}
            </strong>
          </div>

          <button
            type="button"
            className="btn-secondary"
            style={{ height: 28, fontSize: 12 }}
            disabled={!streamStatus && !!streamError}
            onClick={() => setIsPaused((p) => !p)}
          >
            <span>{isPaused ? "Resume" : "Pause"}</span>
            <span className="kbd-hint">Space</span>
          </button>
        </div>
      </header>

      <div className="shell-body">
        {/* Left Navigation Sidebar */}
        <aside className="sidebar">
          <div>
            <button
              type="button"
              className="sidebar-search-trigger"
              onClick={() => {
                setActiveTab("inspector");
                setInspectorMode("address");
                setTimeout(() => inspectorInputRef.current?.focus(), 40);
              }}
            >
              <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                <span>Inspect address</span>
              </span>
              <span className="kbd-hint">⌘K</span>
            </button>

            <div className="nav-group">
              <button
                type="button"
                className={`nav-btn ${activeTab === "stream" ? "active" : ""}`}
                onClick={() => {
                  setActiveTab("stream");
                }}
              >
                <span className="nav-btn-left">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                  </svg>
                  <span>Stream</span>
                </span>
                <span className="nav-badge" title="Total evaluated transactions across all chains">
                  {streamStatus ? formatCompactCount(streamStatus.total_evaluated) : liveReports.length}
                </span>
              </button>

              <button
                type="button"
                className={`nav-btn ${activeTab === "inspector" ? "active" : ""}`}
                onClick={() => setActiveTab("inspector")}
              >
                <span className="nav-btn-left">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                  <span>Inspector</span>
                </span>
              </button>

              <button
                type="button"
                className={`nav-btn ${activeTab === "chains" ? "active" : ""}`}
                onClick={() => setActiveTab("chains")}
              >
                <span className="nav-btn-left">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                    <line x1="6" y1="6" x2="6.01" y2="6" />
                    <line x1="6" y1="18" x2="6.01" y2="18" />
                  </svg>
                  <span>Nodes & Models</span>
                </span>
              </button>
            </div>

            <div className="nav-group-label">Security</div>

            <div className="nav-group">
              <button
                type="button"
                className={`nav-btn ${activeTab === "alerts" ? "active" : ""}`}
                onClick={() => {
                  setActiveTab("alerts");
                }}
              >
                <span className="nav-btn-left">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                  <span>Alerts</span>
                </span>
                <span className="nav-badge" title={`${openAlertsCount} open / ${alertRecords.length} stored alerts`}>
                  {alertRecords.length}
                </span>
              </button>

              <button
                type="button"
                className={`nav-btn ${activeTab === "rules" ? "active" : ""}`}
                onClick={() => setActiveTab("rules")}
              >
                <span className="nav-btn-left">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                  <span>Rules</span>
                </span>
                <span className="nav-badge">{HEURISTIC_RULES.length}</span>
              </button>
            </div>
          </div>

          <div className="sidebar-footer">
            <div className="telemetry-footer-card">
              <div className="telemetry-row">
                <span>SSE Stream</span>
                <span className="mono" style={{ color: sseStatus === "connected" ? "var(--safe)" : sseStatus === "offline" ? "var(--danger)" : "var(--warn)" }}>
                  {sseStatus}
                </span>
              </div>
              <div className="telemetry-row">
                <span>ML Inference</span>
                <span className="mono" style={{ color: mlTelemetry?.onnx_active ? "var(--safe)" : mlTelemetry?.connected ? "var(--warn)" : "var(--danger)" }}>
                  {mlTelemetry?.onnx_active ? "ONNX" : mlTelemetry?.connected ? "Fallback" : "Offline"}
                </span>
              </div>
              <div className="telemetry-row">
                <span>Gateway</span>
                <span className="mono">{GATEWAY_URL.replace(/^https?:\/\//, "")}</span>
              </div>
            </div>
          </div>
        </aside>

