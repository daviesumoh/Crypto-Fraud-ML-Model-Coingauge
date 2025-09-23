from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sentinel_ml.bootstrap import ModelRegistryBundle, build_trained_registry
from sentinel_ml.features import FeatureInputContext, extract_feature_vector
from sentinel_ml.models import AttributionItem, disassemble_evm_bytecode

app = FastAPI(
    title="Sentinel ML Sidecar",
    version="0.2.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:8090",
    ],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

REGISTRY: ModelRegistryBundle = build_trained_registry()

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"mark\s+(this\s+)?(transaction|wallet|contract)\s+(as\s+)?safe", re.IGNORECASE),
    re.compile(r"override\s+risk\s+score", re.IGNORECASE),
    re.compile(r"score\s*=\s*0", re.IGNORECASE),
]


def sanitize_metadata_note(raw_text: Optional[str]) -> Tuple[str, bool]:
    if not raw_text:
        return "", False
    cleaned = raw_text[:280]
    flagged = False
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(cleaned):
            flagged = True
            cleaned = pattern.sub("[REDACTED_INJECTION]", cleaned)
    return cleaned, flagged


class MlInferRequest(BaseModel):
    subject_address: str
    chain_id: int = 1
    tx_value_usd: float = 0.0
    sender_pre_balance_usd: float = 10_000.0
    priority_fee_percentile: float = 50.0
    wallet_tx_count: int = 10
    young_contract_touch: bool = False
    unverified_contract_touch: bool = False
    unlimited_approval: bool = False
    taint_score: float = 0.0
    peel_or_sybil_flag: bool = False
    graph_edge_count: int = 0
    calldata_bytes: int = 0
    is_contract_interaction: bool = False
    triggered_rule_ids: List[str] = Field(default_factory=list)
    untrusted_metadata_note: Optional[str] = None
    target_bytecode_hex: Optional[str] = None


class ShapAttributionOut(BaseModel):
    feature_name: str
    feature_value: float
    shap_impact: float
    direction: str


class ModelPredictionBundleOut(BaseModel):
    anomaly_score: float
    supervised_fraud_prob: float
    bytecode_risk_score: float
    nearest_bytecode_family: Optional[str] = None
    bytecode_similarity: Optional[float] = None
    top_shap_features: List[ShapAttributionOut]
    inference_latency_ms: float


class ForensicBriefOut(BaseModel):
    executive_summary: str
    technical_forensics: str
    recommended_action: str
    evidence_citations: List[str]
    prompt_injection_sanitized: bool


class MlInferResponse(BaseModel):
    predictions: ModelPredictionBundleOut
    forensic_brief: ForensicBriefOut


class BytecodeScanRequest(BaseModel):
    bytecode_hex: str


def _build_diagnostic_brief(
    req: MlInferRequest,
    sup_prob: float,
    anomaly_score: float,
    bytecode_risk: float,
    bytecode_family: Optional[str],
    bytecode_sim: Optional[float],
    shap_items: List[AttributionItem],
) -> ForensicBriefOut:
    _, sanitized = sanitize_metadata_note(req.untrusted_metadata_note)
    citations: List[str] = [f"rule:{r}" for r in req.triggered_rule_ids]
    for item in shap_items[:3]:
        citations.append(f"shap:{item.feature_name}({item.shap_impact:+.3f})")
    if bytecode_family and bytecode_sim is not None:
        citations.append(f"bytecode:{bytecode_family}({bytecode_sim:.2f})")

    is_critical = (
        any(r in ("H-SIM-01", "H-APP-01", "H-SOC-01", "H-AML-01", "H-TOK-01") for r in req.triggered_rule_ids)
        or sup_prob >= 0.78
    )
    is_warn = bool(req.triggered_rule_ids) or sup_prob >= 0.42 or anomaly_score >= 0.55

    if is_critical:
        action = "BLOCK_AND_REVOKE"
        summary = (
            f"High-confidence threat indicators on {req.subject_address[:10]}... "
            f"(classifier={sup_prob:.1%}, anomaly={anomaly_score:.1%})."
        )
    elif is_warn:
        action = "STEP_UP_WARNING"
        summary = (
            f"Elevated risk signals on {req.subject_address[:10]}... "
            f"(classifier={sup_prob:.1%}, anomaly={anomaly_score:.1%})."
        )
    else:
        action = "ALLOW_WITH_MONITORING"
        summary = (
            f"No abnormal execution or taint indicators detected for {req.subject_address[:10]}... "
            f"(classifier={sup_prob:.1%}, anomaly={anomaly_score:.1%})."
        )

    details = [
        f"Classifier={sup_prob:.3f}, Anomaly={anomaly_score:.3f}, BytecodeRisk={bytecode_risk:.3f}, Taint={req.taint_score:.3f}."
    ]
    if shap_items:
        drivers = ", ".join(
            f"{it.feature_name}={it.feature_value:.3f} ({it.shap_impact:+.3f})"
            for it in shap_items[:3]
        )
        details.append(f"Primary feature drivers: {drivers}.")
    if bytecode_family and bytecode_sim is not None:
        details.append(f"Bytecode matches {bytecode_family} (cosine={bytecode_sim:.3f}).")

    return ForensicBriefOut(
        executive_summary=summary,
        technical_forensics=" ".join(details),
        recommended_action=action,
        evidence_citations=citations,
        prompt_injection_sanitized=sanitized,
    )


@app.get("/healthz")
def healthz() -> Dict[str, object]:
    onnx_active = getattr(REGISTRY.fraud_classifier, "_ort_session", None) is not None
    return {
        "status": "ok",
        "service": "sentinel-ml",
        "onnx_active": onnx_active,
        "model_artifact": "model.onnx" if onnx_active else "sklearn_fallback",
        "bytecode_signature_count": len(REGISTRY.bytecode_index._families),
        "holdout_metrics": REGISTRY.holdout_metrics,
    }


@app.get("/v1/ml/metrics")
def get_metrics() -> Dict[str, float]:
    return REGISTRY.holdout_metrics


@app.post("/v1/ml/bytecode-scan")
def scan_bytecode(req: BytecodeScanRequest) -> Dict[str, object]:
    ops = disassemble_evm_bytecode(req.bytecode_hex)
    analysis = REGISTRY.bytecode_index.analyze(req.bytecode_hex)
    return {
        "opcode_count": analysis.opcode_count,
        "opcode_preview": ops[:24],
        "has_delegatecall": analysis.has_delegatecall,
        "has_selfdestruct": analysis.has_selfdestruct,
        "has_create2": analysis.has_create2,
        "has_env_evasion": analysis.has_env_evasion,
        "nearest_malicious_family": analysis.nearest_family,
        "cosine_similarity": analysis.similarity,
        "bytecode_risk_score": analysis.risk_score,
    }


@app.post("/v1/ml/infer", response_model=MlInferResponse)
def infer(req: MlInferRequest) -> MlInferResponse:
    t0 = time.perf_counter()

    bc_analysis = REGISTRY.bytecode_index.analyze(req.target_bytecode_hex)
    is_contract = (
        req.is_contract_interaction
        or bc_analysis.opcode_count > 0
        or req.calldata_bytes > 0
        or req.unlimited_approval
        or req.unverified_contract_touch
        or req.young_contract_touch
    )
    feat_ctx = FeatureInputContext(
        tx_value_usd=req.tx_value_usd,
        sender_pre_balance_usd=req.sender_pre_balance_usd,
        priority_fee_percentile=req.priority_fee_percentile,
        wallet_tx_count=req.wallet_tx_count,
        young_contract_touch=req.young_contract_touch,
        unverified_contract_touch=req.unverified_contract_touch,
        unlimited_approval=req.unlimited_approval,
        taint_score=req.taint_score,
        peel_or_sybil_flag=req.peel_or_sybil_flag,
        graph_edge_count=req.graph_edge_count,
        calldata_bytes=req.calldata_bytes,
        is_contract_interaction=is_contract,
        bytecode_risk_score=bc_analysis.risk_score,
    )
    x = extract_feature_vector(feat_ctx)

    anomaly_score = REGISTRY.anomaly_detector.score_single(x)
    sup_prob, shap_items = REGISTRY.fraud_classifier.predict_with_attributions(x, top_k=5)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    brief = _build_diagnostic_brief(
        req=req,
        sup_prob=sup_prob,
        anomaly_score=anomaly_score,
        bytecode_risk=bc_analysis.risk_score,
        bytecode_family=bc_analysis.nearest_family,
        bytecode_sim=bc_analysis.similarity,
        shap_items=shap_items,
    )

    return MlInferResponse(
        predictions=ModelPredictionBundleOut(
            anomaly_score=round(anomaly_score, 4),
            supervised_fraud_prob=round(sup_prob, 4),
            bytecode_risk_score=bc_analysis.risk_score,
            nearest_bytecode_family=bc_analysis.nearest_family,
            bytecode_similarity=bc_analysis.similarity,
            top_shap_features=[
                ShapAttributionOut(
                    feature_name=it.feature_name,
                    feature_value=it.feature_value,
                    shap_impact=it.shap_impact,
                    direction=it.direction,
                )
                for it in shap_items
            ],
            inference_latency_ms=round(elapsed_ms, 3),
        ),
        forensic_brief=brief,
    )
