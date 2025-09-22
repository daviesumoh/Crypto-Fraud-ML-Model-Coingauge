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


