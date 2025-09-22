from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np

from sentinel_ml.evaluation import (
    compute_expected_calibration_error,
    compute_fpr_at_threshold,
    compute_pr_auc,
    compute_psi,
)
from sentinel_ml.features import FEATURE_NAMES, FeatureInputContext, extract_feature_vector
from sentinel_ml.models import (
    BehavioralAnomalyDetector,
    BytecodeSimilarityIndex,
    CalibratedFraudClassifier,
)


def generate_temporal_web3_dataset(
    n_samples: int = 2000, seed: int = 2025
) -> Tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    rows = []
    labels = []

    for i in range(n_samples):
        is_attack = (i % 5) == 0
        if not is_attack:
            archetype = i % 5
            if archetype == 0:
                tx_val = 0.0
                pre_bal = float(rng.lognormal(mean=8.0, sigma=2.5))
                calldata_len = int(rng.integers(68, 512))
                is_contract = True
                unlim = rng.random() < 0.18
            elif archetype == 1:
                tx_val = float(rng.lognormal(mean=5.8, sigma=1.8))
                pre_bal = tx_val * float(rng.uniform(2.5, 80.0))
                calldata_len = 0
                is_contract = False
                unlim = False
            elif archetype == 2:
                tx_val = float(rng.lognormal(mean=7.2, sigma=1.6))
                pre_bal = tx_val * float(rng.uniform(1.8, 30.0))
                calldata_len = int(rng.integers(132, 1024))
                is_contract = True
                unlim = False
            elif archetype == 3:
                tx_val = 0.0
                pre_bal = float(rng.uniform(50.0, 2_500_000.0))
                calldata_len = 0
                is_contract = False
                unlim = False
            else:
                tx_val = float(rng.uniform(1.0, 400.0))
                pre_bal = float(rng.uniform(500.0, 25_000.0))
                calldata_len = int(rng.choice([0, 68, 100]))
                is_contract = calldata_len > 0
                unlim = False

            ctx = FeatureInputContext(
                tx_value_usd=tx_val,
                sender_pre_balance_usd=pre_bal,
                priority_fee_percentile=float(rng.uniform(5.0, 88.0)),
                wallet_tx_count=int(rng.integers(1, 5000)),
                young_contract_touch=(archetype == 2 and rng.random() < 0.04),
                unverified_contract_touch=(rng.random() < 0.03),
                unlimited_approval=unlim,
                taint_score=float(rng.uniform(0.0, 0.04)),
                peel_or_sybil_flag=False,
                graph_edge_count=int(rng.integers(0, 12)),
                calldata_bytes=calldata_len,
                is_contract_interaction=is_contract,
                bytecode_risk_score=float(rng.uniform(0.0, 0.15)) if is_contract else 0.0,
            )
            rows.append(extract_feature_vector(ctx))
            labels.append(0)
        else:
            threat_kind = i % 4
            if threat_kind == 0:
                ctx = FeatureInputContext(
                    tx_value_usd=float(rng.uniform(0.0, 25.0)),
                    sender_pre_balance_usd=float(rng.uniform(1_500.0, 180_000.0)),
                    priority_fee_percentile=float(rng.uniform(50.0, 96.0)),
                    wallet_tx_count=int(rng.integers(8, 600)),
                    young_contract_touch=True,
                    unverified_contract_touch=True,
                    unlimited_approval=True,
                    taint_score=float(rng.uniform(0.30, 0.95)),
                    peel_or_sybil_flag=False,
                    graph_edge_count=int(rng.integers(1, 10)),
                    calldata_bytes=int(rng.integers(68, 320)),
                    is_contract_interaction=True,
                    bytecode_risk_score=float(rng.uniform(0.60, 0.98)),
                )
            elif threat_kind == 1:
                val = float(rng.uniform(12_000.0, 300_000.0))
                ctx = FeatureInputContext(
                    tx_value_usd=val,
                    sender_pre_balance_usd=val * float(rng.uniform(1.0, 1.06)),
                    priority_fee_percentile=float(rng.uniform(72.0, 99.0)),
                    wallet_tx_count=int(rng.integers(1, 6)),
                    young_contract_touch=False,
                    unverified_contract_touch=False,
                    unlimited_approval=False,
                    taint_score=float(rng.uniform(0.25, 0.90)),
                    peel_or_sybil_flag=True,
                    graph_edge_count=int(rng.integers(5, 25)),
                    calldata_bytes=0,
                    is_contract_interaction=False,
                    bytecode_risk_score=0.0,
                )
            elif threat_kind == 2:
                val = float(rng.uniform(1_500.0, 120_000.0))
                ctx = FeatureInputContext(
                    tx_value_usd=val,
                    sender_pre_balance_usd=val * float(rng.uniform(1.0, 1.03)),
                    priority_fee_percentile=float(rng.uniform(98.5, 99.99)),
                    wallet_tx_count=int(rng.integers(10, 400)),
                    young_contract_touch=False,
                    unverified_contract_touch=True,
                    unlimited_approval=False,
                    taint_score=float(rng.uniform(0.18, 0.70)),
                    peel_or_sybil_flag=False,
                    graph_edge_count=int(rng.integers(1, 6)),
                    calldata_bytes=0,
                    is_contract_interaction=False,
                    bytecode_risk_score=0.0,
                )
            else:
                val = float(rng.uniform(800.0, 80_000.0))
                ctx = FeatureInputContext(
                    tx_value_usd=val,
                    sender_pre_balance_usd=val * float(rng.uniform(1.1, 2.5)),
                    priority_fee_percentile=float(rng.uniform(45.0, 92.0)),
                    wallet_tx_count=int(rng.integers(15, 500)),
                    young_contract_touch=True,
                    unverified_contract_touch=True,
                    unlimited_approval=False,
                    taint_score=float(rng.uniform(0.15, 0.65)),
                    peel_or_sybil_flag=False,
                    graph_edge_count=int(rng.integers(1, 8)),
                    calldata_bytes=int(rng.integers(68, 256)),
                    is_contract_interaction=True,
                    bytecode_risk_score=float(rng.uniform(0.55, 0.95)),
                )
            rows.append(extract_feature_vector(ctx))
            labels.append(1)

    return np.vstack(rows), np.array(labels, dtype=np.int64)


@dataclass
class ModelRegistryBundle:
    anomaly_detector: BehavioralAnomalyDetector
    fraud_classifier: CalibratedFraudClassifier
    bytecode_index: BytecodeSimilarityIndex
    holdout_metrics: Dict[str, float]


import joblib
from pathlib import Path

def build_trained_registry() -> ModelRegistryBundle:
    base_dir = Path(__file__).resolve().parent
    serialized_path = base_dir / "model.joblib"
    onnx_path = base_dir / "model.onnx"
    if serialized_path.exists():
        try:
            bundle = joblib.load(serialized_path)
            if isinstance(bundle, ModelRegistryBundle):
                if onnx_path.exists():
                    bundle.fraud_classifier.attach_onnx_session(str(onnx_path))
                bundle.bytecode_index = BytecodeSimilarityIndex()
                return bundle
        except Exception:
            pass

    X, y = generate_temporal_web3_dataset(n_samples=2000, seed=2025)
    split = int(len(X) * 0.75)
    X_train, y_train = X[:split], y[:split]
    X_val, y_val = X[split:], y[split:]

    anomaly = BehavioralAnomalyDetector(random_state=42).fit(X_train[y_train == 0])
    classifier = CalibratedFraudClassifier(FEATURE_NAMES, random_state=42).fit(X_train, y_train)

    val_probs = classifier.predict_proba(X_val)
    metrics = {
        "temporal_holdout_pr_auc": round(compute_pr_auc(y_val, val_probs), 4),
        "temporal_holdout_fpr_at_55": round(
            compute_fpr_at_threshold(y_val, val_probs, threshold=0.55), 5
        ),
        "temporal_holdout_ece": round(
            compute_expected_calibration_error(y_val, val_probs, n_bins=10), 4
        ),
        "feature_drift_psi_mean": round(
            float(
                np.mean(
                    [compute_psi(X_train[:, col], X_val[:, col]) for col in range(X.shape[1])]
                )
            ),
            4,
        ),
    }

    return ModelRegistryBundle(
        anomaly_detector=anomaly,
        fraud_classifier=classifier,
        bytecode_index=BytecodeSimilarityIndex(),
        holdout_metrics=metrics,
    )
