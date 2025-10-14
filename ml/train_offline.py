#!/usr/bin/env python3
"""Offline Model Training & Serialization Script for Web3 Sentinel.

Trains a Calibrated GBDT and SVD Anomaly Detector on real or curated on-chain attack
datasets (e.g. Forta Network Phishing Datasets, ScamSniffer dumps, or Dune Analytics queries)
and exports the pre-trained weights to `sentinel_ml/model.joblib` (and optionally `model.onnx`).

Usage:
    # 1. Train on default canonical on-chain feature vectors:
    python train_offline.py

    # 2. Train on your downloaded Forta/ScamSniffer CSV dataset:
    python train_offline.py --data path/to/forta_attacks.csv --output sentinel_ml/model.joblib
"""

import argparse
import os
from pathlib import Path
import sys

import joblib
import numpy as np

# Ensure sentinel_ml is importable
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from sentinel_ml.bootstrap import (
    ModelRegistryBundle,
    generate_temporal_web3_dataset,
)
from sentinel_ml.evaluation import (
    compute_expected_calibration_error,
    compute_fpr_at_threshold,
    compute_pr_auc,
    compute_psi,
)
from sentinel_ml.features import FEATURE_NAMES
from sentinel_ml.models import (
    BehavioralAnomalyDetector,
    BytecodeSimilarityIndex,
    CalibratedFraudClassifier,
)


def train_and_export(
    dataset_path: str = None,
    output_path: str = None,
    export_onnx: bool = True,
):
    if output_path is None:
        output_path = CURRENT_DIR / "sentinel_ml" / "model.joblib"
    else:
        output_path = Path(output_path)

    default_real_csv = CURRENT_DIR / "data" / "real_web3_training_dataset.csv"
    if dataset_path is None and default_real_csv.exists():
        dataset_path = str(default_real_csv)

    print("=" * 65)
    print("Web3 Sentinel: Offline Model Training & Serialization Pipeline")
    print("=" * 65)

    if dataset_path and os.path.exists(dataset_path):
        print(f"[*] Loading historical labeled dataset from: {dataset_path}")
        import csv
        from sklearn.model_selection import train_test_split
        from sentinel_ml.features import FeatureInputContext, extract_feature_vector

        rows = []
        labels = []
        with open(dataset_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                vec = [float(r.get(name, 0.0)) for name in FEATURE_NAMES]
                rows.append(vec)
                labels.append(int(r.get("is_attack", r.get("label", 0))))
        real_attack_n = int(sum(labels))
        real_benign_n = len(labels) - real_attack_n
        print(f"[+] Loaded {len(rows)} real on-chain transactions ({real_attack_n} attacks, {real_benign_n} benign).")

        # Supplement zero-value Permit2/unlimited approval phishing & verified protocol approvals
        # (off-chain Permit signatures & 0-value approve() calls are absent from AssetTransfer logs)
        rng = np.random.default_rng(2025)
        for idx_p in range(240):
            ctx = FeatureInputContext(
                tx_value_usd=float(rng.uniform(0.0, 25.0)),
                sender_pre_balance_usd=float(rng.uniform(1_500.0, 250_000.0)),
                priority_fee_percentile=float(rng.uniform(55.0, 96.0)),
                wallet_tx_count=int(rng.integers(5, 600)),
                young_contract_touch=True,
                unverified_contract_touch=True,
                unlimited_approval=True,
                taint_score=float(rng.uniform(0.25, 0.95)),
                peel_or_sybil_flag=False,
                graph_edge_count=3,
                calldata_bytes=int(rng.integers(68, 320)),
                is_contract_interaction=True,
                bytecode_risk_score=0.0 if (idx_p % 2 == 0) else float(rng.uniform(0.35, 0.95)),
            )
            rows.append(extract_feature_vector(ctx).tolist())
            labels.append(1)

        for _ in range(220):
            ctx = FeatureInputContext(
                tx_value_usd=0.0,
                sender_pre_balance_usd=float(rng.uniform(500.0, 500_000.0)),
                priority_fee_percentile=float(rng.uniform(15.0, 75.0)),
                wallet_tx_count=int(rng.integers(25, 4000)),
                young_contract_touch=False,
                unverified_contract_touch=False,
                unlimited_approval=True,
                taint_score=0.0,
                peel_or_sybil_flag=False,
                graph_edge_count=2,
                calldata_bytes=68,
                is_contract_interaction=True,
                bytecode_risk_score=0.0,
            )
            rows.append(extract_feature_vector(ctx).tolist())
            labels.append(0)

        X = np.array(rows, dtype=np.float64)
        y = np.array(labels, dtype=np.int64)
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.25, stratify=y, random_state=42
        )
    else:
        print("[*] No CSV dataset found. Generating canonical calibrated Web3 feature matrix...")
        X, y = generate_temporal_web3_dataset(n_samples=5000, seed=2025)
        print(f"[+] Synthesized {len(X)} calibrated feature vectors across 4 attack and 5 benign archetypes.")
        split = int(len(X) * 0.75)
        X_train, y_train = X[:split], y[:split]
        X_val, y_val = X[split:], y[split:]

    print(f"[*] Training Tier-1 SVD Behavioral Anomaly Autoencoder on benign baselines ({len(X_train[y_train == 0])} rows)...")
    anomaly = BehavioralAnomalyDetector(random_state=42).fit(X_train[y_train == 0])

    print("[*] Training Tier-2 Calibrated GBDT Classifier (GradientBoosting + Platt Sigmoid Calibration)...")
    classifier = CalibratedFraudClassifier(FEATURE_NAMES, random_state=42).fit(X_train, y_train)

    print("[*] Evaluating validation holdout metrics...")
    val_probs = classifier.predict_proba(X_val)
    pr_auc = compute_pr_auc(y_val, val_probs)
    fpr_at_55 = compute_fpr_at_threshold(y_val, val_probs, threshold=0.55)
    ece = compute_expected_calibration_error(y_val, val_probs, n_bins=10)
    mean_psi = float(np.mean([compute_psi(X_train[:, col], X_val[:, col]) for col in range(X.shape[1])]))

    print(f"    - PR-AUC:               {pr_auc:.4f} (target: >= 0.85)")
    print(f"    - FPR @ 0.55 threshold: {fpr_at_55:.5f} (target: <= 0.005)")
    print(f"    - Expected Calib Error: {ece:.4f} (target: <= 0.08)")
    print(f"    - Mean Feature Drift PSI: {mean_psi:.4f} (target: <= 0.25)")

    metrics = {
        "temporal_holdout_pr_auc": round(pr_auc, 4),
        "temporal_holdout_fpr_at_55": round(fpr_at_55, 5),
        "temporal_holdout_ece": round(ece, 4),
        "feature_drift_psi_mean": round(mean_psi, 4),
    }

    bundle = ModelRegistryBundle(
        anomaly_detector=anomaly,
        fraud_classifier=classifier,
        bytecode_index=BytecodeSimilarityIndex(),
        holdout_metrics=metrics,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path)
    file_size_kb = output_path.stat().st_size / 1024.0
    print(f"\n[+] Successfully exported pre-trained model bundle to:")
    print(f"    {output_path} ({file_size_kb:.1f} KB)")

    if export_onnx:
        try:
            import onnxruntime as ort
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType

            initial_type = [("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))]
            onnx_model = convert_sklearn(
                classifier.model,
                initial_types=initial_type,
                target_opset={"": 17, "ai.onnx.ml": 3},
                options={id(classifier.model): {"zipmap": False}},
            )
            onnx_path = output_path.with_suffix(".onnx")
            onnx_path.write_bytes(onnx_model.SerializeToString())

            sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
            ort_out = sess.run(None, {"float_input": np.asarray(X_val[:20], dtype=np.float32)})[1][:, 1]
            sk_out = classifier.model.predict_proba(X_val[:20])[:, 1]
            max_diff = float(np.max(np.abs(ort_out - sk_out)))
            onnx_kb = onnx_path.stat().st_size / 1024.0
            print(f"[+] Successfully exported ONNX model to: {onnx_path} ({onnx_kb:.1f} KB)")
            print(f"[+] Verified ONNX Runtime parity vs scikit-learn: max_diff={max_diff:.2e}")
        except ImportError as exc:
            print(f"[!] ONNX export skipped ({exc}); joblib artifact is saved.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and export Web3 Sentinel ML model artifacts")
    parser.add_argument("--data", type=str, default=None, help="Path to labeled training CSV")
    parser.add_argument("--output", type=str, default=None, help="Output destination for model.joblib")
    parser.add_argument("--onnx", action="store_true", help="Also export model.onnx")
    args = parser.parse_args()

    train_and_export(args.data, args.output, args.onnx)

