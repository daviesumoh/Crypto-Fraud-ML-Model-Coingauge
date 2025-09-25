from fastapi.testclient import TestClient

from sentinel_ml.models import BytecodeSimilarityIndex
from sentinel_ml.server import REGISTRY as SERVER_REGISTRY, app, sanitize_metadata_note


def test_temporal_holdout_meets_production_slo_targets() -> None:
    metrics = SERVER_REGISTRY.holdout_metrics
    assert metrics["temporal_holdout_pr_auc"] >= 0.92
    assert metrics["temporal_holdout_fpr_at_55"] <= 0.01
    assert metrics["temporal_holdout_ece"] <= 0.05
    assert metrics["feature_drift_psi_mean"] < 0.20


def test_polymorphic_drainer_address_rotation_cannot_evade_opcode_similarity() -> None:
    idx = BytecodeSimilarityIndex()
    mutated_pink_drainer = (
        "0x366000803760008036600073deadbeefdeadbeefdeadbeefdeadbeefdeadbeef5af43d82803e903d91602b57fd5bf3"
    )
    family, sim = idx.query(mutated_pink_drainer)
    assert family == "PinkDrainer_MulticallProxy"
    assert sim is not None and sim >= 0.99


def test_benign_wallet_and_transfer_score_low_anomaly() -> None:
    client = TestClient(app)
    resp = client.post(
        "/v1/ml/infer",
        json={
            "subject_address": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
            "chain_id": 1,
            "tx_value_usd": 0.0,
            "sender_pre_balance_usd": 650000.0,
            "priority_fee_percentile": 45.0,
            "wallet_tx_count": 1520,
            "young_contract_touch": False,
            "unverified_contract_touch": False,
            "unlimited_approval": False,
            "taint_score": 0.0,
            "peel_or_sybil_flag": False,
            "graph_edge_count": 0,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["predictions"]["anomaly_score"] < 0.25
    assert body["predictions"]["supervised_fraud_prob"] < 0.15


