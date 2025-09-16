from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List

import numpy as np

FEATURE_NAMES: List[str] = [
    "tx_value_log_usd",
    "balance_drain_ratio",
    "priority_fee_percentile_norm",
    "wallet_age_log_txs",
    "calldata_size_log",
    "is_contract_interaction",
    "multi_hop_haircut_taint",
    "peel_or_sybil_flag",
    "unlimited_approval_flag",
    "unverified_contract_flag",
    "young_contract_flag",
    "bytecode_risk_score",
]


@dataclass
class FeatureInputContext:
    tx_value_usd: float
    sender_pre_balance_usd: float
    priority_fee_percentile: float
    wallet_tx_count: int
    young_contract_touch: bool
    unverified_contract_touch: bool
    unlimited_approval: bool
    taint_score: float
    peel_or_sybil_flag: bool
    graph_edge_count: int = 0
    calldata_bytes: int = 0
    is_contract_interaction: bool = False
    bytecode_risk_score: float = 0.0


def extract_feature_vector(ctx: FeatureInputContext) -> np.ndarray:
    tx_log = math.log1p(max(0.0, ctx.tx_value_usd)) / 15.0
    pre_bal = max(1.0, ctx.sender_pre_balance_usd)
    drain_ratio = min(1.0, max(0.0, ctx.tx_value_usd) / pre_bal)
    prio_norm = min(1.0, max(0.0, ctx.priority_fee_percentile) / 100.0)
    age_log = min(1.0, math.log1p(max(0, ctx.wallet_tx_count)) / 10.0)
    calldata_log = min(1.0, math.log1p(max(0, ctx.calldata_bytes)) / 8.0)
    is_contract = 1.0 if ctx.is_contract_interaction else 0.0
    taint = min(1.0, max(0.0, ctx.taint_score))
    peel_sybil = 1.0 if ctx.peel_or_sybil_flag else 0.0
    unlim = 1.0 if ctx.unlimited_approval else 0.0
    unver = 1.0 if ctx.unverified_contract_touch else 0.0
    young = 1.0 if ctx.young_contract_touch else 0.0
    bytecode_risk = min(1.0, max(0.0, ctx.bytecode_risk_score))

    return np.array(
        [
            tx_log,
            drain_ratio,
            prio_norm,
            age_log,
            calldata_log,
            is_contract,
            taint,
            peel_sybil,
            unlim,
            unver,
            young,
            bytecode_risk,
        ],
        dtype=np.float64,
    )
