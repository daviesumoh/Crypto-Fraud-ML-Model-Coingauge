"""MLOps evaluation & drift monitoring metrics (PR-AUC, ECE, FPR, Population Stability Index)."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score


def compute_pr_auc(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    return float(average_precision_score(y_true, y_prob))


def compute_fpr_at_threshold(
    y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.55
) -> float:
    neg_mask = y_true == 0
    if not np.any(neg_mask):
        return 0.0
    false_positives = np.sum(y_prob[neg_mask] >= threshold)
    return float(false_positives / np.sum(neg_mask))


def compute_expected_calibration_error(
    y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10
) -> float:
    """Compute Expected Calibration Error (ECE) across uniform probability bins."""
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(y_true)
    if n == 0:
        return 0.0

    for idx in range(n_bins):
        lo, hi = bins[idx], bins[idx + 1]
        mask = (y_prob >= lo) & (y_prob <= hi if idx == n_bins - 1 else y_prob < hi)
        if np.any(mask):
            bin_acc = float(np.mean(y_true[mask]))
            bin_conf = float(np.mean(y_prob[mask]))
            ece += (np.sum(mask) / n) * abs(bin_acc - bin_conf)
    return float(ece)


def compute_psi(reference: np.ndarray, current: np.ndarray, n_bins: int = 10) -> float:
    """Compute Population Stability Index (PSI) to detect production feature drift (`PSI > 0.2`)."""
    quantiles = np.linspace(0, 100, n_bins + 1)
    edges = np.percentile(reference, quantiles)
    edges[0] = -np.inf
    edges[-1] = np.inf
    # Deduplicate any identical bin edges on binary/sparse columns
    edges = np.unique(edges)
    if len(edges) < 2:
        return 0.0

    ref_counts, _ = np.histogram(reference, bins=edges)
    cur_counts, _ = np.histogram(current, bins=edges)

    ref_pct = np.clip(ref_counts / max(1, len(reference)), 1e-4, 1.0)
    cur_pct = np.clip(cur_counts / max(1, len(current)), 1e-4, 1.0)

    return float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))

