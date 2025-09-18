"""Tier 1 Unsupervised Behavioral Anomaly Detector.

Combines a vectorized Random-Hyperplane Isolation Ensemble with an exact SVD bottleneck
Subspace Autoencoder trained purely on clean/benign Web3 wallet behavioral vectors,
achieving `< 1 ms` single-request inference latency without Python tree-dispatch overhead.
"""

from __future__ import annotations

import numpy as np
from sklearn.preprocessing import StandardScaler


class BehavioralAnomalyDetector:
    def __init__(
        self, n_hyperplanes: int = 128, latent_dim: int = 6, random_state: int = 42
    ) -> None:
        self.n_hyperplanes = n_hyperplanes
        self.latent_dim = latent_dim
        self.random_state = random_state
        self.scaler = StandardScaler()
        self._normals: np.ndarray = np.zeros((18, n_hyperplanes), dtype=np.float64)
        self._splits: np.ndarray = np.zeros((1, n_hyperplanes), dtype=np.float64)
        self._inlier_agreement_mean: np.ndarray = np.zeros(n_hyperplanes, dtype=np.float64)
        self._iso_p95: float = 1.0
        self._proj_matrix: np.ndarray = np.eye(18, dtype=np.float64)
        self._residual_p95: float = 1.0
        self.is_fitted: bool = False

    def fit(self, benign_features: np.ndarray) -> "BehavioralAnomalyDetector":
        scaled = np.ascontiguousarray(self.scaler.fit_transform(benign_features), dtype=np.float64)
        rng = np.random.default_rng(self.random_state)
        d = scaled.shape[1]

        # 1. Vectorized Random-Hyperplane Isolation Ensemble (SCiForest / LSH isolation cuts)
        raw_dirs = rng.normal(0.0, 1.0, size=(d, self.n_hyperplanes))
        self._normals = raw_dirs / (np.linalg.norm(raw_dirs, axis=0, keepdims=True) + 1e-8)
        with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
            proj = scaled @ self._normals  # (N, M)
        lo = np.percentile(proj, 2, axis=0, keepdims=True)
        hi = np.percentile(proj, 98, axis=0, keepdims=True)
        self._splits = rng.uniform(lo, hi)
        halfspace_freq = np.mean(proj >= self._splits, axis=0)  # empirical benign mass in halfspace
        self._inlier_agreement_mean = halfspace_freq

        # Isolation rarity score: negative log probability of falling into the same halfspaces as benign mass
        benign_side = (proj >= self._splits).astype(np.float64)
        benign_mass = benign_side * halfspace_freq + (1.0 - benign_side) * (1.0 - halfspace_freq)
        iso_rarity = -np.mean(np.log(np.clip(benign_mass, 1e-3, 1.0)), axis=1)
        self._iso_p95 = float(max(np.percentile(iso_rarity, 95), 1e-4))

        # 2. Closed-form SVD Bottleneck Subspace Autoencoder
        _, _, vt = np.linalg.svd(scaled, full_matrices=False)
        k = min(self.latent_dim, vt.shape[0])
        components = vt[:k]
        with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
            self._proj_matrix = components.T @ components
            recon = scaled @ self._proj_matrix
        mse = np.mean((scaled - recon) ** 2, axis=1)
        self._residual_p95 = float(max(np.percentile(mse, 95), 1e-4))
        self.is_fitted = True
        return self

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        scaled = np.ascontiguousarray(self.scaler.transform(X), dtype=np.float64)
        with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
            proj = scaled @ self._normals
            recon = scaled @ self._proj_matrix

        side = (proj >= self._splits).astype(np.float64)
        freq = self._inlier_agreement_mean[None, :]
        mass = side * freq + (1.0 - side) * (1.0 - freq)
        iso_rarity = -np.mean(np.log(np.clip(mass, 1e-3, 1.0)), axis=1)
        if_prob = 1.0 / (1.0 + np.exp(-4.0 * (iso_rarity / self._iso_p95 - 0.95)))

        mse = np.mean((scaled - recon) ** 2, axis=1)
        ae_prob = np.clip(mse / (3.5 * self._residual_p95), 0.0, 1.0)

        combined = 0.55 * if_prob + 0.45 * ae_prob
        return np.clip(combined, 0.01, 0.99)

    def score_single(self, x: np.ndarray) -> float:
        return float(self.score_batch(x.reshape(1, -1))[0])
