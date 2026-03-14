# CoinGauge ML Sidecar (`sentinel_ml`)

FastAPI inference service providing tabular fraud scoring, unsupervised anomaly detection, bytecode opcode analysis, and diagnostic summaries for CoinGauge:

1. **Feature Extraction (`sentinel_ml/features/extractor.py`)**: 12-dimensional normalized transaction, wallet, contract, taint, and bytecode feature vector.
2. **Unsupervised Anomaly Detection (`sentinel_ml/models/anomaly.py`)**: Random-hyperplane isolation cuts combined with SVD subspace reconstruction error trained on benign transactions.
3. **Calibrated GBDT + ONNX Runtime (`sentinel_ml/models/tabular_classifier.py`)**: Gradient boosted trees with Platt sigmoid calibration exported to `model.onnx`, paired with single-feature ablation attributions.
4. **Opcode Disassembler & Similarity (`sentinel_ml/models/bytecode_similarity.py`)**: Operand-stripped EVM opcode 2/3-gram blake2b embeddings matched against 253 exploit/drainer signatures (`data/malicious_bytecodes.json` plus canonical templates).
5. **Metadata Sanitizer (`sentinel_ml/server.py`)**: Filters prompt-injection patterns out of untrusted transaction metadata strings before generating deterministic brief text.
