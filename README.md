# CoinGauge

Real-time Ethereum and Base transaction risk analyzer combining local `revm` execution simulation, deterministic threat heuristics, ONNX tabular scoring, and opcode similarity checks.

## Architecture

```
.
├── crates/
│   ├── common-types/       # Shared transaction, simulation, and risk schemas
│   ├── evm-simulator/      # Local revm state-diff simulator and ABI permission decoder
│   ├── heuristics-engine/  # 9 deterministic threat rules and haircut taint tracker
│   ├── chain-indexer/      # JSON-RPC block/price client, reorg tracker, threat intel map
│   └── risk-gateway/       # Axum HTTP + SSE server (:8090) and JSONL alert/dispute store
├── ml/
│   ├── sentinel_ml/        # FastAPI sidecar (:8091) running model.onnx, SVD anomaly, opcode index
│   ├── data/               # Real mainnet/Forta/ScamSniffer feature CSV and drainer bytecodes
│   └── tests/              # Holdout metric, opcode invariance, and concurrency tests
├── web/                    # Next.js 14 monitoring workbench, alerts triage, and pre-sign simulator
└── env/                    # Environment variable template (.env.example)
```

## Components

### Risk Gateway (`crates/risk-gateway`)
HTTP and Server-Sent Events service bound on `:8090`:
- `GET /healthz`: Gateway health, cached ETH/USD price, and persisted alert count.
- `POST /v1/evaluate/transaction`: Runs pre-sign `revm` simulation, heuristic checks, and ML scoring.
- `POST /v1/evaluate/wallet`: Evaluates wallet history and graph edges without live block simulation.
- `GET /v1/wallet/inspect?address=...&chain_id=...`: Live RPC inspection of balance, nonce, bytecode, and asset transfers (30s TTL wallet cache).
- `GET /v1/stream/events`: SSE push stream for evaluated Ethereum Mainnet (`chain_id=1`) and Base Mainnet (`chain_id=8453`) transactions.
- `GET /v1/stream/latest`: Returns up to the 100 most recent evaluated stream transactions.
- `GET /v1/stream/alerts` & `PATCH /v1/stream/alerts/:evaluation_id`: Disk-persisted alert log (up to 500 transactions with `risk_score >= 25`) with analyst triage updates (`OPEN`, `ACKNOWLEDGED`, `CONFIRMED`, `FALSE_POSITIVE`).
- `GET /v1/feedback/disputes` & `POST /v1/feedback/disputes`: Validated, disk-persisted false-positive and label dispute log.
- `GET /v1/audit-log`: Recent pre-sign and wallet evaluations held in memory (capped at 200).
- Embeds a 10,413-entry normalized address lookup map sourced from Forta Network, ScamSniffer, and canonical protocol labels (`crates/chain-indexer/data/threat_intel.json`).

### EVM Simulator (`crates/evm-simulator`)
Executes candidate transactions inside an in-memory `revm` instance with RPC-backed contract bytecode/balance seeding (5m code cache) and mainnet block-header defaults to surface:
- Native ETH balance movements and reverted execution reasons.
- ERC-20 `approve`, `increaseAllowance`, ERC-721 `setApprovalForAll`, EIP-2612 `permit`, and Permit2 approvals decoded from calldata and logs.
- Conditional external calls following `COINBASE`, `GASPRICE`, or `PREVRANDAO`.

### Heuristics Engine (`crates/heuristics-engine`)
Implements 9 deterministic rules and composite risk calibration:
- Execution & token traps: `H-SIM-01` (asymmetric outflow), `H-APP-01` (excessive/EOA approvals), `H-EVM-01` (metamorphic/evasion/untrusted non-zero `DELEGATECALL`), `H-TOK-01` (sell trap / high transfer tax).
- Wallet & mempool signals: `H-SOC-01` (prefix/suffix dust address poisoning), `H-MEM-01` (key-sweeper high-fee full balance outflow).
- Graph & threat intelligence: `H-AML-01` (sanctioned/threat-intel haircut taint with omnibus sink termination), `H-GRF-01` (peel chain), `H-GRF-02` (sybil gas fan-out cluster).

### ML Sidecar (`ml/sentinel_ml`)
FastAPI service on `:8091`:
- `ml/build_real_dataset.py` and `ml/train_offline.py` build labeled feature vectors from Ethereum Mainnet blocks, Forta exploit deployments, and ScamSniffer addresses, then serialize `sentinel_ml/model.joblib` and `sentinel_ml/model.onnx`.
- **Calibrated GBDT Classifier**: Platt-calibrated gradient-boosted classifier executed via `onnxruntime` with marginal ablation feature attributions.
- **Behavioral Anomaly Detector**: Random-hyperplane isolation + SVD subspace reconstruction residual fitted on benign baseline vectors.
- **Opcode Similarity Index**: 64-dim blake2b n-gram cosine lookup against 253 opcode signatures (`ml/data/malicious_bytecodes.json` plus structural templates) and tight-window `JUMPI` checks after env opcodes.
- **Metadata Sanitizer**: Strips prompt-injection strings from untrusted metadata notes before building diagnostic summaries.

### Web UI (`web/`)
Next.js 14 App Router UI styled with plain CSS variables (`web/app/globals.css`, port `3001`):
- **Stream**: Live SSE transaction feed with Chain, Risk Tier, Value, and `Flagged only` filters plus transaction drawer.
- **Alerts**: Separate persistent alert feed (`GET /v1/stream/alerts`) with triage status filtering and inline triage actions.
- **Inspector**: Address Risk inspection plus interactive Pre-Sign Transaction Simulator (`POST /v1/evaluate/transaction`).
- **Nodes & Models**: RPC sync health, ONNX runtime status, holdout metrics, threat/bytecode registry counts, and dispute history.

## Configuration

Copy `env/.env.example` to `env/.env` and set either an Alchemy key or QuickNode RPC URLs:

```env
ALCHEMY_API_KEY=
ETHEREUM_RPC_URL=
BASE_RPC_URL=
SENTINEL_GATEWAY_ADDR=0.0.0.0:8090
SENTINEL_ML_SERVICE_URL=http://127.0.0.1:8091
COINGAUGE_DATA_DIR=data
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001
PORT=3001
```

Without private RPC keys, the chain pollers fall back to `https://ethereum-rpc.publicnode.com` and `https://mainnet.base.org`. Note that multi-hop transfer history in **Address Inspector** relies on `alchemy_getAssetTransfers` and is skipped on non-Alchemy endpoints.

## Running Locally

### Prerequisites
- Rust 1.83+ (Cargo)
- Python 3.9+
- Node.js 18+

### 1. Start the ML Sidecar
```bash
cd ml
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn sentinel_ml.server:app --host 127.0.0.1 --port 8091
```

### 2. Start the Risk Gateway
```bash
cargo run -p risk-gateway
```

### 3. Start the Web UI
```bash
cd web
npm install
npm run build
npx next start -p 3001
```

Open `http://localhost:3001`.

## Testing

```bash
cargo test --workspace
cd ml && .venv/bin/pytest -v
cd web && npm run build
```
