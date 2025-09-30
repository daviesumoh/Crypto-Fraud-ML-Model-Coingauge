#!/usr/bin/env python3
"""Build Real On-Chain Web3 Risk Training Dataset & Threat Intelligence Corpus.

Combines:
  1. Verified open-source threat intelligence datasets in `ml/data/`:
     - Forta Network (`forta_malicious_contracts.csv`, `forta_phishing_scams.csv`, `forta_etherscan_malicious_labels.csv`)
     - ScamSniffer (`scamsniffer_addresses.json`)
  2. Live Ethereum Mainnet JSON-RPC extraction (via `env/.env`):
     - Real exploit deployment transactions (`contract_creation_tx`)
     - Real deployed bytecode (`eth_getCode`) of malicious contracts & drainers
     - Real asset transfers (`alchemy_getAssetTransfers`) of active drainers/phishers
     - Real recent Ethereum Mainnet blocks (`eth_getBlockByNumber`) for benign baseline transactions
     - Real canonical DeFi protocol bytecodes & transactions

Outputs:
  - `ml/data/real_web3_training_dataset.csv`: Real on-chain labeled features (`y=1` attack, `y=0` benign)
  - `ml/data/malicious_bytecodes.json`: Disassembled bytecode signatures from real exploits & drainers
  - `crates/chain-indexer/data/threat_intel.json`: Consolidated Forta + ScamSniffer blacklist for live gateway
"""

from __future__ import annotations

import csv
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
DATA_DIR = CURRENT_DIR / "data"
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from sentinel_ml.features import FEATURE_NAMES, FeatureInputContext, extract_feature_vector
from sentinel_ml.models.bytecode_similarity import disassemble_evm_bytecode

VERIFIED_BENIGN_PROTOCOLS: Dict[str, str] = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "Tether USD (USDT)",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USD Coin (USDC)",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "Wrapped Ether (WETH)",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "Dai Stablecoin (DAI)",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router V1",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Aggregation Router V5",
    "0x0000000000000068f116a894984e2db1123eb395": "OpenSea Seaport 1.6",
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool",
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "Lido stETH",
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance Hot Wallet 14",
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance Hot Wallet 16",
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": "Coinbase Omnibus 1",
    "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": "Coinbase Omnibus 10",
    "0xd8da6bf26964af9d7eed9e03e53415d37aa96045": "vitalik.eth",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router 02",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
    "0xba12222222228d8ba445958a75a0704d566bf2c8": "Balancer V2 Vault",
    "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419": "Chainlink ETH/USD Feed",
}

UNLIMITED_APPROVAL_SELECTORS = {
    "0x095ea7b3",  # approve(address,uint256)
    "0x39509351",  # increaseAllowance(address,uint256)
    "0xa22cb465",  # setApprovalForAll(address,bool)
    "0xd505accf",  # EIP-2612 permit
    "0x87517c45",  # Permit2 approve
    "0x2b67b570",  # Permit2 permit single
}


def load_eth_rpc_url() -> str:
    env_path = ROOT_DIR / "env" / ".env"
    env_map: Dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            env_map[k.strip()] = v.strip().strip('"').strip("'")

    url = env_map.get("ETHEREUM_RPC_URL") or env_map.get("QUICKNODE_ETHEREUM_URL") or ""
    if not url and env_map.get("ALCHEMY_API_KEY"):
        url = f"https://eth-mainnet.g.alchemy.com/v2/{env_map['ALCHEMY_API_KEY']}"
    if not url:
        raise RuntimeError("No ETHEREUM_RPC_URL or ALCHEMY_API_KEY configured in env/.env")
    return url


def batch_rpc(client: httpx.Client, url: str, calls: List[Tuple[str, list]]) -> List[Any]:
    results: List[Any] = [None] * len(calls)
    chunk_size = 25
    for start in range(0, len(calls), chunk_size):
        chunk = calls[start : start + chunk_size]
        payload = [
            {"jsonrpc": "2.0", "id": i, "method": method, "params": params}
            for i, (method, params) in enumerate(chunk)
        ]
        for attempt in range(3):
            try:
                resp = client.post(url, json=payload)
                if resp.status_code == 429:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                resp.raise_for_status()
                items = resp.json()
                if isinstance(items, list):
                    for item in items:
                        idx = item.get("id")
                        if idx is not None and 0 <= idx < len(chunk):
                            results[start + idx] = item.get("result")
                break
            except Exception:
                time.sleep(0.2 * (attempt + 1))
        time.sleep(0.04)
    return results


def single_rpc(client: httpx.Client, url: str, method: str, params: list) -> Any:
    for attempt in range(5):
        try:
            resp = client.post(
                url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            )
            if resp.status_code == 429:
                time.sleep(1.0 * (attempt + 1))
                continue
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data and data["result"] is not None:
                    return data["result"]
                time.sleep(0.5)
        except Exception:
            time.sleep(0.5 * (attempt + 1))
    return None


def parse_hex_int(val: Any) -> int:
    if isinstance(val, int):
        return val
    if not isinstance(val, str):
        return 0
    s = val.strip()
    if s in ("", "0x", "0X"):
        return 0
    try:
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s)
    except ValueError:
        return 0


def compute_uniform_priority_percentile(tx_obj: dict) -> float:
    """Compute a consistent priority fee percentile relative to EIP-1559 tips."""
    if "_block_prio_pct" in tx_obj:
        return float(tx_obj["_block_prio_pct"])
    tip_wei = parse_hex_int(tx_obj.get("maxPriorityFeePerGas"))
    tip_gwei = tip_wei / 1e9 if tip_wei > 0 else 1.5
    if tip_gwei <= 2.5:
        return 40.0 + tip_gwei * 10.0
    if tip_gwei <= 10.0:
        return 65.0 + (tip_gwei - 2.5) * 3.0
    return min(99.9, 87.5 + min(12.4, (tip_gwei - 10.0) * 0.5))


def check_calldata_unlimited_approval(input_hex: str) -> bool:
    clean = (input_hex or "").lower()
    if not clean.startswith("0x"):
        clean = "0x" + clean
    if len(clean) < 10:
        return False
    sel = clean[:10]
    if sel not in UNLIMITED_APPROVAL_SELECTORS:
        return False
    args_hex = clean[10:]
    if sel == "0xa22cb465" and len(args_hex) >= 128:
        # setApprovalForAll(operator, approved)
        return parse_hex_int("0x" + args_hex[64:128]) == 1
    if sel == "0x095ea7b3" and len(args_hex) >= 128:
        val = parse_hex_int("0x" + args_hex[64:128])
        return val >= (1 << 120)
    if sel == "0xd505accf" and len(args_hex) >= 192:
        val = parse_hex_int("0x" + args_hex[128:192])
        return val >= (1 << 120)
    return True


def score_bytecode_structural(code_hex: str) -> Tuple[float, Dict[str, Any]]:
    if not code_hex or len(code_hex) <= 4:
        return 0.0, {}
    ops = disassemble_evm_bytecode(code_hex)
    if not ops:
        return 0.0, {}
    op_set = set(ops)
    has_delegatecall = "DELEGATECALL" in op_set or "CALLCODE" in op_set
    has_selfdestruct = "SELFDESTRUCT" in op_set
    has_create2 = "CREATE2" in op_set
    saw_env = False
    has_env_evasion = False
    for op in ops:
        if op in ("COINBASE", "GASPRICE", "PREVRANDAO"):
            saw_env = True
        elif op == "JUMPI" and saw_env:
            has_env_evasion = True
            break

    risk = 0.0
    if has_selfdestruct:
        risk += 0.35
    if has_env_evasion:
        risk += 0.35
    if has_delegatecall and len(ops) < 150:
        risk += 0.25
    if has_create2 and has_selfdestruct:
        risk += 0.25
    if len(ops) < 80 and has_delegatecall:
        risk += 0.15

    return round(min(1.0, risk), 4), {
        "opcode_count": len(ops),
        "has_delegatecall": has_delegatecall,
        "has_selfdestruct": has_selfdestruct,
        "has_create2": has_create2,
        "has_env_evasion": has_env_evasion,
    }


def load_threat_feeds() -> Tuple[Dict[str, Tuple[str, str, str]], List[dict]]:
    """Returns (address -> (entity_name, category, source), exploit_contracts_rows)."""
    registry: Dict[str, Tuple[str, str, str]] = {}
    exploit_rows: List[dict] = []

    # 1. Forta malicious smart contracts
    p1 = DATA_DIR / "forta_malicious_contracts.csv"
    if p1.exists():
        with p1.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                exploit_rows.append(row)
                addr = (row.get("contract_address") or "").strip().lower()
                tag = (row.get("contract_tag") or row.get("contract_creator_tag") or "Malicious Exploit Contract").strip()
                if len(addr) == 42 and addr.startswith("0x"):
                    registry[addr] = (tag, "Exploiter", "FORTA_LABELED")
                creator = (row.get("contract_creator") or "").strip().lower()
                if len(creator) == 42 and creator.startswith("0x"):
                    ctag = (row.get("contract_creator_tag") or f"Deployer: {tag}").strip()
                    registry[creator] = (ctag, "Exploiter", "FORTA_LABELED")

    # 2. Forta phishing scams
    p2 = DATA_DIR / "forta_phishing_scams.csv"
    if p2.exists():
        with p2.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                addr = (row.get("address") or "").strip().lower()
                tag = (row.get("etherscan_tag") or "Phishing / Drainer").strip()
                if len(addr) == 42 and addr.startswith("0x") and addr not in VERIFIED_BENIGN_PROTOCOLS:
                    registry.setdefault(addr, (tag, "WalletDrainer", "FORTA_PHISH"))

    # 3. Forta etherscan malicious labels
    p3 = DATA_DIR / "forta_etherscan_malicious_labels.csv"
    if p3.exists():
        with p3.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                addr = (row.get("banned_address") or "").strip().lower()
                tag = (row.get("wallet_tag") or "Malicious Entity").strip()
                if len(addr) == 42 and addr.startswith("0x") and addr not in VERIFIED_BENIGN_PROTOCOLS:
                    registry.setdefault(addr, (tag, "Phishing", "ETHERSCAN_FORTA"))

    # 4. ScamSniffer address database
    p4 = DATA_DIR / "scamsniffer_addresses.json"
    if p4.exists():
        addrs = json.loads(p4.read_text(encoding="utf-8"))
        for a in addrs:
            addr = str(a).strip().lower()
            if len(addr) == 42 and addr.startswith("0x") and addr not in VERIFIED_BENIGN_PROTOCOLS:
                registry.setdefault(addr, ("ScamSniffer Flagged Drainer", "WalletDrainer", "SCAMSNIFFER"))

    return registry, exploit_rows


