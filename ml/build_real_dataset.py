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


def main() -> None:
    print("=" * 72)
    print("Web3 Sentinel: Real On-Chain Dataset & Malicious Bytecode Extractor")
    print("=" * 72)

    rpc_url = load_eth_rpc_url()
    client = httpx.Client(timeout=20.0, headers={"User-Agent": "Web3Sentinel/1.0"})

    registry, exploit_rows = load_threat_feeds()
    print(f"[+] Consolidated Threat Registry: {len(registry):,} unique verified malicious addresses")

    # Export Rust gateway consolidated threat intel feed
    rust_intel_path = ROOT_DIR / "crates" / "chain-indexer" / "data" / "threat_intel.json"
    rust_intel_path.parent.mkdir(parents=True, exist_ok=True)
    intel_list = [
        {"address": addr, "name": info[0], "category": info[1], "source": info[2]}
        for addr, info in registry.items()
    ]
    rust_intel_path.write_text(json.dumps(intel_list, indent=None), encoding="utf-8")
    print(f"[+] Saved Rust threat intel database ({len(intel_list):,} entries) -> {rust_intel_path}")

    # Query Chainlink ETH/USD price
    res_price = single_rpc(
        client,
        rpc_url,
        "eth_call",
        [{"to": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419", "data": "0x50d25bcd"}, "latest"],
    )
    eth_price = parse_hex_int(res_price) / 1e8 if res_price else 2500.0
    if not (100.0 <= eth_price <= 100_000.0):
        eth_price = 2500.0
    print(f"[+] Live Chainlink ETH/USD price: ${eth_price:,.2f}")

    benign_only = "--benign-only" in sys.argv
    out_csv = DATA_DIR / "real_web3_training_dataset.csv"
    dataset_rows: List[dict] = []

    if benign_only and out_csv.exists():
        with out_csv.open("r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if int(r.get("is_attack", 0)) == 1:
                    r["is_attack"] = 1
                    dataset_rows.append(r)
        print(f"[*] --benign-only: Loaded {len(dataset_rows)} existing Phase 1 attack rows from CSV.")
    else:
        dataset_rows.extend(_extract_phase1_attacks(client, rpc_url, eth_price, exploit_rows))

    time.sleep(1.0)
    dataset_rows.extend(_extract_phase2_benign(client, rpc_url, eth_price, registry))

    fieldnames = ["source", "ref", "tag", "is_attack"] + FEATURE_NAMES
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(dataset_rows)

    n_attack = sum(1 for r in dataset_rows if int(r["is_attack"]) == 1)
    n_benign = sum(1 for r in dataset_rows if int(r["is_attack"]) == 0)
    print(f"\n[+] Saved real on-chain dataset -> {out_csv}")
    print(f"    Total Samples: {len(dataset_rows):,} ({n_attack:,} real attacks/exploits, {n_benign:,} live mainnet benign txs)")


def _extract_phase1_attacks(
    client: httpx.Client,
    rpc_url: str,
    eth_price: float,
    exploit_rows: List[dict],
) -> List[dict]:
    print("\n[*] Phase 1: Querying live RPC for real Forta exploit txs & malicious contract bytecodes...")
    # Sample up to 350 exploit contracts with creation_tx
    seen_contracts: Set[str] = set()
    sampled_exploits: List[dict] = []
    for row in exploit_rows:
        c_addr = (row.get("contract_address") or "").strip().lower()
        c_tx = (row.get("contract_creation_tx") or "").strip().lower()
        if c_addr and c_addr not in seen_contracts and c_addr.startswith("0x") and len(c_addr) == 42:
            seen_contracts.add(c_addr)
            sampled_exploits.append(row)
        if len(sampled_exploits) >= 600:
            break

    # Also take up to 250 contract addresses flagged in Forta phishing_scams.csv
    phish_contracts: List[Tuple[str, str]] = []
    phish_eoas: List[Tuple[str, str]] = []
    p_phish = DATA_DIR / "forta_phishing_scams.csv"
    if p_phish.exists():
        with p_phish.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                addr = (row.get("address") or "").strip().lower()
                tag = (row.get("etherscan_tag") or "Phishing").strip()
                is_c = (row.get("is_contract") or "").strip().lower() == "true"
                if len(addr) == 42 and addr not in VERIFIED_BENIGN_PROTOCOLS:
                    if is_c and len(phish_contracts) < 250 and addr not in seen_contracts:
                        seen_contracts.add(addr)
                        phish_contracts.append((addr, tag))
                    elif not is_c and len(phish_eoas) < 150:
                        phish_eoas.append((addr, tag))

    # Also add active ScamSniffer drainers
    ss_addrs = json.loads((DATA_DIR / "scamsniffer_addresses.json").read_text(encoding="utf-8"))
    for a in ss_addrs[:150]:
        addr = str(a).strip().lower()
        if len(addr) == 42 and addr not in VERIFIED_BENIGN_PROTOCOLS:
            phish_eoas.append((addr, "ScamSniffer_Drainer"))

    all_mal_contract_addrs = [(r["contract_address"].strip().lower(), (r.get("contract_tag") or r.get("contract_creator_tag") or "Forta_Exploit").strip()) for r in sampled_exploits] + phish_contracts

    print(f"    Batch fetching eth_getCode for {len(all_mal_contract_addrs)} verified malicious contracts...")
    code_calls = [("eth_getCode", [addr, "latest"]) for addr, _ in all_mal_contract_addrs]
    codes = batch_rpc(client, rpc_url, code_calls)

    malicious_bytecodes: List[dict] = []
    addr_to_bytecode_risk: Dict[str, float] = {}
    for (addr, tag), code_hex in zip(all_mal_contract_addrs, codes):
        if isinstance(code_hex, str) and len(code_hex) > 10:
            brisk, stats = score_bytecode_structural(code_hex)
            addr_to_bytecode_risk[addr] = brisk
            # Save up to 250 real malicious bytecodes (truncate to 16KB hex max per record to stay compact)
            if len(malicious_bytecodes) < 250:
                malicious_bytecodes.append({
                    "address": addr,
                    "family": tag[:48] or "ExploitContract",
                    "bytecode_hex": code_hex[:32768],
                    "structural_risk": brisk,
                    **stats,
                })

    bc_path = DATA_DIR / "malicious_bytecodes.json"
    bc_path.write_text(json.dumps(malicious_bytecodes, indent=2), encoding="utf-8")
    print(f"[+] Extracted and disassembled {len(malicious_bytecodes)} real malicious contract bytecodes -> {bc_path}")

    # Fetch real exploit creation transactions
    creation_txs = [
        (r["contract_creation_tx"].strip().lower(), r["contract_address"].strip().lower(), (r.get("contract_creator") or "").strip().lower(), (r.get("contract_tag") or r.get("contract_creator_tag") or "Forta_Exploit").strip())
        for r in sampled_exploits
        if r.get("contract_creation_tx", "").strip().startswith("0x")
    ]
    print(f"    Batch fetching eth_getTransactionByHash for {len(creation_txs)} real exploit creation transactions...")
    tx_calls = [("eth_getTransactionByHash", [txh]) for txh, _, _, _ in creation_txs]
    tx_objs = batch_rpc(client, rpc_url, tx_calls)

    # Fetch creator balances and tx counts
    creators = list({c for _, _, c, _ in creation_txs if len(c) == 42})
    creator_bal_calls = [("eth_getBalance", [c, "latest"]) for c in creators]
    creator_cnt_calls = [("eth_getTransactionCount", [c, "latest"]) for c in creators]
    creator_bals = batch_rpc(client, rpc_url, creator_bal_calls)
    creator_cnts = batch_rpc(client, rpc_url, creator_cnt_calls)
    creator_state = {
        c: (parse_hex_int(b) / 1e18 * eth_price, parse_hex_int(n))
        for c, b, n in zip(creators, creator_bals, creator_cnts)
    }

    dataset_rows: List[dict] = []

    for (txh, c_addr, creator, tag), tx_obj in zip(creation_txs, tx_objs):
        if not isinstance(tx_obj, dict):
            continue
        val_eth = parse_hex_int(tx_obj.get("value")) / 1e18
        val_usd = val_eth * eth_price
        inp = tx_obj.get("input") or "0x"
        calldata_bytes = max(0, (len(inp) - 2) // 2)
        gas_price_gwei = parse_hex_int(tx_obj.get("gasPrice") or tx_obj.get("maxFeePerGas")) / 1e9
        nonce = parse_hex_int(tx_obj.get("nonce"))
        c_bal_usd, c_tx_cnt = creator_state.get(creator, (val_usd * 1.1, nonce + 1))
        brisk = addr_to_bytecode_risk.get(c_addr, 0.35)

        # Use uniform priority fee curve across all transactions
        prio_pct = compute_uniform_priority_percentile(tx_obj)
        ctx = FeatureInputContext(
            tx_value_usd=val_usd,
            sender_pre_balance_usd=max(c_bal_usd, val_usd + 50.0, 50.0),
            priority_fee_percentile=prio_pct,
            wallet_tx_count=max(1, nonce),
            young_contract_touch=True,
            unverified_contract_touch=True,
            unlimited_approval=False,
            taint_score=0.0,
            peel_or_sybil_flag=(nonce <= 5),
            graph_edge_count=1,
            calldata_bytes=calldata_bytes,
            is_contract_interaction=True,
            bytecode_risk_score=brisk,
        )
        vec = extract_feature_vector(ctx)
        dataset_rows.append({
            "source": "forta_exploit_deploy",
            "ref": txh,
            "tag": tag,
            "is_attack": 1,
            **{name: round(float(val), 6) for name, val in zip(FEATURE_NAMES, vec)},
        })

    # Fetch real Alchemy Asset Transfers for phishing / ScamSniffer drainers
    drainer_sample = phish_eoas[:60] + phish_eoas[-60:]
    print(f"    Fetching real on-chain transfers via alchemy_getAssetTransfers for {len(drainer_sample)} drainer/phish addresses...")
    drainer_addrs = [a for a, _ in drainer_sample]
    # Batch getTransactionCount & getBalance
    d_cnts = batch_rpc(client, rpc_url, [("eth_getTransactionCount", [a, "latest"]) for a in drainer_addrs])
    d_bals = batch_rpc(client, rpc_url, [("eth_getBalance", [a, "latest"]) for a in drainer_addrs])
    drainer_meta = {
        a: (parse_hex_int(b) / 1e18 * eth_price, parse_hex_int(n))
        for a, b, n in zip(drainer_addrs, d_bals, d_cnts)
    }

    phish_tx_hashes: List[Tuple[str, str, float]] = []  # (tx_hash, tag, val_usd)
    for addr, tag_str in drainer_sample[:80]:
        for direction in ("toAddress", "fromAddress"):
            res = single_rpc(
                client,
                rpc_url,
                "alchemy_getAssetTransfers",
                [{
                    "fromBlock": "0x0",
                    "toBlock": "latest",
                    direction: addr,
                    "category": ["external", "erc20"],
                    "maxCount": "0x5",
                    "order": "desc",
                }],
            )
            if isinstance(res, dict) and isinstance(res.get("transfers"), list):
                for tr in res["transfers"][:3]:
                    txh = tr.get("hash")
                    if txh and len(phish_tx_hashes) < 400:
                        asset = (tr.get("asset") or "ETH").upper()
                        v = float(tr.get("value") or 0.0)
                        v_usd = v * eth_price if asset in ("ETH", "WETH") else (v if asset in ("USDC", "USDT", "DAI") else 0.0)
                        phish_tx_hashes.append((txh, tag_str, v_usd))

    # Deduplicate phish hashes & fetch actual tx payloads
    unique_phish_txs: Dict[str, Tuple[str, float]] = {}
    for txh, tag, v_usd in phish_tx_hashes:
        unique_phish_txs.setdefault(txh, (tag, v_usd))
    phish_tx_list = [(txh, tag, v_usd) for txh, (tag, v_usd) in unique_phish_txs.items()]
    print(f"    Batch fetching {len(phish_tx_list)} real drainer/phishing transactions from chain...")
    phish_tx_objs = batch_rpc(client, rpc_url, [("eth_getTransactionByHash", [txh]) for txh, _, _ in phish_tx_list])

    # Collect unique senders and recipients of phish txs for real nonces/balances/code
    p_addrs: Set[str] = set()
    for tx_obj in phish_tx_objs:
        if isinstance(tx_obj, dict):
            if tx_obj.get("from"):
                p_addrs.add(tx_obj["from"].lower())
            if tx_obj.get("to"):
                p_addrs.add(tx_obj["to"].lower())
    p_addr_list = list(p_addrs)
    p_codes = batch_rpc(client, rpc_url, [("eth_getCode", [a, "latest"]) for a in p_addr_list])
    p_bals = batch_rpc(client, rpc_url, [("eth_getBalance", [a, "latest"]) for a in p_addr_list])
    p_cnts = batch_rpc(client, rpc_url, [("eth_getTransactionCount", [a, "latest"]) for a in p_addr_list])
    p_state = {
        a: (isinstance(c, str) and len(c) > 4, c if isinstance(c, str) else "0x", parse_hex_int(b) / 1e18 * eth_price, parse_hex_int(n))
        for a, c, b, n in zip(p_addr_list, p_codes, p_bals, p_cnts)
    }

    for (txh, tag, est_usd), tx_obj in zip(phish_tx_list, phish_tx_objs):
        if not isinstance(tx_obj, dict):
            continue
        frm = (tx_obj.get("from") or "").lower()
        to = (tx_obj.get("to") or "").lower()
        inp = tx_obj.get("input") or "0x"
        val_eth = parse_hex_int(tx_obj.get("value")) / 1e18
        val_usd = max(est_usd, val_eth * eth_price)
        nonce = parse_hex_int(tx_obj.get("nonce"))
        calldata_bytes = max(0, (len(inp) - 2) // 2)
        unlim_app = check_calldata_unlimited_approval(inp)

        _, _, f_bal_usd, f_cnt = p_state.get(frm, (False, "0x", val_usd * 1.1, nonce + 1))
        to_is_contract, to_code, _, to_cnt = p_state.get(to, (False, "0x", 0.0, 0))
        to_in_verified = to in VERIFIED_BENIGN_PROTOCOLS
        brisk = score_bytecode_structural(to_code)[0] if to_is_contract and not to_in_verified else 0.0

        is_sweep = (f_bal_usd > 0 and val_usd / max(1.0, f_bal_usd) >= 0.7) or (nonce <= 3 and val_usd > 500)
        prio_pct = compute_uniform_priority_percentile(tx_obj)

        ctx = FeatureInputContext(
            tx_value_usd=val_usd,
            sender_pre_balance_usd=max(f_bal_usd, val_usd + 10.0, 50.0),
            priority_fee_percentile=prio_pct,
            wallet_tx_count=max(1, min(f_cnt, nonce + 1) if nonce > 0 else f_cnt),
            young_contract_touch=(to_is_contract and not to_in_verified and to_cnt <= 20),
            unverified_contract_touch=(to_is_contract and not to_in_verified),
            unlimited_approval=unlim_app,
            taint_score=0.0,
            peel_or_sybil_flag=is_sweep,
            graph_edge_count=5,
            calldata_bytes=calldata_bytes,
            is_contract_interaction=to_is_contract,
            bytecode_risk_score=brisk,
        )
        vec = extract_feature_vector(ctx)
        dataset_rows.append({
            "source": "scamsniffer_forta_phish",
            "ref": txh,
            "tag": tag,
            "is_attack": 1,
            **{name: round(float(val), 6) for name, val in zip(FEATURE_NAMES, vec)},
        })

    return dataset_rows


