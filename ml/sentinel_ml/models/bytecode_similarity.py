from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

OPCODE_TABLE: Dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x10: "LT",
    0x11: "GT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x20: "KECCAK256",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFF: "SELFDESTRUCT",
}


@dataclass
class BytecodeAnalysis:
    opcode_count: int
    has_delegatecall: bool
    has_selfdestruct: bool
    has_create2: bool
    has_env_evasion: bool
    nearest_family: Optional[str]
    similarity: Optional[float]
    risk_score: float


def disassemble_evm_bytecode(bytecode_hex: str) -> List[str]:
    clean = bytecode_hex.strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if not clean or len(clean) % 2 != 0:
        return []
    try:
        raw = bytes.fromhex(clean)
    except ValueError:
        return []

    mnemonics: List[str] = []
    pc = 0
    n = len(raw)

    while pc < n:
        op = raw[pc]
        if 0x60 <= op <= 0x7F:
            push_len = op - 0x5F
            mnemonics.append(f"PUSH{push_len}")
            pc += 1 + push_len
            continue
        if 0x80 <= op <= 0x8F:
            mnemonics.append(f"DUP{op - 0x7F}")
        elif 0x90 <= op <= 0x9F:
            mnemonics.append(f"SWAP{op - 0x8F}")
        elif 0xA0 <= op <= 0xA4:
            mnemonics.append(f"LOG{op - 0xA0}")
        else:
            mnemonics.append(OPCODE_TABLE.get(op, f"OP_{op:02x}"))
        pc += 1

    return mnemonics


def compute_opcode_embedding(bytecode_hex: str, dim: int = 64) -> np.ndarray:
    ops = disassemble_evm_bytecode(bytecode_hex)
    vec = np.zeros(dim, dtype=np.float64)
    if not ops:
        return vec

    for width in (2, 3):
        for i in range(max(0, len(ops) - width + 1)):
            gram = "|".join(ops[i : i + width]).encode("utf-8")
            digest = hashlib.blake2b(gram, digest_size=8).digest()
            idx = int.from_bytes(digest[:4], "little") % dim
            sign = 1.0 if (digest[4] & 1) == 0 else -1.0
            vec[idx] += sign

    norm = float(np.linalg.norm(vec))
    return vec / norm if norm > 0.0 else vec


class BytecodeSimilarityIndex:
    def __init__(self, corpus_path: Optional[Path] = None) -> None:
        templates = {
            "PinkDrainer_MulticallProxy": (
                "0x36600080376000803660007311111111111111111111111111111111111111115af43d82803e903d91602b57fd5bf3"
            ),
            "InfernoDrainer_Create2Vault": (
                "0x4160065700005b336000526020600020546000527322222222222222222222222222222222222222225af1f5ff"
            ),
            "BlacklistTax_HoneypotERC20": (
                "0x3360005260206000205415601557600080fd5b3460043560020460015500"
            ),
        }
        self._families: List[Tuple[str, np.ndarray]] = [
            (name, compute_opcode_embedding(code)) for name, code in templates.items()
        ]

        default_corpus = Path(__file__).resolve().parents[2] / "data" / "malicious_bytecodes.json"
        target_path = corpus_path or default_corpus
        if target_path.exists():
            try:
                records = json.loads(target_path.read_text(encoding="utf-8"))
                if isinstance(records, list):
                    for rec in records:
                        code = rec.get("bytecode_hex")
                        fam = rec.get("family") or rec.get("address") or "Forta_Exploit"
                        if isinstance(code, str) and len(code) > 10:
                            vec = compute_opcode_embedding(code)
                            if float(np.linalg.norm(vec)) > 0.0:
                                self._families.append((str(fam), vec))
            except Exception:
                pass

    def analyze(self, bytecode_hex: Optional[str]) -> BytecodeAnalysis:
        if not bytecode_hex or len(bytecode_hex.strip()) <= 6:
            return BytecodeAnalysis(
                opcode_count=0,
                has_delegatecall=False,
                has_selfdestruct=False,
                has_create2=False,
                has_env_evasion=False,
                nearest_family=None,
                similarity=None,
                risk_score=0.0,
            )

        ops = disassemble_evm_bytecode(bytecode_hex)
        if not ops:
            return BytecodeAnalysis(0, False, False, False, False, None, None, 0.0)

        op_set = set(ops)
        has_delegatecall = "DELEGATECALL" in op_set or "CALLCODE" in op_set
        has_selfdestruct = "SELFDESTRUCT" in op_set
        has_create2 = "CREATE2" in op_set

        env_countdown = 0
        has_env_evasion = False
        for op in ops:
            if op in ("COINBASE", "GASPRICE", "PREVRANDAO"):
                env_countdown = 6
            elif env_countdown > 0:
                if op == "JUMPI":
                    has_env_evasion = True
                    break
                env_countdown -= 1

        q = compute_opcode_embedding(bytecode_hex)
        best_family: Optional[str] = None
        best_sim: float = 0.0

        if float(np.linalg.norm(q)) > 0.0:
            for name, ref_vec in self._families:
                sim = float(np.dot(q, ref_vec))
                if sim > best_sim:
                    best_sim = sim
                    best_family = name

        matched_family = best_family if best_sim >= 0.85 else None
        reported_sim = round(best_sim, 4) if best_sim >= 0.25 else None

        risk = 0.0
        if best_sim >= 0.85:
            risk += 0.55 * best_sim
        if has_selfdestruct:
            risk += 0.35
        if has_env_evasion:
            risk += 0.40
        if has_create2 and has_selfdestruct:
            risk += 0.30

        return BytecodeAnalysis(
            opcode_count=len(ops),
            has_delegatecall=has_delegatecall,
            has_selfdestruct=has_selfdestruct,
            has_create2=has_create2,
            has_env_evasion=has_env_evasion,
            nearest_family=matched_family,
            similarity=reported_sim,
            risk_score=round(min(1.0, risk), 4),
        )

    def query(self, bytecode_hex: Optional[str]) -> Tuple[Optional[str], Optional[float]]:
        res = self.analyze(bytecode_hex)
        return res.nearest_family, res.similarity
