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


