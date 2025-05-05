//! Local EVM state-diff simulator (`revm`), evasion-opcode tracer, and ABI permission decoder.
//!
//! Powers the `< 200 ms` Pre-Sign Transaction Firewall without requiring self-hosted archive nodes:
//! account/bytecode/storage state can be seeded from a read-through Redis + Managed RPC (`AlloyDB`)
//! cache into `revm::InMemoryDB`, with realistic block header overrides to defeat `gasprice == 0`
//! simulation-evasion checks.

use std::collections::HashMap;
use std::time::Instant;

use common_types::{
    normalize_address, AssetMovement, AssetStandard, CallType, CanonicalTransaction,
    InternalCallTrace, PermissionKind, PermissionMutation, SimulationResult,
};
use revm::{
    db::{CacheDB, EmptyDB},
    interpreter::{CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, CreateScheme, Interpreter},
    primitives::{
        AccountInfo, Address, Bytecode, Bytes, ExecutionResult, Output, TransactTo, B256, U256,
    },
    Database, Evm, EvmContext, Inspector,
};
use thiserror::Error;

/// Known EVM function selectors for approvals, permits, and token transfers.
pub mod selectors {
    /// `approve(address,uint256)`
    pub const ERC20_APPROVE: &str = "0x095ea7b3";
    /// `increaseAllowance(address,uint256)`
    pub const INCREASE_ALLOWANCE: &str = "0x39509351";
    /// `setApprovalForAll(address,bool)`
    pub const SET_APPROVAL_FOR_ALL: &str = "0xa22cb465";
    /// `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` (EIP-2612)
    pub const EIP2612_PERMIT: &str = "0xd505accf";
    /// `approve(address,address,uint160,uint48)` (Uniswap Permit2 direct allowance)
    pub const PERMIT2_APPROVE: &str = "0x87517c45";
    /// `permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)` (Permit2 single)
    pub const PERMIT2_PERMIT_SINGLE: &str = "0x2b67b570";
    /// `transfer(address,uint256)`
    pub const ERC20_TRANSFER: &str = "0xa9059cbb";
    /// `transferFrom(address,address,uint256)`
    pub const ERC20_TRANSFER_FROM: &str = "0x23b872dd";
}

/// Keccak256 topic0 hashes for standard token events.
pub mod topics {
    /// `Transfer(address indexed from, address indexed to, uint256 value)`
    pub const TRANSFER_TOPIC0: &str =
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    /// `Approval(address indexed owner, address indexed spender, uint256 value)`
    pub const APPROVAL_TOPIC0: &str =
        "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
    /// `ApprovalForAll(address indexed owner, address indexed operator, bool approved)`
    pub const APPROVAL_FOR_ALL_TOPIC0: &str =
        "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";
}

#[derive(Debug, Error)]
