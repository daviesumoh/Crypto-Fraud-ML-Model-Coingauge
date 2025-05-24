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
pub enum SimulatorError {
    #[error("invalid EVM hex string `{0}`")]
    InvalidHex(String),
    #[error("EVM execution error: {0}")]
    ExecutionFailed(String),
}

/// Seeded account state (fetched via read-through Redis / Managed RPC cache).
#[derive(Debug, Clone, Default)]
pub struct SeededAccount {
    pub balance_wei: u128,
    pub nonce: u64,
    pub bytecode_hex: Option<String>,
    pub storage_slots: HashMap<U256, U256>,
}

/// Provider trait for on-demand state forking against live JSON-RPC (Alchemy / QuickNode).
pub trait ForkStateProvider: Send + Sync {
    fn fetch_code(&self, address: &str) -> Option<String>;
    fn fetch_balance(&self, address: &str) -> Option<u128>;
    fn fetch_storage(&self, address: &str, slot_hex: &str) -> Option<String>;
}

/// Custom `revm::Inspector` recording internal call frames and simulation-evasion opcodes.
#[derive(Debug, Default)]
struct SecurityInspector {
    traces: Vec<InternalCallTrace>,
    saw_env_inspection_opcode: bool,
    saw_conditional_jump_after_env: bool,
    env_evasion_branch_to_call: bool,
}

impl<DB: Database> Inspector<DB> for SecurityInspector {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        let op = interp.current_opcode();
        // 0x3a = GASPRICE, 0x41 = COINBASE, 0x44 = PREVRANDAO / DIFFICULTY
        if matches!(op, 0x3a | 0x41 | 0x44) {
            self.saw_env_inspection_opcode = true;
        } else if op == 0x57 && self.saw_env_inspection_opcode {
            // 0x57 = JUMPI conditional branch following environment inspection
            self.saw_conditional_jump_after_env = true;
        } else if matches!(op, 0xf1 | 0xf2 | 0xf4 | 0xfa) && self.saw_conditional_jump_after_env {
            // External CALL / CALLCODE / DELEGATECALL / STATICCALL gated on block env branch
            self.env_evasion_branch_to_call = true;
        }
    }

    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        let depth = context.journaled_state.depth() as u16;
        let call_type = match inputs.scheme {
            CallScheme::Call => CallType::Call,
            CallScheme::CallCode => CallType::CallCode,
            CallScheme::DelegateCall => CallType::DelegateCall,
            CallScheme::StaticCall => CallType::StaticCall,
            CallScheme::ExtCall
            | CallScheme::ExtStaticCall
            | CallScheme::ExtDelegateCall => CallType::Call,
        };
        let selector = if inputs.input.len() >= 4 {
            format!("0x{}", hex::encode(&inputs.input[..4]))
        } else {
            "0x".to_string()
        };
        let value_wei = inputs
            .transfer_value()
            .map(|v| v.to::<u128>())
            .unwrap_or(0);

        self.traces.push(InternalCallTrace {
            depth,
            call_type,
            caller: format!("{:#x}", inputs.caller),
            target: format!("{:#x}", inputs.bytecode_address),
            value_wei,
            selector,
            reverted: false,
        });
        None
    }

    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        if !outcome.result.result.is_ok() {
            if let Some(last) = self.traces.last_mut() {
                last.reverted = true;
            }
        }
        outcome
    }

    fn create(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        let depth = context.journaled_state.depth() as u16;
        let call_type = match inputs.scheme {
            CreateScheme::Create => CallType::Create,
            CreateScheme::Create2 { .. } => CallType::Create2,
        };
        self.traces.push(InternalCallTrace {
            depth,
            call_type,
            caller: format!("{:#x}", inputs.caller),
            target: "0x0000000000000000000000000000000000000000".to_string(),
            value_wei: inputs.value.to::<u128>(),
            selector: "0xcreate".to_string(),
            reverted: false,
        });
        None
    }
}

/// Parse a 20-byte EVM `Address` from hex string.
pub fn parse_evm_address(addr: &str) -> Result<Address, SimulatorError> {
    let clean = addr.trim().strip_prefix("0x").unwrap_or(addr.trim());
    let bytes = hex::decode(clean).map_err(|_| SimulatorError::InvalidHex(addr.to_string()))?;
    if bytes.len() != 20 {
        return Err(SimulatorError::InvalidHex(addr.to_string()));
    }
    Ok(Address::from_slice(&bytes))
}

/// Parse arbitrary hex payload (`0x...`) into `Bytes`.
pub fn parse_hex_bytes(data: &str) -> Result<Bytes, SimulatorError> {
    let clean = data.trim().strip_prefix("0x").unwrap_or(data.trim());
    if clean.is_empty() {
        return Ok(Bytes::new());
    }
    let raw = hex::decode(clean).map_err(|_| SimulatorError::InvalidHex(data.to_string()))?;
    Ok(Bytes::from(raw))
}

/// Local `revm` state-diff simulator with realistic block-header anti-evasion defaults.
#[derive(Debug, Default, Clone)]
pub struct EvmStateSimulator {
    seeded_accounts: HashMap<String, SeededAccount>,
    eth_price_usd: f64,
}

impl EvmStateSimulator {
    pub fn new(eth_price_usd: f64) -> Self {
        Self {
            seeded_accounts: HashMap::new(),
            eth_price_usd: if eth_price_usd > 0.0 {
                eth_price_usd
            } else {
                3200.0
            },
        }
    }

    /// Seed an account's balance, nonce, runtime bytecode, or storage slots prior to simulation.
    pub fn seed_account(&mut self, address: &str, account: SeededAccount) {
        self.seeded_accounts
            .insert(normalize_address(address), account);
    }

    /// Simulate a transaction locally in `revm` and decode all asset deltas, permissions, and traces.
    pub fn simulate_transaction(
        &self,
        tx: &CanonicalTransaction,
    ) -> Result<SimulationResult, SimulatorError> {
        self.simulate_transaction_with_fork(tx, None)
    }

    /// Simulate a transaction in `revm` with on-demand state forking against live RPC.
    pub fn simulate_transaction_with_fork(
        &self,
        tx: &CanonicalTransaction,
        fork_provider: Option<&dyn ForkStateProvider>,
    ) -> Result<SimulationResult, SimulatorError> {
        let start = Instant::now();
        let mut db = CacheDB::new(EmptyDB::default());

        let sender_addr = parse_evm_address(&tx.sender)?;
        let calldata = parse_hex_bytes(&tx.calldata_hex)?;

        let sim_gas_limit = tx.gas_limit.max(500_000);
        let sim_gas_price_wei = tx.max_fee_per_gas_wei.max(25_000_000_000);

        // Ensure sender has enough seeded ETH to cover value + max simulated gas fee
        let min_sender_wei = tx
            .value_wei
            .saturating_add((sim_gas_limit as u128).saturating_mul(sim_gas_price_wei).saturating_mul(2))
            .max(10_000_000_000_000_000_000); // >= 10 ETH simulation buffer if unseeded

        for (addr_str, seeded) in &self.seeded_accounts {
            let addr = parse_evm_address(addr_str)?;
            let code = if let Some(code_hex) = &seeded.bytecode_hex {
                let raw = parse_hex_bytes(code_hex)?;
                if raw.is_empty() {
                    None
                } else {
                    Some(Bytecode::new_raw(raw))
                }
            } else {
                None
            };
            let balance = if addr == sender_addr {
                U256::from(seeded.balance_wei.max(min_sender_wei))
            } else {
                U256::from(seeded.balance_wei)
            };
            db.insert_account_info(
                addr,
                AccountInfo {
                    balance,
                    nonce: seeded.nonce,
                    code_hash: B256::ZERO,
                    code,
                },
            );
            for (slot, val) in &seeded.storage_slots {
                let _ = db.insert_account_storage(addr, *slot, *val);
            }
        }

        if !self
            .seeded_accounts
            .contains_key(&normalize_address(&tx.sender))
        {
            db.insert_account_info(
                sender_addr,
                AccountInfo {
                    balance: U256::from(min_sender_wei),
                    nonce: tx.nonce,
                    code_hash: B256::ZERO,
                    code: None,
                },
            );
        }

