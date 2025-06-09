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

        // On-demand RPC forking: load runtime bytecode and balances for target contracts
        if let Some(provider) = fork_provider {
            if let Some(rcpt) = &tx.recipient {
                let norm_rcpt = normalize_address(rcpt);
                if !self.seeded_accounts.contains_key(&norm_rcpt) {
                    if let Some(code_hex) = provider.fetch_code(rcpt) {
                        let clean = code_hex.trim_start_matches("0x");
                        if !clean.is_empty() {
                            if let Ok(raw) = hex::decode(clean) {
                                if let Ok(addr) = parse_evm_address(rcpt) {
                                    let balance = provider.fetch_balance(rcpt).unwrap_or(0);
                                    db.insert_account_info(
                                        addr,
                                        AccountInfo {
                                            balance: U256::from(balance),
                                            nonce: 1,
                                            code_hash: B256::ZERO,
                                            code: Some(Bytecode::new_raw(Bytes::from(raw))),
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Also fork referenced contract addresses in calldata (e.g. approve/transfer target)
            if calldata.len() >= 36 {
                if let Some(arg_addr) = word_to_address(&calldata[4..36]) {
                    let norm_arg = normalize_address(&arg_addr);
                    if !self.seeded_accounts.contains_key(&norm_arg) && norm_arg != normalize_address(&tx.sender) {
                        if let Some(c_hex) = provider.fetch_code(&arg_addr) {
                            let clean = c_hex.trim_start_matches("0x");
                            if !clean.is_empty() {
                                if let Ok(raw) = hex::decode(clean) {
                                    if let Ok(a) = parse_evm_address(&arg_addr) {
                                        let bal = provider.fetch_balance(&arg_addr).unwrap_or(0);
                                        db.insert_account_info(
                                            a,
                                            AccountInfo {
                                                balance: U256::from(bal),
                                                nonce: 1,
                                                code_hash: B256::ZERO,
                                                code: Some(Bytecode::new_raw(Bytes::from(raw))),
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let transact_to = match &tx.recipient {
            Some(rcpt) if !rcpt.trim().is_empty() => TransactTo::Call(parse_evm_address(rcpt)?),
            _ => TransactTo::Create,
        };

        // Realistic mainnet block header overrides to defeat `tx.gasprice == 0` / coinbase checks
        let realistic_coinbase =
            parse_evm_address("0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97")?;

        let mut inspector = SecurityInspector::default();
        let exec_result = {
            let mut evm = Evm::builder()
                .with_db(&mut db)
                .with_external_context(&mut inspector)
                .modify_cfg_env(|cfg| {
                    cfg.chain_id = tx.chain_id;
                })
                .modify_block_env(|blk| {
                    blk.number = U256::from(tx.block_number.max(21_000_000));
                    blk.timestamp = U256::from(tx.timestamp_sec.max(1_730_000_000));
                    blk.coinbase = realistic_coinbase;
                    blk.basefee = U256::from(20_000_000_000u64);
                    blk.prevrandao = Some(B256::repeat_byte(0xa5));
                })
                .modify_tx_env(|tx_env| {
                    tx_env.caller = sender_addr;
                    tx_env.transact_to = transact_to;
                    tx_env.data = calldata.clone();
                    tx_env.value = U256::from(tx.value_wei);
                    tx_env.gas_limit = sim_gas_limit;
                    tx_env.gas_price = U256::from(sim_gas_price_wei);
                    tx_env.chain_id = Some(tx.chain_id);
                    tx_env.nonce = None; // Allow out-of-order pre-sign simulation
                })
                .append_handler_register(revm::inspector_handle_register)
                .build();

            evm.transact_commit()
                .map_err(|e| SimulatorError::ExecutionFailed(format!("{e:?}")))?
        };

        let mut asset_movements = Vec::new();
        let mut permission_mutations = Vec::new();

        // 1. Native value transfer (if non-zero)
        if tx.value_wei > 0 {
            if let Some(rcpt) = &tx.recipient {
                let usd = if tx.value_usd > 0.0 {
                    tx.value_usd
                } else {
                    (tx.value_wei as f64 / 1e18) * self.eth_price_usd
                };
                asset_movements.push(AssetMovement {
                    asset_standard: AssetStandard::Native,
                    token_address: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                    token_symbol: Some("ETH".to_string()),
                    from_address: normalize_address(&tx.sender),
                    to_address: normalize_address(rcpt),
                    raw_amount: tx.value_wei,
                    amount_usd: usd,
                    recipient_post_balance_usd: usd,
                });
            }
        }

        // 2. Decode top-level calldata permissions & token transfers (critical for unseeded contracts & Permit2)
        if let Some(rcpt) = &tx.recipient {
            decode_calldata_mutations(
                &normalize_address(&tx.sender),
                &normalize_address(rcpt),
                &calldata,
                tx.value_usd,
                &mut asset_movements,
                &mut permission_mutations,
            );
        }

        // 3. Extract emitted EVM logs (`Transfer`, `Approval`, `ApprovalForAll`)
        let (success, gas_used, revert_reason) = match exec_result {
            ExecutionResult::Success {
                gas_used, logs, ..
            } => {
                for log in logs {
                    let emitter = format!("{:#x}", log.address);
                    let topics_hex: Vec<String> = log
                        .data
                        .topics()
                        .iter()
                        .map(|t| format!("{:#x}", t))
                        .collect();
                    decode_log_event(
                        &emitter,
                        &topics_hex,
                        log.data.data.as_ref(),
                        &mut asset_movements,
                        &mut permission_mutations,
                    );
                }
                (true, gas_used, None)
            }
            ExecutionResult::Revert { gas_used, output } => (
                false,
                gas_used,
                Some(format!("Reverted: 0x{}", hex::encode(output))),
            ),
            ExecutionResult::Halt { reason, gas_used } => {
                (false, gas_used, Some(format!("Halted: {reason:?}")))
            }
        };

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(SimulationResult {
            success,
            revert_reason,
            gas_used,
            internal_traces: inspector.traces,
            asset_movements,
            permission_mutations,
            env_evasion_opcode_detected: inspector.env_evasion_branch_to_call,
            honeypot_sell_reverted: false,
            observed_sell_tax_pct: 0.0,
            simulation_latency_ms: elapsed_ms,
        })
    }
}

/// Extract address from a 32-byte ABI word (`bytes[12..32]`).
fn word_to_address(word: &[u8]) -> Option<String> {
    if word.len() < 32 {
        return None;
    }
    Some(format!("0x{}", hex::encode(&word[12..32])))
}

/// Check if a 32-byte uint256 word represents an effectively unlimited approval (`>= 2^128 - 1`).
fn word_is_unlimited_u256(word: &[u8]) -> (bool, u128) {
    if word.len() < 32 {
        return (false, 0);
    }
    let upper_non_zero = word[..16].iter().any(|&b| b != 0);
    let mut lower = [0u8; 16];
    lower.copy_from_slice(&word[16..32]);
    let lower_val = u128::from_be_bytes(lower);
    let is_max_uint160 = word[12..32].iter().all(|&b| b == 0xff);
    (
        upper_non_zero || is_max_uint160 || lower_val == u128::MAX,
        if upper_non_zero { u128::MAX } else { lower_val },
    )
}

/// Decode common token approvals, `Permit2`, and transfers directly from ABI calldata.
pub fn decode_calldata_mutations(
    sender: &str,
    target: &str,
    calldata: &[u8],
    fallback_usd: f64,
    movements: &mut Vec<AssetMovement>,
    permissions: &mut Vec<PermissionMutation>,
) {
    if calldata.len() < 4 {
        return;
    }
    let selector = format!("0x{}", hex::encode(&calldata[..4]));
    let args = &calldata[4..];

    match selector.as_str() {
        selectors::ERC20_APPROVE | selectors::INCREASE_ALLOWANCE if args.len() >= 64 => {
            if let Some(spender) = word_to_address(&args[0..32]) {
                let (is_unlimited, raw) = word_is_unlimited_u256(&args[32..64]);
                permissions.push(PermissionMutation {
                    kind: if selector == selectors::ERC20_APPROVE {
                        PermissionKind::Erc20Approve
                    } else {
                        PermissionKind::IncreaseAllowance
                    },
                    owner: sender.to_string(),
                    spender,
                    token_address: target.to_string(),
                    is_unlimited,
                    allowance_usd: if is_unlimited {
                        1_000_000_000.0
                    } else {
                        (raw as f64) / 1e6
                    },
                    expiration_sec: None,
                });
            }
        }
        selectors::SET_APPROVAL_FOR_ALL if args.len() >= 64 => {
            if let Some(operator) = word_to_address(&args[0..32]) {
                let approved = args[63] != 0;
                if approved {
                    permissions.push(PermissionMutation {
                        kind: PermissionKind::ApprovalForAll,
                        owner: sender.to_string(),
                        spender: operator,
                        token_address: target.to_string(),
                        is_unlimited: true,
                        allowance_usd: 1_000_000_000.0,
                        expiration_sec: None,
                    });
                }
            }
        }
        selectors::EIP2612_PERMIT if args.len() >= 128 => {
            if let (Some(owner), Some(spender)) =
                (word_to_address(&args[0..32]), word_to_address(&args[32..64]))
            {
                let (is_unlimited, raw) = word_is_unlimited_u256(&args[64..96]);
                permissions.push(PermissionMutation {
                    kind: PermissionKind::Eip2612Permit,
                    owner,
                    spender,
                    token_address: target.to_string(),
                    is_unlimited,
                    allowance_usd: if is_unlimited {
                        1_000_000_000.0
                    } else {
                        (raw as f64) / 1e6
                    },
                    expiration_sec: None,
                });
            }
        }
        selectors::PERMIT2_APPROVE if args.len() >= 128 => {
            if let (Some(token), Some(spender)) =
                (word_to_address(&args[0..32]), word_to_address(&args[32..64]))
            {
                let (is_unlimited, raw) = word_is_unlimited_u256(&args[64..96]);
                permissions.push(PermissionMutation {
                    kind: PermissionKind::UniswapPermit2,
                    owner: sender.to_string(),
                    spender,
                    token_address: token,
                    is_unlimited,
                    allowance_usd: if is_unlimited {
                        1_000_000_000.0
                    } else {
                        (raw as f64) / 1e6
                    },
                    expiration_sec: None,
                });
            }
        }
        selectors::PERMIT2_PERMIT_SINGLE if args.len() >= 192 => {
            // ABI layout: owner (0..32), details.token (32..64), details.amount (64..96),
            // details.expiration (96..128), details.nonce (128..160), spender (160..192)
            if let (Some(owner), Some(token), Some(spender)) = (
                word_to_address(&args[0..32]),
                word_to_address(&args[32..64]),
                word_to_address(&args[160..192]),
            ) {
                let (is_unlimited, raw) = word_is_unlimited_u256(&args[64..96]);
                permissions.push(PermissionMutation {
                    kind: PermissionKind::UniswapPermit2,
                    owner,
                    spender,
                    token_address: token,
                    is_unlimited,
                    allowance_usd: if is_unlimited {
                        1_000_000_000.0
                    } else {
                        (raw as f64) / 1e6
                    },
                    expiration_sec: None,
                });
            }
        }
        selectors::ERC20_TRANSFER if args.len() >= 64 => {
            if let Some(rcpt) = word_to_address(&args[0..32]) {
                let (_, raw) = word_is_unlimited_u256(&args[32..64]);
                let usd = if fallback_usd > 0.0 {
                    fallback_usd
                } else {
                    (raw as f64) / 1e6
                };
                movements.push(AssetMovement {
                    asset_standard: AssetStandard::Erc20,
                    token_address: target.to_string(),
                    token_symbol: None,
                    from_address: sender.to_string(),
                    to_address: rcpt,
                    raw_amount: raw,
                    amount_usd: usd,
                    recipient_post_balance_usd: usd,
                });
            }
        }
        _ => {}
    }
}

/// Decode standard ERC-20 / ERC-721 `Transfer`, `Approval`, and `ApprovalForAll` log events.
fn decode_log_event(
    emitter: &str,
    topics: &[String],
    data: &[u8],
    movements: &mut Vec<AssetMovement>,
    permissions: &mut Vec<PermissionMutation>,
) {
    if topics.is_empty() {
        return;
    }
    match topics[0].as_str() {
        topics::TRANSFER_TOPIC0 if topics.len() >= 3 => {
            let from = format!("0x{}", &topics[1][topics[1].len().saturating_sub(40)..]);
            let to = format!("0x{}", &topics[2][topics[2].len().saturating_sub(40)..]);
            let (_, raw) = if data.len() >= 32 {
                word_is_unlimited_u256(&data[0..32])
            } else {
                (false, 1)
            };
            let standard = if topics.len() == 4 {
                AssetStandard::Erc721
            } else {
                AssetStandard::Erc20
            };
            movements.push(AssetMovement {
                asset_standard: standard,
                token_address: normalize_address(emitter),
                token_symbol: None,
                from_address: normalize_address(&from),
                to_address: normalize_address(&to),
                raw_amount: raw,
                amount_usd: (raw as f64) / 1e6,
                recipient_post_balance_usd: (raw as f64) / 1e6,
            });
        }
        topics::APPROVAL_TOPIC0 if topics.len() >= 3 && data.len() >= 32 => {
            let owner = format!("0x{}", &topics[1][topics[1].len().saturating_sub(40)..]);
            let spender = format!("0x{}", &topics[2][topics[2].len().saturating_sub(40)..]);
            let (is_unlimited, raw) = word_is_unlimited_u256(&data[0..32]);
            permissions.push(PermissionMutation {
                kind: PermissionKind::Erc20Approve,
                owner: normalize_address(&owner),
                spender: normalize_address(&spender),
                token_address: normalize_address(emitter),
                is_unlimited,
                allowance_usd: if is_unlimited {
                    1_000_000_000.0
                } else {
                    (raw as f64) / 1e6
                },
                expiration_sec: None,
            });
        }
        topics::APPROVAL_FOR_ALL_TOPIC0 if topics.len() >= 3 && data.len() >= 32 => {
            let owner = format!("0x{}", &topics[1][topics[1].len().saturating_sub(40)..]);
            let spender = format!("0x{}", &topics[2][topics[2].len().saturating_sub(40)..]);
            if data[31] != 0 {
                permissions.push(PermissionMutation {
                    kind: PermissionKind::ApprovalForAll,
                    owner: normalize_address(&owner),
                    spender: normalize_address(&spender),
                    token_address: normalize_address(emitter),
                    is_unlimited: true,
                    allowance_usd: 1_000_000_000.0,
                    expiration_sec: None,
                });
            }
        }
        _ => {}
    }
}

/// Remove Output unused warning helper while preserving revm compatibility.
const _: fn(&Output) = |_| {};

#[cfg(test)]
mod tests {
    use super::*;
    use common_types::FinalityStatus;

    fn sample_tx(recipient: &str, calldata_hex: &str) -> CanonicalTransaction {
        CanonicalTransaction {
            chain_id: 1,
            block_number: 21_200_000,
            block_hash: format!("0x{}", "11".repeat(32)),
            parent_hash: format!("0x{}", "00".repeat(32)),
            tx_hash: format!("0x{}", "22".repeat(32)),
            timestamp_sec: 1_730_500_000,
            finality_status: FinalityStatus::Pending,
            sender: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            recipient: Some(recipient.to_string()),
            value_wei: 0,
            value_usd: 0.0,
            calldata_hex: calldata_hex.to_string(),
            gas_limit: 250_000,
            max_fee_per_gas_wei: 30_000_000_000,
            priority_fee_per_gas_wei: 2_000_000_000,
            block_priority_fee_percentile: 50.0,
            nonce: 12,
            blocks_since_last_inbound_funding: Some(100),
            sender_pre_balance_usd: 25_000.0,
        }
    }

    #[test]
    fn simulates_unlimited_erc20_approve_and_decodes_permission() {
        let sim = EvmStateSimulator::new(3200.0);
        let spender_word = format!("000000000000000000000000{}", "bb".repeat(20));
        let max_u256_word = "ff".repeat(32);
        let calldata = format!("0x095ea7b3{spender_word}{max_u256_word}");
        let token = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

        let res = sim
            .simulate_transaction(&sample_tx(token, &calldata))
            .expect("simulation succeeds");

        assert!(res.success);
        assert_eq!(res.permission_mutations.len(), 1);
        let perm = &res.permission_mutations[0];
        assert_eq!(perm.kind, PermissionKind::Erc20Approve);
        assert!(perm.is_unlimited);
        assert_eq!(perm.spender, format!("0x{}", "bb".repeat(20)));
    }

    #[test]
    fn detects_coinbase_evasion_branch_and_delegatecall_in_revm() {
        let mut sim = EvmStateSimulator::new(3200.0);
        let malicious_contract = "0xcccccccccccccccccccccccccccccccccccccccc";
        let impl_target = "dddddddddddddddddddddddddddddddddddddddd";

        // Hand-crafted EVM runtime bytecode:
        // 00: 41          COINBASE
        // 01: 15          ISZERO
        // 02: 15          ISZERO        (1 because simulator injects realistic coinbase!)
        // 03: 60 08       PUSH1 0x08
        // 05: 57          JUMPI         (conditional branch gated on COINBASE!)
        // 06: 00          STOP
        // 07: 5b          JUMPDEST      (offset 0x07? wait: index 7 -> let's push 0x07!)
        // Let's trace exact byte offsets:
        // [0] 0x41 (COINBASE)
        // [1] 0x60, [2] 0x06 (PUSH1 0x06)
        // [3] 0x57 (JUMPI -> jumps to offset 6 since COINBASE != 0)
        // [4] 0x00 (STOP)
        // [5] 0x00 (STOP)
        // [6] 0x5b (JUMPDEST)
        // [7] 0x60, [8] 0x00 (PUSH1 0 retSize)
        // [9] 0x60, [10] 0x00 (PUSH1 0 retOffset)
        // [11] 0x60, [12] 0x00 (PUSH1 0 argsSize)
        // [13] 0x60, [14] 0x00 (PUSH1 0 argsOffset)
        // [15] 0x73, [16..35] <20-byte impl_target> (PUSH20 target)
        // [36] 0x5a (GAS)
        // [37] 0xf4 (DELEGATECALL)
        // [38] 0x00 (STOP)
        let bytecode = format!(
            "0x4160065700005b600060006000600073{impl_target}5af400"
        );

        sim.seed_account(
            malicious_contract,
            SeededAccount {
                balance_wei: 0,
                nonce: 1,
                bytecode_hex: Some(bytecode),
                storage_slots: HashMap::new(),
            },
        );

        let res = sim
            .simulate_transaction(&sample_tx(malicious_contract, "0xdeadbeef"))
            .expect("simulation succeeds");

        assert!(res.env_evasion_opcode_detected);
        assert!(res
            .internal_traces
            .iter()
            .any(|t| t.call_type == CallType::DelegateCall
                && t.target == format!("0x{impl_target}")));
    }
}
