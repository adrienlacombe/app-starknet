use crate::crypto;
use crate::types::FieldElement;

extern crate alloc;
use alloc::vec::Vec;

#[derive(Default, Debug)]
pub struct Call {
    pub to: FieldElement,
    pub selector: FieldElement,
    pub nb_calldata: usize,
    pub nb_rcv_calldata: usize,
    pub calldata: Vec<FieldElement>,
}

#[derive(Default, Debug)]
pub struct InvokeTransactionV1 {
    pub version: FieldElement,
    pub sender_address: FieldElement,
    pub max_fee: FieldElement,
    pub chain_id: FieldElement,
    pub nonce: FieldElement,
    pub nb_calls: usize,
    pub nb_rcv_calls: usize,
    pub call: Call,
    pub hasher: crypto::pedersen::PedersenHasher,
    pub hasher_calldata: crypto::pedersen::PedersenHasher,
}

#[derive(Default, Debug)]
pub struct InvokeTransactionV3 {
    pub version: FieldElement,
    pub sender_address: FieldElement,
    pub tip: FieldElement,
    pub l1_gas_bounds: FieldElement,
    pub l2_gas_bounds: FieldElement,
    pub l1_data_gas_bounds: FieldElement,
    pub paymaster_data: Vec<FieldElement>,
    pub chain_id: FieldElement,
    pub nonce: FieldElement,
    pub data_availability_mode: FieldElement,
    pub account_deployment_data: Vec<FieldElement>,
    pub nb_calls: usize,
    pub nb_rcv_calls: usize,
    pub call: Call,
    pub hasher: crypto::poseidon::PoseidonHasher,
    pub hasher_calldata: crypto::poseidon::PoseidonHasher,
}

#[derive(Default, Debug)]
pub struct DeployAccountTransactionV1 {
    pub version: FieldElement,
    pub contract_address: FieldElement,
    pub max_fee: FieldElement,
    pub chain_id: FieldElement,
    pub nonce: FieldElement,
    pub class_hash: FieldElement,
    pub contract_address_salt: FieldElement,
    pub constructor_calldata: Vec<FieldElement>,
    pub hasher: crypto::pedersen::PedersenHasher,
}

#[derive(Default, Debug)]
pub struct DeployAccountTransactionV3 {
    pub version: FieldElement,
    pub contract_address: FieldElement,
    pub tip: FieldElement,
    pub l1_gas_bounds: FieldElement,
    pub l2_gas_bounds: FieldElement,
    pub l1_data_gas_bounds: FieldElement,
    pub paymaster_data: Vec<FieldElement>,
    pub chain_id: FieldElement,
    pub nonce: FieldElement,
    pub data_availability_mode: FieldElement,
    pub class_hash: FieldElement,
    pub contract_address_salt: FieldElement,
    pub nb_constructor_calldata: usize,
    pub nb_rcv_constructor_calldata: usize,
    pub hasher: crypto::poseidon::PoseidonHasher,
    pub hasher_calldata: crypto::poseidon::PoseidonHasher,
}

#[derive(Default, Debug)]
pub enum Transaction {
    #[default]
    None,
    InvokeV1(InvokeTransactionV1),
    InvokeV3(InvokeTransactionV3),
    DeployAccountV1(DeployAccountTransactionV1),
    DeployAccountV3(DeployAccountTransactionV3),
}

impl Transaction {
    pub fn get_nb_received_calls(&self) -> usize {
        match self {
            Transaction::InvokeV1(tx) => tx.nb_rcv_calls,
            Transaction::InvokeV3(tx) => tx.nb_rcv_calls,
            Transaction::DeployAccountV1(_tx) => 1usize,
            Transaction::DeployAccountV3(_tx) => 1usize,
            Transaction::None => 0usize,
        }
    }

    pub fn get_nb_calls(&self) -> usize {
        match self {
            Transaction::InvokeV1(tx) => tx.nb_calls,
            Transaction::InvokeV3(tx) => tx.nb_calls,
            Transaction::DeployAccountV1(_tx) => 1usize,
            Transaction::DeployAccountV3(_tx) => 1usize,
            Transaction::None => 0usize,
        }
    }
}

#[derive(PartialEq)]
pub enum RequestType {
    Unknown,
    GetPubkey,
    GetMldsa44Pubkey,
    #[cfg(feature = "signhash")]
    SignHash,
    SignMldsa44Hash,
    SignTx,
    SignTxV1,
    SignDeployAccount,
    SignDeployAccountV1,
}

pub const MLDSA44_TRANSFER_MAX_LEN: usize = 2420;

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum MldsaObjectKind {
    None = 0,
    PublicKey = 1,
    Signature = 2,
}

pub struct MldsaTransfer {
    pub data: [u8; MLDSA44_TRANSFER_MAX_LEN],
    pub len: usize,
    pub session_id: u32,
    pub kind: MldsaObjectKind,
}

impl MldsaTransfer {
    pub const fn new() -> Self {
        Self {
            data: [0u8; MLDSA44_TRANSFER_MAX_LEN],
            len: 0,
            session_id: 0,
            kind: MldsaObjectKind::None,
        }
    }

    pub fn clear(&mut self) {
        self.data.fill(0);
        self.len = 0;
        self.session_id = 0;
        self.kind = MldsaObjectKind::None;
    }
}

#[derive(Default, Debug)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

use ledger_device_sdk::nbgl::{NbglHomeAndSettings, NbglSpinner};

pub struct Ctx {
    pub req_type: RequestType,
    pub tx: Transaction,
    pub hash: FieldElement,
    pub signature: Signature,
    pub bip32_path: [u32; 6],
    pub mldsa_transfer: MldsaTransfer,
    pub next_mldsa_session_id: u32,
    pub home: NbglHomeAndSettings,
    pub spinner: NbglSpinner,
}

impl Ctx {
    pub fn new() -> Self {
        Self {
            req_type: RequestType::Unknown,
            tx: Transaction::default(),
            hash: FieldElement::default(),
            signature: Signature::default(),
            bip32_path: [0u32; 6],
            mldsa_transfer: MldsaTransfer::new(),
            next_mldsa_session_id: 1,
            home: NbglHomeAndSettings::new(),
            spinner: NbglSpinner::new(),
        }
    }

    pub fn reset(&mut self) {
        self.req_type = RequestType::Unknown;
        self.tx = Transaction::default();
        self.hash = FieldElement::default();
        self.signature = Signature::default();
        self.bip32_path.fill(0);
        self.mldsa_transfer.clear();
    }

    pub fn start_mldsa_transfer(&mut self, kind: MldsaObjectKind, len: usize) {
        self.mldsa_transfer.kind = kind;
        self.mldsa_transfer.len = len;
        self.mldsa_transfer.session_id = self.next_mldsa_session_id;
        self.next_mldsa_session_id = self.next_mldsa_session_id.wrapping_add(1).max(1);
    }

    /// Consume an ML-DSA request without discarding an approved transfer.
    pub fn finish_mldsa_request(&mut self) {
        self.req_type = RequestType::Unknown;
        self.hash = FieldElement::default();
        self.bip32_path.fill(0);
    }
}
