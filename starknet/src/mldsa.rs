//! ML-DSA-44 key derivation and signing for the experimental Starknet signer.

use crate::context::{Ctx, MldsaObjectKind};
use ledger_device_sdk::ecc::{bip32_derive, CurvesId, Secret};
use ledger_device_sdk::hash::{sha2::Sha2_256, HashInit};
use ledger_device_sdk::io::Reply;
use ledger_device_sdk::mldsa::{
    self as sdk_mldsa, MlDsaParam, MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN,
};
use ledger_device_sdk::sys::{cx_err_t, MLDSA_param_t, CX_OK, MLDSA_44};

const KEY_DERIVATION_DOMAIN: &[u8] = b"Starknet ML-DSA-44 seed v1";
const MLDSA_SEED_LEN: usize = 32;

#[derive(Debug)]
pub enum MldsaError {
    KeyDerivation,
    KeyGeneration,
    Signing,
    Fingerprint,
}

impl From<MldsaError> for Reply {
    fn from(_error: MldsaError) -> Self {
        // Keep parity with the existing host client's SW_SIGNATURE_FAIL value.
        Reply(0xB008)
    }
}

extern "C" {
    /// Deterministic FIPS 204 key generation implemented by the Ledger C SDK.
    ///
    /// The safe Rust SDK currently exposes only randomized key generation. This
    /// symbol is linked by the SDK's `mldsa` feature and lets the application
    /// derive a recoverable, domain-separated key from the Ledger seed. Replace
    /// this declaration once the Rust SDK exposes a public seeded-keygen wrapper.
    /// The declaration matches ledger-secure-sdk v26.5.0 (db03d3e8).
    fn MLDSA_internal_keygen(
        pk: *mut u8,
        pk_len: usize,
        sk: *mut u8,
        sk_len: usize,
        seed: *const u8,
        param: MLDSA_param_t,
    ) -> cx_err_t;
}

fn derive_mldsa_seed(path: &[u32], seed: &mut Secret<MLDSA_SEED_LEN>) -> Result<(), MldsaError> {
    let mut bip32_node = Secret::<64>::new();
    bip32_derive(CurvesId::Secp256k1, path, bip32_node.as_mut(), None)
        .map_err(|_| MldsaError::KeyDerivation)?;

    let mut hasher = Sha2_256::new();
    hasher
        .update(KEY_DERIVATION_DOMAIN)
        .map_err(|_| MldsaError::KeyDerivation)?;
    hasher
        .update(&bip32_node.as_ref()[..32])
        .map_err(|_| MldsaError::KeyDerivation)?;
    hasher
        .finalize(seed.as_mut())
        .map_err(|_| MldsaError::KeyDerivation)
}

fn keygen_from_path(
    path: &[u32],
    public_key: &mut [u8],
    secret_key: &mut [u8],
) -> Result<(), MldsaError> {
    let mut seed = Secret::<MLDSA_SEED_LEN>::new();
    derive_mldsa_seed(path, &mut seed)?;

    // SAFETY: all buffers have the exact ML-DSA-44 sizes required by the C SDK,
    // remain valid for the call, do not overlap, and `seed` has the FIPS 204
    // key-generation seed length.
    let error = unsafe {
        MLDSA_internal_keygen(
            public_key.as_mut_ptr(),
            public_key.len(),
            secret_key.as_mut_ptr(),
            secret_key.len(),
            seed.as_ref().as_ptr(),
            MLDSA_44,
        )
    };
    if error == CX_OK {
        Ok(())
    } else {
        Err(MldsaError::KeyGeneration)
    }
}

pub fn generate_public_key(ctx: &mut Ctx) -> Result<[u8; 32], MldsaError> {
    let path = ctx.bip32_path;
    let mut secret_key = Secret::<MLDSA44_SK_LEN>::new();
    keygen_from_path(
        &path,
        &mut ctx.mldsa_transfer.data[..MLDSA44_PK_LEN],
        secret_key.as_mut(),
    )?;

    let mut fingerprint = [0u8; 32];
    Sha2_256::new()
        .hash(&ctx.mldsa_transfer.data[..MLDSA44_PK_LEN], &mut fingerprint)
        .map_err(|_| MldsaError::Fingerprint)?;
    ctx.start_mldsa_transfer(MldsaObjectKind::PublicKey, MLDSA44_PK_LEN);
    Ok(fingerprint)
}

pub fn sign_hash(ctx: &mut Ctx) -> Result<(), MldsaError> {
    let path = ctx.bip32_path;
    let mut secret_key = Secret::<MLDSA44_SK_LEN>::new();
    keygen_from_path(
        &path,
        &mut ctx.mldsa_transfer.data[..MLDSA44_PK_LEN],
        secret_key.as_mut(),
    )?;

    // Starknet APDUs and the review screen use canonical big-endian felts. The
    // Cairo verifier serializes the felt to exactly 32 little-endian bytes.
    let mut message = ctx.hash.value;
    message.reverse();
    let signature_len = sdk_mldsa::sign(
        &mut ctx.mldsa_transfer.data[..MLDSA44_SIG_LEN],
        &message,
        &[],
        secret_key.as_ref(),
        MlDsaParam::MlDsa44,
    )
    .map_err(|_| MldsaError::Signing)?;
    if signature_len != MLDSA44_SIG_LEN {
        return Err(MldsaError::Signing);
    }

    ctx.start_mldsa_transfer(MldsaObjectKind::Signature, signature_len);
    Ok(())
}
