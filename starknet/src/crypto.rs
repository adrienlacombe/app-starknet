use ledger_device_sdk::ecc::{ECPublicKey, SeedDerive, Stark256};
use ledger_device_sdk::io::{Reply, SyscallError};

pub mod pedersen;
pub mod poseidon;

use crate::context::{Ctx, Transaction};
use crate::types::FieldElement;

/// Length in bytes of an EIP-2645 derivation path (without m), e.g m/2645'/1195502025'/1148870696'/0'/0'/0
/// with every step encoded with 4 bytes (total length = 6 x 4 = 24 bytes)
const EIP2645_PATH_BYTES_LENGTH: usize = 24;
/// Hardened 2645 value
const EIP2645_PATH_PREFIX: u32 = 0x80000A55;

#[derive(Debug)]
pub enum CryptoError {
    UnvalidPathPrefix = 0xFF00,
    UnvalidPathLength = 0xFF01,
    Sign = 0xFF02,
}

impl From<CryptoError> for Reply {
    fn from(ce: CryptoError) -> Reply {
        Reply(ce as u16)
    }
}

/// Helper function that signs with ECDSA in deterministic nonce
pub fn sign_hash(ctx: &mut Ctx) -> Result<(), CryptoError> {
    // ledger_device_sdk::testing::debug_print("Before shift: ");
    // ledger_device_sdk::testing::debug_print(&ctx.hash.m_hash.to_hex_string());
    // ledger_device_sdk::testing::debug_print("\n");
    poseidon::poseidon_shift(&mut ctx.hash.m_hash);
    // ledger_device_sdk::testing::debug_print("After shift:  ");
    // ledger_device_sdk::testing::debug_print(&ctx.hash.m_hash.to_hex_string());
    // ledger_device_sdk::testing::debug_print("\n");

    match Stark256::derive_from_path(ctx.bip32_path.as_ref())
        .deterministic_sign(ctx.hash.m_hash.value.as_ref())
    {
        Ok(s) => {
            let der = s.0;
            convert_der_to_rs(&der[..], &mut ctx.hash.r, &mut ctx.hash.s).unwrap();
            ctx.hash.v = s.2 as u8;
            Ok(())
        }
        Err(_) => Err(CryptoError::Sign),
    }
}

/// Helper function that retrieves public key
pub fn get_pubkey(ctx: &Ctx) -> Result<ECPublicKey<65, 'W'>, SyscallError> {
    let private_key = Stark256::derive_from_path(&ctx.bip32_path);

    match private_key.public_key() {
        Ok(public_key) => Ok(public_key),
        Err(_) => Err(SyscallError::Unspecified),
    }
}

fn read_be_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(core::mem::size_of::<u32>());
    *input = rest;
    u32::from_be_bytes(int_bytes.try_into().unwrap())
}

pub fn set_derivation_path(buf: &mut &[u8], ctx: &mut Ctx) -> Result<(), CryptoError> {
    match buf.len() {
        EIP2645_PATH_BYTES_LENGTH => {
            for i in 0..6 {
                ctx.bip32_path[i] = read_be_u32(buf);
            }
            match ctx.bip32_path[0] {
                EIP2645_PATH_PREFIX => Ok(()),
                _ => Err(CryptoError::UnvalidPathPrefix),
            }
        }
        _ => Err(CryptoError::UnvalidPathLength),
    }
}

#[derive(Debug)]
enum ConvertError<const R: usize, const S: usize> {
    /// The DER prefix (at index 0) found was different than the expected 0x30
    InvalidDERPrefix(u8),
    /// The R marker was different than expected (0x02)
    InvalidRMarker(u8),
    /// The encoded len for R was not the same as the expected
    InvalidRLen(usize),
    /// The S marker was different than expected (0x02)
    InvalidSMarker(u8),
    /// The encoded len for S was not the same as the expected
    InvalidSLen(usize),
    /// Passed signature was too short to be read properly
    TooShort,
    /// Passed signature encoded payload len was not in the expected range
    InvalidPayloadLen(usize, usize, usize),
}

/// Converts a DER encoded signature into a (r, s) encoded signture
fn convert_der_to_rs<const R: usize, const S: usize>(
    sig: &[u8],
    out_r: &mut [u8; R],
    out_s: &mut [u8; S],
) -> Result<(), ConvertError<R, S>> {
    const MINPAYLOADLEN: usize = 1;
    const PAYLOADLEN: usize = 32;
    const MAXPAYLOADLEN: usize = 33;

    let payload_range = core::ops::RangeInclusive::new(MINPAYLOADLEN, MAXPAYLOADLEN);
    // https://github.com/libbitcoin/libbitcoin-system/wiki/ECDSA-and-DER-Signatures#serialised-der-signature-sequence
    // 0                [1 byte]   - DER Prefix
    // 1                [1 byte]   - Payload len
    // 2                [1 byte]   - R Marker. Always 02
    // 3                [1 byte]   - R Len                      RLEN
    // ROFFSET ...      [.?. byte] - R                          ROFFSET
    // ROFFSET+RLEN     [1 byte]   - S Marker. Always 02
    // ROFFSET+RLEN+1   [1 byte]   - S Length                   SLEN
    // ROFFSET+RLEN+2   [.?. byte] - S                          SOFFSET

    //check that we have at least the DER prefix and the payload len
    if sig.len() < 2 {
        return Err(ConvertError::TooShort);
    }

    //check DER prefix
    if sig[0] != 0x30 {
        return Err(ConvertError::InvalidDERPrefix(sig[0]));
    }

    //check payload len size
    let payload_len = sig[1] as usize;
    let min_payload_len = 2 + MINPAYLOADLEN + 2 + MINPAYLOADLEN;
    let max_payload_len = 2 + MAXPAYLOADLEN + 2 + MAXPAYLOADLEN;
    if payload_len < min_payload_len || payload_len > max_payload_len {
        return Err(ConvertError::InvalidPayloadLen(
            min_payload_len,
            payload_len,
            max_payload_len,
        ));
    }

    //check that the input slice is at least as long as the encoded len
    if sig.len() - 2 < payload_len {
        return Err(ConvertError::TooShort);
    }

    //retrieve R
    if sig[2] != 0x02 {
        return Err(ConvertError::InvalidRMarker(sig[2]));
    }

    let r_len = sig[3] as usize;
    if !payload_range.contains(&r_len) {
        return Err(ConvertError::InvalidRLen(r_len));
    }

    //sig[4], after DER, after Payload, after marker after len
    let r = &sig[4..4 + r_len];

    //retrieve S
    if sig[4 + r_len] != 0x02 {
        return Err(ConvertError::InvalidSMarker(sig[4 + r_len]));
    }

    let s_len = sig[4 + r_len + 1] as usize;
    if !payload_range.contains(&s_len) {
        return Err(ConvertError::InvalidSLen(s_len));
    }

    //after r (4 + r_len), after marker, after len
    let s = &sig[4 + r_len + 2..4 + r_len + 2 + s_len];

    out_r.fill(0);
    out_r[PAYLOADLEN - r_len..].copy_from_slice(r);

    out_s.fill(0);
    out_s[PAYLOADLEN - s_len..].copy_from_slice(s);

    Ok(())
}

pub fn tx_hash(tx: &Transaction) -> FieldElement {
    match tx.version.into() {
        1u8 => {
            let mut hasher = pedersen::PedersenHasher::new();
            /* "invoke" */
            hasher.update(FieldElement::INVOKE);
            /* version */
            hasher.update(tx.version);
            /* sender_address */
            hasher.update(tx.sender_address);
            /* 0 */
            hasher.update(FieldElement::ZERO);
            /* h(calldata) */
            let mut hasher_calldata = pedersen::PedersenHasher::new();
            hasher_calldata.update(FieldElement::from(tx.calls.len() as u8));
            let mut calldata_len = 1u8;
            tx.calls.iter().for_each(|c| {
                hasher_calldata.update(c.to);
                hasher_calldata.update(c.selector);
                hasher_calldata.update(FieldElement::from(c.calldata.len() as u8));
                calldata_len += 3;
                c.calldata.iter().for_each(|d| {
                    hasher_calldata.update(*d);
                    calldata_len += 1;
                });
            });
            hasher_calldata.update(FieldElement::from(calldata_len));
            let hash_calldata = hasher_calldata.finalize();
            hasher.update(hash_calldata);
            /* max fee */
            hasher.update(tx.max_fee);
            /* chain_id */
            hasher.update(tx.chain_id);
            /* nonce */
            hasher.update(tx.nonce);

            hasher.update(FieldElement::from(8u8));

            hasher.finalize()
        }
        3u8 => {
            let mut hasher = poseidon::PoseidonHasher::new();
            /* "invoke" */
            hasher.update(FieldElement::INVOKE);
            /* version */
            hasher.update(tx.version);
            /* sender_address */
            hasher.update(tx.sender_address);
            /* h(tip, l1_gas_bounds, l2_gas_bounds) */
            let fee_hash = poseidon::PoseidonStark252::hash_many(&[
                tx.tip,
                tx.l1_gas_bounds,
                tx.l2_gas_bounds,
            ]);
            hasher.update(fee_hash);
            /* h(paymaster_data) */
            let paymaster_hash = poseidon::PoseidonStark252::hash_many(&tx.paymaster_data);
            hasher.update(paymaster_hash);
            /* chain_id */
            hasher.update(tx.chain_id);
            /* nonce */
            hasher.update(tx.nonce);
            /* data_availability_modes */
            hasher.update(tx.data_availability_mode);
            /* h(account_deployment_data) */
            let accound_deployment_data_hash =
                poseidon::PoseidonStark252::hash_many(&tx.account_deployment_data);
            hasher.update(accound_deployment_data_hash);
            /* h(calldata) */
            let mut hasher_calldata = poseidon::PoseidonHasher::new();
            hasher_calldata.update(FieldElement::from(tx.calls.len() as u8));
            tx.calls.iter().for_each(|c| {
                hasher_calldata.update(c.to);
                hasher_calldata.update(c.selector);
                hasher_calldata.update(FieldElement::from(c.calldata.len() as u8));
                c.calldata.iter().for_each(|d| hasher_calldata.update(*d));
            });
            let hash_calldata = hasher_calldata.finalize();

            hasher.update(hash_calldata);

            hasher.finalize()
        }
        _ => panic!("Invalid version"),
    }
}
