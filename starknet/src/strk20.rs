use core::cmp::Ordering;

use ledger_device_sdk::{
    ecc::{bip32_derive, CurvesId, Secret},
    hmac::{sha2::Sha2_256, HMACInit},
    io::Reply,
    sys::{
        cx_hash_sha256, cx_math_cmp_no_throw, cx_math_modm_no_throw, cx_math_subm_no_throw, CX_OK,
    },
};

pub const CONTEXT_LENGTH: usize = 116;
pub const COMMAND_PAYLOAD_LENGTH: usize = 24 + CONTEXT_LENGTH;

const DOMAIN_SEPARATOR: &[u8; 22] = b"STRK20_ACCOUNT_LEAF_V1";
const HMAC_INPUT_LENGTH: usize = DOMAIN_SEPARATOR.len() + CONTEXT_LENGTH + 4;

// Stark-curve order:
// 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
const STARK_CURVE_ORDER: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xb7, 0x81, 0x12, 0x6d, 0xca, 0xe7, 0xb2, 0x32, 0x1e, 0x66, 0xa2, 0x41, 0xad, 0xc6, 0x4d, 0x2f,
];

// floor(STARK_CURVE_ORDER / 2), excluded by the account-leaf-v1 profile.
const STARK_CURVE_LOWER_HALF_BOUNDARY: [u8; 32] = [
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xdb, 0xc0, 0x89, 0x36, 0xe5, 0x73, 0xd9, 0x19, 0x0f, 0x33, 0x51, 0x20, 0xd6, 0xe3, 0x26, 0x97,
];

// 2^256 - (2^256 mod STARK_CURVE_ORDER). This is also the rejection
// boundary used by the app's EIP-2645 Stark account-key grinding.
const UNBIASED_REDUCTION_LIMIT: [u8; 32] = [
    0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf7,
    0x38, 0xa1, 0x3b, 0x4b, 0x92, 0x0e, 0x94, 0x11, 0xae, 0x6d, 0xa5, 0xf4, 0x0b, 0x03, 0x58, 0xb1,
];

// Starknet field prime, used to reject non-canonical felt252 encodings.
const STARK_FIELD_PRIME: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

const ZERO: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strk20Error {
    InvalidContextLength = 0xFF03,
    UnsupportedVersion = 0xFF04,
    InvalidFelt = 0xFF05,
    UnsupportedKeyIndex = 0xFF06,
    AccountKeyDerivation = 0xFF07,
    InvalidAccountLeaf = 0xFF08,
    Hmac = 0xFF09,
    Math = 0xFF0A,
    DerivationExhausted = 0xFF0B,
}

impl From<Strk20Error> for Reply {
    fn from(error: Strk20Error) -> Self {
        Reply(error as u16)
    }
}

pub struct DerivationContext {
    bytes: [u8; CONTEXT_LENGTH],
}

impl DerivationContext {
    pub fn parse(input: &[u8]) -> Result<Self, Strk20Error> {
        if input.len() != CONTEXT_LENGTH {
            return Err(Strk20Error::InvalidContextLength);
        }
        if input[0..4] != [0, 0, 0, 1] {
            return Err(Strk20Error::UnsupportedVersion);
        }
        if !is_canonical_felt(&input[4..36])
            || !is_canonical_felt(&input[36..68])
            || !is_canonical_felt(&input[68..100])
        {
            return Err(Strk20Error::InvalidFelt);
        }
        if input[100..116] != [0u8; 16] {
            return Err(Strk20Error::UnsupportedKeyIndex);
        }

        let mut bytes = [0u8; CONTEXT_LENGTH];
        bytes.copy_from_slice(input);
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; CONTEXT_LENGTH] {
        &self.bytes
    }

    pub fn chain_id(&self) -> &[u8] {
        &self.bytes[4..36]
    }

    pub fn account_address(&self) -> &[u8] {
        &self.bytes[36..68]
    }

    pub fn pool_address(&self) -> &[u8] {
        &self.bytes[68..100]
    }
}

pub fn derive_viewing_key(
    bip32_path: &[u32; 6],
    context: &DerivationContext,
) -> Result<Secret<32>, Strk20Error> {
    let account_leaf = derive_stark_account_leaf(bip32_path)?;
    let account_leaf_bytes: &[u8; 32] = account_leaf
        .as_ref()
        .try_into()
        .map_err(|_| Strk20Error::AccountKeyDerivation)?;
    derive_viewing_key_from_leaf(account_leaf_bytes, context).map(|(key, _counter)| key)
}

fn derive_stark_account_leaf(bip32_path: &[u32; 6]) -> Result<Secret<32>, Strk20Error> {
    let mut secp256k1_node = Secret::<64>::new();
    bip32_derive(
        CurvesId::Secp256k1,
        bip32_path,
        secp256k1_node.as_mut(),
        None,
    )
    .map_err(|_| Strk20Error::AccountKeyDerivation)?;

    let mut account_leaf = Secret::<32>::new();
    for grind_index in 0..=u8::MAX {
        // EIP-2645 hashes the 32-byte secp256k1 node plus this one-byte
        // grinding index, exactly as Stark256::derive_from_path does.
        secp256k1_node.as_mut()[32] = grind_index;
        unsafe {
            cx_hash_sha256(
                secp256k1_node.as_ref().as_ptr(),
                33,
                account_leaf.as_mut().as_mut_ptr(),
                32,
            )
        };

        if compare(account_leaf.as_ref(), &UNBIASED_REDUCTION_LIMIT)? == Ordering::Less {
            reduce_mod_stark_order(account_leaf.as_mut())?;
            return Ok(account_leaf);
        }
    }

    Err(Strk20Error::AccountKeyDerivation)
}

fn derive_viewing_key_from_leaf(
    account_leaf: &[u8; 32],
    context: &DerivationContext,
) -> Result<(Secret<32>, u32), Strk20Error> {
    if compare(account_leaf, &ZERO)? != Ordering::Greater
        || compare(account_leaf, &STARK_CURVE_ORDER)? != Ordering::Less
    {
        return Err(Strk20Error::InvalidAccountLeaf);
    }

    let mut hmac_input = [0u8; HMAC_INPUT_LENGTH];
    hmac_input[..DOMAIN_SEPARATOR.len()].copy_from_slice(DOMAIN_SEPARATOR);
    hmac_input[DOMAIN_SEPARATOR.len()..DOMAIN_SEPARATOR.len() + CONTEXT_LENGTH]
        .copy_from_slice(context.as_bytes());

    for counter in 0..=u32::MAX {
        hmac_input[HMAC_INPUT_LENGTH - 4..].copy_from_slice(&counter.to_be_bytes());

        let mut digest = Secret::<32>::new();
        let mut hmac = Sha2_256::new(account_leaf);
        let hmac_result = hmac.hmac(&hmac_input, digest.as_mut());
        zeroize_hmac(&mut hmac);
        hmac_result.map_err(|_| Strk20Error::Hmac)?;

        if compare(digest.as_ref(), &UNBIASED_REDUCTION_LIMIT)? != Ordering::Less {
            continue;
        }

        reduce_mod_stark_order(digest.as_mut())?;
        if compare(digest.as_ref(), &ZERO)? == Ordering::Equal {
            continue;
        }

        let mut negated = Secret::<32>::new();
        let status = unsafe {
            cx_math_subm_no_throw(
                negated.as_mut().as_mut_ptr(),
                ZERO.as_ptr(),
                digest.as_ref().as_ptr(),
                STARK_CURVE_ORDER.as_ptr(),
                32,
            )
        };
        if status != CX_OK {
            return Err(Strk20Error::Math);
        }

        let folded = if compare(digest.as_ref(), negated.as_ref())? == Ordering::Greater {
            negated
        } else {
            digest
        };

        if compare(folded.as_ref(), &STARK_CURVE_LOWER_HALF_BOUNDARY)? == Ordering::Less {
            return Ok((folded, counter));
        }
    }

    Err(Strk20Error::DerivationExhausted)
}

fn reduce_mod_stark_order(value: &mut [u8]) -> Result<(), Strk20Error> {
    let status = unsafe {
        cx_math_modm_no_throw(
            value.as_mut_ptr(),
            value.len(),
            STARK_CURVE_ORDER.as_ptr(),
            STARK_CURVE_ORDER.len(),
        )
    };
    if status == CX_OK {
        Ok(())
    } else {
        Err(Strk20Error::Math)
    }
}

fn compare(left: &[u8], right: &[u8]) -> Result<Ordering, Strk20Error> {
    if left.len() != right.len() {
        return Err(Strk20Error::Math);
    }

    let mut result = 0;
    let status =
        unsafe { cx_math_cmp_no_throw(left.as_ptr(), right.as_ptr(), left.len(), &mut result) };
    if status != CX_OK {
        return Err(Strk20Error::Math);
    }

    Ok(result.cmp(&0))
}

fn is_canonical_felt(value: &[u8]) -> bool {
    value.len() == 32 && compare_bytes(value, &STARK_FIELD_PRIME) == Ordering::Less
}

fn compare_bytes(left: &[u8], right: &[u8]) -> Ordering {
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        match left_byte.cmp(right_byte) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    left.len().cmp(&right.len())
}

fn zeroize_hmac(hmac: &mut Sha2_256) {
    // The SDK's HMAC type has no Drop implementation. Volatile writes ensure
    // that the keyed hash state is scrubbed instead of being optimized away.
    let hmac_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (hmac as *mut Sha2_256).cast::<u8>(),
            core::mem::size_of::<Sha2_256>(),
        )
    };
    for byte in hmac_bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}
