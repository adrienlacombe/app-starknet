use crate::types::FieldElement;
use ledger_device_sdk::sys::*;

/// Streaming Keccak-256 hasher wrapping the Ledger OS `cx_sha3_t` context.
///
/// Used to compute `starknet_keccak(encode_type_string)` by streaming
/// the encode_type string in chunks (since APDU payload is limited).
pub struct KeccakHasher {
    ctx: cx_sha3_t,
}

impl KeccakHasher {
    /// Initialise a new Keccak-256 streaming context.
    pub fn new() -> Self {
        let mut hasher = Self {
            ctx: cx_sha3_t {
                header: cx_hash_header_s {
                    info: core::ptr::null(),
                    counter: 0,
                },
                output_size: 0,
                block_size: 0,
                blen: 0,
                block: [0u8; 200],
                acc: [0u64; 25],
            },
        };
        unsafe {
            cx_keccak_init_no_throw(&mut hasher.ctx, 256);
        }
        hasher
    }

    /// Feed data into the running keccak hash.
    pub fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        unsafe {
            cx_hash_no_throw(
                &mut self.ctx.header as *mut cx_hash_t,
                0, // mode=0 means update (not final)
                data.as_ptr(),
                data.len(),
                core::ptr::null_mut(),
                0,
            );
        }
    }

    /// Finalise the keccak-256 hash and return a `starknet_keccak` result:
    /// the 256-bit keccak digest with the most-significant 6 bits masked off
    /// (i.e. result fits in 250 bits).
    pub fn finalize_starknet_keccak(mut self) -> FieldElement {
        let mut digest = [0u8; 32];
        unsafe {
            cx_hash_no_throw(
                &mut self.ctx.header as *mut cx_hash_t,
                CX_LAST, // finalize
                core::ptr::null(), // no additional data
                0,
                digest.as_mut_ptr(),
                32,
            );
        }
        // Mask MSB: starknet_keccak keeps only the lower 250 bits
        digest[0] &= 0x03;
        FieldElement { value: digest }
    }
}
