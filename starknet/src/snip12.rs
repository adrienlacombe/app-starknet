extern crate alloc;
use alloc::string::String;

use crate::crypto::keccak::KeccakHasher;
use crate::crypto::pedersen::PedersenHasher;
use crate::crypto::poseidon::{PoseidonHasher, PoseidonStark252};
use crate::crypto::HasherTrait;
use crate::types::FieldElement;

/// Maximum number of type definitions (domain + primary + nested)
const MAX_TYPES: usize = 4;
/// Maximum number of displayable fields
pub const MAX_DISPLAY_FIELDS: usize = 8;
/// Maximum field name length
const MAX_NAME_LEN: usize = 24;
/// Maximum formatted display value length
const MAX_VALUE_LEN: usize = 80;

/// SNIP-12 revision (determines hash function)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Snip12Revision {
    V0, // Pedersen
    V1, // Poseidon
}

impl Default for Snip12Revision {
    fn default() -> Self {
        Snip12Revision::V1
    }
}

/// Type tags for display formatting of field values
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TypeTag {
    Felt = 0x00,
    ShortString = 0x01,
    Address = 0x02,
    U128 = 0x03,
    U256 = 0x04,
    Bool = 0x05,
    Timestamp = 0x06,
    TokenAmount = 0x07,
    Opaque = 0xFF,
}

impl From<u8> for TypeTag {
    fn from(v: u8) -> Self {
        match v {
            0x00 => TypeTag::Felt,
            0x01 => TypeTag::ShortString,
            0x02 => TypeTag::Address,
            0x03 => TypeTag::U128,
            0x04 => TypeTag::U256,
            0x05 => TypeTag::Bool,
            0x06 => TypeTag::Timestamp,
            0x07 => TypeTag::TokenAmount,
            _ => TypeTag::Opaque,
        }
    }
}

/// A field prepared for display on the Ledger screen.
#[derive(Debug, Clone)]
pub struct DisplayField {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub value: [u8; MAX_VALUE_LEN],
    pub value_len: usize,
}

impl Default for DisplayField {
    fn default() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            value: [0u8; MAX_VALUE_LEN],
            value_len: 0,
        }
    }
}

impl DisplayField {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }

    pub fn value_str(&self) -> &str {
        core::str::from_utf8(&self.value[..self.value_len]).unwrap_or("?")
    }
}

/// Internal enum to hold either hasher type for struct hashing
enum StructHasher {
    Pedersen(PedersenHasher),
    Poseidon(PoseidonHasher),
}

impl StructHasher {
    fn update(&mut self, fe: FieldElement) {
        match self {
            StructHasher::Pedersen(h) => h.update(fe),
            StructHasher::Poseidon(h) => h.update(fe),
        }
    }

    fn finalize(self) -> FieldElement {
        match self {
            StructHasher::Pedersen(h) => h.finalize(),
            StructHasher::Poseidon(h) => h.finalize(),
        }
    }
}

/// SNIP-12 message state, accumulated across multiple APDUs.
// Debug omitted: contains FFI types (KeccakHasher) that don't derive Debug
pub struct Snip12Message {
    pub revision: Snip12Revision,
    pub account_address: FieldElement,

    // Type definitions
    pub num_types: u8,
    pub num_types_received: u8,
    pub type_hashes: [FieldElement; MAX_TYPES],
    pub domain_type_idx: u8,
    pub primary_type_idx: u8,

    // Keccak state for streaming type definitions
    keccak: Option<KeccakHasher>,
    current_type_idx: u8,

    // Domain struct hashing
    pub num_domain_fields: u8,
    pub num_domain_fields_received: u8,
    domain_hasher: Option<StructHasher>,
    pub domain_hash: FieldElement,

    // Message struct hashing
    pub num_message_fields: u8,
    pub num_message_fields_received: u8,
    message_hasher: Option<StructHasher>,
    pub message_hash: FieldElement,

    // Display fields
    pub display_fields: [DisplayField; MAX_DISPLAY_FIELDS],
    pub num_display_fields: usize,

    // For u256 continuation: tracks if we're building a u256
    pending_u256_low: Option<FieldElement>,
    pending_u256_field_idx: usize,
}

impl core::fmt::Debug for Snip12Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Snip12Message")
            .field("revision", &self.revision)
            .field("num_types", &self.num_types)
            .field("num_display_fields", &self.num_display_fields)
            .finish()
    }
}

impl Default for Snip12Message {
    fn default() -> Self {
        Self {
            revision: Snip12Revision::V1,
            account_address: FieldElement::default(),
            num_types: 0,
            num_types_received: 0,
            type_hashes: [FieldElement::default(); MAX_TYPES],
            domain_type_idx: 0,
            primary_type_idx: 0,
            keccak: None,
            current_type_idx: 0,
            num_domain_fields: 0,
            num_domain_fields_received: 0,
            domain_hasher: None,
            domain_hash: FieldElement::default(),
            num_message_fields: 0,
            num_message_fields_received: 0,
            message_hasher: None,
            message_hash: FieldElement::default(),
            display_fields: default_display_fields(),
            num_display_fields: 0,
            pending_u256_low: None,
            pending_u256_field_idx: 0,
        }
    }
}

fn default_display_fields() -> [DisplayField; MAX_DISPLAY_FIELDS] {
    [
        DisplayField::default(),
        DisplayField::default(),
        DisplayField::default(),
        DisplayField::default(),
        DisplayField::default(),
        DisplayField::default(),
        DisplayField::default(),
        DisplayField::default(),
    ]
}

/// Parse P1=0x01 metadata payload.
/// Layout: REVISION(1) | NUM_TYPES(1) | NUM_DOM_FE(1) | NUM_MSG_FE(1) | ACCOUNT_ADDR(32)
pub fn set_metadata(data: &[u8], msg: &mut Snip12Message) {
    msg.revision = match data[0] {
        0x00 => Snip12Revision::V0,
        _ => Snip12Revision::V1,
    };
    msg.num_types = data[1];
    msg.num_domain_fields = data[2];
    msg.num_message_fields = data[3];
    msg.account_address = FieldElement::from(&data[4..36]);
}

/// P1=0x02, P2=0x00: Start a new type definition.
/// Layout: TYPE_IDX(1) | IS_PRIMARY(1) | IS_DOMAIN(1) | STRING_CHUNK(N)
pub fn start_type_def(data: &[u8], msg: &mut Snip12Message) {
    let type_idx = data[0];
    let is_primary = data[1] != 0;
    let is_domain = data[2] != 0;

    msg.current_type_idx = type_idx;
    if is_primary {
        msg.primary_type_idx = type_idx;
    }
    if is_domain {
        msg.domain_type_idx = type_idx;
    }

    // Start streaming keccak
    let mut keccak = KeccakHasher::new();
    if data.len() > 3 {
        keccak.update(&data[3..]);
    }
    msg.keccak = Some(keccak);
}

/// P1=0x02, P2=0x01: Continue streaming encode_type string.
pub fn continue_type_def(data: &[u8], msg: &mut Snip12Message) {
    if let Some(ref mut keccak) = msg.keccak {
        keccak.update(data);
    }
}

/// P1=0x02, P2=0x02: Finalize type definition - compute starknet_keccak.
pub fn finalize_type_def(data: &[u8], msg: &mut Snip12Message) {
    if let Some(ref mut keccak) = msg.keccak {
        if !data.is_empty() {
            keccak.update(data);
        }
    }
    if let Some(keccak) = msg.keccak.take() {
        let idx = msg.current_type_idx as usize;
        if idx < MAX_TYPES {
            msg.type_hashes[idx] = keccak.finalize_starknet_keccak();
        }
        msg.num_types_received += 1;
    }
}

/// P1=0x02: Dispatch based on P2
pub fn handle_type_def(data: &[u8], p2: u8, msg: &mut Snip12Message) {
    match p2 {
        0x00 => start_type_def(data, msg),
        0x01 => continue_type_def(data, msg),
        0x02 => finalize_type_def(data, msg),
        _ => {}
    }
}

/// Initialize the domain hasher with the domain type hash.
fn init_domain_hasher(msg: &mut Snip12Message) {
    let mut hasher = match msg.revision {
        Snip12Revision::V0 => StructHasher::Pedersen(PedersenHasher::default()),
        Snip12Revision::V1 => StructHasher::Poseidon(PoseidonHasher::default()),
    };
    // First element is the domain type hash
    hasher.update(msg.type_hashes[msg.domain_type_idx as usize]);
    msg.domain_hasher = Some(hasher);
}

/// P1=0x03: Add a domain field (32-byte FieldElement).
pub fn add_domain_field(data: &[u8], msg: &mut Snip12Message) {
    if msg.domain_hasher.is_none() {
        init_domain_hasher(msg);
    }

    let fe = FieldElement::from(&data[..32]);
    if let Some(ref mut hasher) = msg.domain_hasher {
        hasher.update(fe);
    }
    msg.num_domain_fields_received += 1;

    // If all domain fields received, finalize domain hash
    if msg.num_domain_fields_received >= msg.num_domain_fields {
        if let Some(hasher) = msg.domain_hasher.take() {
            msg.domain_hash = finalize_struct_hash(hasher, msg.revision, msg.num_domain_fields);
        }
    }
}

/// Initialize the message hasher with the primary type hash.
fn init_message_hasher(msg: &mut Snip12Message) {
    let mut hasher = match msg.revision {
        Snip12Revision::V0 => StructHasher::Pedersen(PedersenHasher::default()),
        Snip12Revision::V1 => StructHasher::Poseidon(PoseidonHasher::default()),
    };
    // First element is the primary type hash
    hasher.update(msg.type_hashes[msg.primary_type_idx as usize]);
    msg.message_hasher = Some(hasher);
}

/// P1=0x04: Add a message field with display info.
/// P2=0x00 (new field): NAME_LEN(1) | NAME(N) | TYPE_TAG(1) | VALUE(32)
/// P2=0x01 (continuation for u256 high felt): VALUE(32)
pub fn add_message_field(data: &[u8], p2: u8, msg: &mut Snip12Message) {
    if msg.message_hasher.is_none() {
        init_message_hasher(msg);
    }

    match p2 {
        0x00 => {
            // New field
            let name_len = data[0] as usize;
            let name_end = 1 + name_len;
            let name_bytes = &data[1..name_end];
            let type_tag = TypeTag::from(data[name_end]);
            let value = FieldElement::from(&data[name_end + 1..name_end + 33]);

            // Hash the value into the message struct hash
            if let Some(ref mut hasher) = msg.message_hasher {
                hasher.update(value);
            }

            // Format and store display field
            if type_tag == TypeTag::U256 {
                // U256: this is the low felt, wait for high felt continuation
                msg.pending_u256_low = Some(value);
                msg.pending_u256_field_idx = msg.num_display_fields;
                // Store name for later
                if msg.num_display_fields < MAX_DISPLAY_FIELDS {
                    let df = &mut msg.display_fields[msg.num_display_fields];
                    let len = name_len.min(MAX_NAME_LEN);
                    df.name[..len].copy_from_slice(&name_bytes[..len]);
                    df.name_len = len;
                    // Value will be set on continuation
                }
            } else {
                store_display_field(msg, name_bytes, name_len, type_tag, &value);
            }

            msg.num_message_fields_received += 1;
        }
        0x01 => {
            // Continuation (u256 high felt)
            let value = FieldElement::from(&data[..32]);

            // Hash the high felt
            if let Some(ref mut hasher) = msg.message_hasher {
                hasher.update(value);
            }

            // Complete the u256 display
            if let Some(low) = msg.pending_u256_low.take() {
                format_u256_display(msg, &low, &value);
            }

            msg.num_message_fields_received += 1;
        }
        _ => {}
    }

    // Check if all message fields received
    if msg.num_message_fields_received >= msg.num_message_fields {
        if let Some(hasher) = msg.message_hasher.take() {
            msg.message_hash =
                finalize_struct_hash(hasher, msg.revision, msg.num_message_fields);
        }
    }
}

/// Finalize a struct hash.
/// For Poseidon (V1): hash_many semantics (PoseidonHasher handles padding).
/// For Pedersen (V0): append field count, then finalize.
fn finalize_struct_hash(
    mut hasher: StructHasher,
    revision: Snip12Revision,
    num_fields: u8,
) -> FieldElement {
    match revision {
        Snip12Revision::V0 => {
            // Pedersen: append count (type_hash + num_fields elements)
            hasher.update(FieldElement::from((num_fields as usize) + 1));
            hasher.finalize()
        }
        Snip12Revision::V1 => {
            // Poseidon: finalize handles padding internally
            hasher.finalize()
        }
    }
}

/// Check if the message is complete (all types, domain fields, and message fields received).
pub fn is_complete(msg: &Snip12Message) -> bool {
    msg.num_types_received >= msg.num_types
        && msg.num_domain_fields_received >= msg.num_domain_fields
        && msg.num_message_fields_received >= msg.num_message_fields
}

/// Compute the final SNIP-12 message hash.
/// hash = hash_array([PREFIX, domain_hash, account, message_hash])
///
/// For V0 (Pedersen): hash = pedersen(pedersen(pedersen(PREFIX, domain_hash), account), message_hash) with length appended
/// For V1 (Poseidon): hash = poseidon_hash_many([PREFIX, domain_hash, account, message_hash])
pub fn compute_final_hash(msg: &Snip12Message) -> FieldElement {
    // "StarkNet Message" as short string prefix
    let prefix = starknet_message_prefix();

    match msg.revision {
        Snip12Revision::V0 => {
            let mut hasher = PedersenHasher::default();
            hasher.update(prefix);
            hasher.update(msg.domain_hash);
            hasher.update(msg.account_address);
            hasher.update(msg.message_hash);
            // Pedersen: append length
            let mut result = hasher.finalize();
            // For SNIP-12 V0, the final hash is pedersen(pedersen(pedersen(pedersen(0, prefix), domain_hash), account), message_hash)
            // then we need to append the count
            // Actually PedersenHasher starts at state=0 and chains, then we need count
            // The count for the outer hash is 4 (prefix + domain_hash + account + message_hash)
            // But PedersenHasher.finalize() just returns the state without appending count
            // We need to manually do: pedersen(state, 4)
            use crate::crypto::pedersen::pedersen_hash;
            pedersen_hash(&mut result, &FieldElement::from(4usize));
            result
        }
        Snip12Revision::V1 => {
            let values = [prefix, msg.domain_hash, msg.account_address, msg.message_hash];
            PoseidonStark252::hash_many(&values)
        }
    }
}

/// The "StarkNet Message" prefix as a felt252 (short string encoding).
fn starknet_message_prefix() -> FieldElement {
    // "StarkNet Message" = 0x537461726b4e6574204d657373616765
    let mut fe = FieldElement::default();
    let bytes = b"StarkNet Message";
    let offset = 32 - bytes.len();
    fe.value[offset..].copy_from_slice(bytes);
    fe
}

/// Store a formatted display field.
fn store_display_field(
    msg: &mut Snip12Message,
    name_bytes: &[u8],
    name_len: usize,
    type_tag: TypeTag,
    value: &FieldElement,
) {
    if msg.num_display_fields >= MAX_DISPLAY_FIELDS {
        return;
    }

    let df = &mut msg.display_fields[msg.num_display_fields];

    // Copy name
    let len = name_len.min(MAX_NAME_LEN);
    df.name[..len].copy_from_slice(&name_bytes[..len]);
    df.name_len = len;

    // Format value based on type tag
    let formatted = format_value(type_tag, value);
    let vlen = formatted.len().min(MAX_VALUE_LEN);
    df.value[..vlen].copy_from_slice(&formatted.as_bytes()[..vlen]);
    df.value_len = vlen;

    msg.num_display_fields += 1;
}

/// Format a u256 (low + high felts) and store the display field.
fn format_u256_display(msg: &mut Snip12Message, low: &FieldElement, high: &FieldElement) {
    if msg.pending_u256_field_idx >= MAX_DISPLAY_FIELDS {
        return;
    }

    let formatted = format_u256(low, high);
    let df = &mut msg.display_fields[msg.pending_u256_field_idx];
    let vlen = formatted.len().min(MAX_VALUE_LEN);
    df.value[..vlen].copy_from_slice(&formatted.as_bytes()[..vlen]);
    df.value_len = vlen;

    // Only increment display field count now
    if msg.pending_u256_field_idx == msg.num_display_fields {
        msg.num_display_fields += 1;
    }
}

/// Format a field value based on its type tag.
fn format_value(tag: TypeTag, value: &FieldElement) -> String {
    match tag {
        TypeTag::Felt => format_felt(value),
        TypeTag::ShortString => format_shortstring(value),
        TypeTag::Address => format_address(value),
        TypeTag::U128 => format_u128(value),
        TypeTag::Bool => format_bool(value),
        TypeTag::Timestamp => format_u128(value), // Display as decimal
        TypeTag::TokenAmount => format_u128(value), // Display as decimal
        TypeTag::Opaque => format_felt(value),
        TypeTag::U256 => format_u128(value), // Should not happen for single felt
    }
}

/// Format a felt as "0x" + hex.
fn format_felt(value: &FieldElement) -> String {
    let mut s = String::from("0x");
    s.push_str(&value.to_hex_string());
    s
}

/// Format a short string (felt as ASCII).
fn format_shortstring(value: &FieldElement) -> String {
    // Find first non-zero byte
    let start = value.value.iter().position(|&b| b != 0).unwrap_or(32);
    let bytes = &value.value[start..];
    // Only include printable ASCII
    let mut s = String::new();
    for &b in bytes {
        if b >= 0x20 && b <= 0x7E {
            s.push(b as char);
        }
    }
    if s.is_empty() {
        String::from("")
    } else {
        s
    }
}

/// Format an address as "0x" + hex.
fn format_address(value: &FieldElement) -> String {
    let mut s = String::from("0x");
    s.push_str(&value.to_hex_string());
    s
}

/// Format a u128 as decimal string.
fn format_u128(value: &FieldElement) -> String {
    value.to_dec_string(None)
}

/// Format a u256 from low and high u128 felts as decimal.
fn format_u256(low: &FieldElement, high: &FieldElement) -> String {
    use num_bigint::BigUint;

    let low_bn = BigUint::from_bytes_be(&low.value);
    let high_bn = BigUint::from_bytes_be(&high.value);
    let shift = BigUint::from(1u8) << 128;
    let result = high_bn * shift + low_bn;
    alloc::string::ToString::to_string(&result)
}

/// Format a bool value.
fn format_bool(value: &FieldElement) -> String {
    if value.value[31] == 0 && value.value.iter().all(|&b| b == 0) {
        String::from("false")
    } else {
        String::from("true")
    }
}
