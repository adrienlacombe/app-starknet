#!/usr/bin/env python3
"""
Generate SNIP-12 APDU .dat files for testing the SignTypedData (INS=0x08) flow.

Protocol:
  P1=0x00: Derivation path (24 bytes)
  P1=0x01: Metadata: REVISION(1) | NUM_TYPES(1) | NUM_DOM_FE(1) | NUM_MSG_FE(1) | ACCOUNT_ADDR(32)
  P1=0x02: Type definitions (streamed via P2=0x00/0x01/0x02)
  P1=0x03: Domain fields (each 32 bytes)
  P1=0x04: Message fields (P2=0x00 new field, P2=0x01 u256 continuation)
"""

import os

CLA = 0x5A
INS_SIGN_TYPED_DATA = 0x08

# Derivation path: m/2645'/1195502025'/1148870696'/0'/0'/0
DPATH = bytes.fromhex("80000a55c741e9c9c47a6028800000008000000000000000")


def build_apdu(ins, p1, p2, data):
    """Build a raw APDU hex string."""
    payload = bytes(data) if not isinstance(data, bytes) else data
    header = bytes([CLA, ins, p1, p2, len(payload)])
    return (header + payload).hex()


def felt_from_int(v):
    """Encode an integer as a 32-byte big-endian felt."""
    return v.to_bytes(32, "big")


def felt_from_shortstring(s):
    """Encode a short string (<=31 chars) as a felt (right-aligned in 32 bytes)."""
    b = s.encode("ascii")
    assert len(b) <= 31, f"Short string too long: {s}"
    return b"\x00" * (32 - len(b)) + b


def write_dat(filename, lines):
    """Write APDU lines to a .dat file."""
    with open(filename, "w") as f:
        for line in lines:
            f.write(f"=> {line}\n")
    print(f"  Written: {filename} ({len(lines)} APDUs)")


def generate_clear_sign_transfer():
    """
    Generate a SNIP-12 clear-sign test: a simple "Transfer" message.

    Domain: StarknetDomain(name, version, chainId)
      - name = "MyDapp"
      - version = "1"
      - chainId = "SN_MAIN"

    Message: Transfer(amount, recipient)
      - amount = 1000 (u128)
      - recipient = 0x049d36...0001 (address)

    Revision: V1 (Poseidon)
    """
    apdus = []

    # P1=0x00: Derivation path
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x00, 0x00, DPATH))

    # P1=0x01: Metadata
    revision = 0x01  # V1 = Poseidon
    num_types = 0x02  # domain type + primary type
    num_dom_fe = 0x03  # 3 domain fields
    num_msg_fe = 0x02  # 2 message fields
    account_addr = felt_from_int(0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7)
    metadata = bytes([revision, num_types, num_dom_fe, num_msg_fe]) + account_addr
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x01, 0x00, metadata))

    # P1=0x02: Type definitions
    # Type 0: Domain type "StarknetDomain(name:shortstring,version:shortstring,chainId:shortstring)"
    encode_type_0 = b"StarknetDomain(name:shortstring,version:shortstring,chainId:shortstring)"
    # P2=0x00 (new type): TYPE_IDX(1) | IS_PRIMARY(1) | IS_DOMAIN(1) | STRING_CHUNK(N)
    type_def_0 = bytes([0x00, 0x00, 0x01]) + encode_type_0  # idx=0, not primary, is domain
    # Since encode_type fits in one APDU, use P2=0x02 (finalize) directly
    # But protocol says P2=0x00 starts, P2=0x02 finalizes. Let's use start+finalize.
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x00, type_def_0))
    # Finalize with empty data
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x02, b""))

    # Type 1: Primary type "Transfer(amount:u128,recipient:ContractAddress)"
    encode_type_1 = b"Transfer(amount:u128,recipient:ContractAddress)"
    type_def_1 = bytes([0x01, 0x01, 0x00]) + encode_type_1  # idx=1, is primary, not domain
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x00, type_def_1))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x02, b""))

    # P1=0x03: Domain fields (3 fields, each 32 bytes)
    domain_name = felt_from_shortstring("MyDapp")
    domain_version = felt_from_shortstring("1")
    domain_chain_id = felt_from_shortstring("SN_MAIN")
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, domain_name))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, domain_version))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, domain_chain_id))

    # P1=0x04: Message fields
    # Field 1: "amount" (u128) = 1000
    name_amount = b"amount"
    type_tag_u128 = 0x03
    value_amount = felt_from_int(1000)
    field1_data = bytes([len(name_amount)]) + name_amount + bytes([type_tag_u128]) + value_amount
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x04, 0x00, field1_data))

    # Field 2: "recipient" (address) = 0x049D36...
    name_recipient = b"recipient"
    type_tag_addr = 0x02
    value_recipient = felt_from_int(0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7)
    field2_data = bytes([len(name_recipient)]) + name_recipient + bytes([type_tag_addr]) + value_recipient
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x04, 0x00, field2_data))

    return apdus


def generate_clear_sign_order():
    """
    Generate a SNIP-12 clear-sign test: an "Order" message with more fields.

    Domain: StarknetDomain(name, version, chainId)
      - name = "Exchange"
      - version = "1"
      - chainId = "SN_MAIN"

    Message: Order(maker, price, qty, side)
      - maker = 0x049d36... (address)
      - price = 42000 (u128)
      - qty = 5 (u128)
      - side = "buy" (shortstring)

    Revision: V1 (Poseidon)
    """
    apdus = []

    # P1=0x00: Derivation path
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x00, 0x00, DPATH))

    # P1=0x01: Metadata
    revision = 0x01
    num_types = 0x02
    num_dom_fe = 0x03
    num_msg_fe = 0x04  # 4 message fields
    account_addr = felt_from_int(0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7)
    metadata = bytes([revision, num_types, num_dom_fe, num_msg_fe]) + account_addr
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x01, 0x00, metadata))

    # Type 0: Domain
    encode_type_0 = b"StarknetDomain(name:shortstring,version:shortstring,chainId:shortstring)"
    type_def_0 = bytes([0x00, 0x00, 0x01]) + encode_type_0
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x00, type_def_0))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x02, b""))

    # Type 1: Primary
    encode_type_1 = b"Order(maker:ContractAddress,price:u128,qty:u128,side:shortstring)"
    type_def_1 = bytes([0x01, 0x01, 0x00]) + encode_type_1
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x00, type_def_1))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x02, b""))

    # Domain fields
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, felt_from_shortstring("Exchange")))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, felt_from_shortstring("1")))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, felt_from_shortstring("SN_MAIN")))

    # Message fields
    # maker (address)
    name = b"maker"
    val = felt_from_int(0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7)
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x04, 0x00,
                            bytes([len(name)]) + name + bytes([0x02]) + val))

    # price (u128)
    name = b"price"
    val = felt_from_int(42000)
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x04, 0x00,
                            bytes([len(name)]) + name + bytes([0x03]) + val))

    # qty (u128)
    name = b"qty"
    val = felt_from_int(5)
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x04, 0x00,
                            bytes([len(name)]) + name + bytes([0x03]) + val))

    # side (shortstring)
    name = b"side"
    val = felt_from_shortstring("buy")
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x04, 0x00,
                            bytes([len(name)]) + name + bytes([0x01]) + val))

    return apdus


def generate_complex_message():
    """
    Generate a SNIP-12 message with 9 fields (exceeds MAX_DISPLAY_FIELDS=8)
    to trigger blind signing fallback.

    Domain: StarknetDomain(name, version, chainId)
      - name = "ComplexDapp"
      - version = "1"
      - chainId = "SN_MAIN"

    Message: ComplexOrder(maker, taker, price, qty, side, nonce, expiry, fee, salt)
      - 9 fields -> exceeds display limit -> blind signing

    Revision: V1 (Poseidon)
    """
    apdus = []

    # P1=0x00: Derivation path
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x00, 0x00, DPATH))

    # P1=0x01: Metadata
    revision = 0x01
    num_types = 0x02
    num_dom_fe = 0x03
    num_msg_fe = 0x09  # 9 message fields -> exceeds MAX_DISPLAY_FIELDS (8)
    account_addr = felt_from_int(0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7)
    metadata = bytes([revision, num_types, num_dom_fe, num_msg_fe]) + account_addr
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x01, 0x00, metadata))

    # Type 0: Domain
    encode_type_0 = b"StarknetDomain(name:shortstring,version:shortstring,chainId:shortstring)"
    type_def_0 = bytes([0x00, 0x00, 0x01]) + encode_type_0
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x00, type_def_0))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x02, b""))

    # Type 1: Primary
    encode_type_1 = b"ComplexOrder(maker:ContractAddress,taker:ContractAddress,price:u128,qty:u128,side:shortstring,nonce:u128,expiry:u128,fee:u128,salt:felt)"
    type_def_1 = bytes([0x01, 0x01, 0x00]) + encode_type_1
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x00, type_def_1))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x02, 0x02, b""))

    # Domain fields
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, felt_from_shortstring("ComplexDapp")))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, felt_from_shortstring("1")))
    apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x03, 0x00, felt_from_shortstring("SN_MAIN")))

    # Message fields (9 total)
    fields = [
        (b"maker",  0x02, felt_from_int(0x049D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7)),
        (b"taker",  0x02, felt_from_int(0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF)),
        (b"price",  0x03, felt_from_int(42000)),
        (b"qty",    0x03, felt_from_int(5)),
        (b"side",   0x01, felt_from_shortstring("buy")),
        (b"nonce",  0x03, felt_from_int(1)),
        (b"expiry", 0x03, felt_from_int(1700000000)),
        (b"fee",    0x03, felt_from_int(100)),
        (b"salt",   0x00, felt_from_int(0xDEADBEEF)),
    ]

    for name, type_tag, val in fields:
        apdus.append(build_apdu(INS_SIGN_TYPED_DATA, 0x04, 0x00,
                                bytes([len(name)]) + name + bytes([type_tag]) + val))

    return apdus


if __name__ == "__main__":
    outdir = os.path.join(os.path.dirname(__file__), "apdu")

    print("Generating SNIP-12 APDU data files...")

    # Test case 1: Simple transfer (clear sign, 2 message fields)
    apdus = generate_clear_sign_transfer()
    write_dat(os.path.join(outdir, "snip12_transfer.dat"), apdus)

    # Test case 2: Order with more fields (clear sign, 4 message fields)
    apdus = generate_clear_sign_order()
    write_dat(os.path.join(outdir, "snip12_order.dat"), apdus)

    # Test case 3: Complex message (9 fields, triggers blind signing fallback)
    apdus = generate_complex_message()
    write_dat(os.path.join(outdir, "snip12_complex.dat"), apdus)

    print("Done.")
