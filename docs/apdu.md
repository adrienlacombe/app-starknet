# APDU protocol description

This document aims to provide a description of the APDU protocol supported by the app, explaining what each instruction does, the expected parameters and return values

## General Structure

The general structure of a request and response is as followed:

### Request / Command

| Field   | Type     | Content                | Note                   |
|:--------|:---------|:-----------------------|------------------------|
| CLA     | byte (1) | Application Identifier | 0x5A                   |
| INS     | byte (1) | Instruction ID         |                        |
| P1      | byte (1) | Parameter 1            |                        |
| P2      | byte (1) | Parameter 2            |                        |
| L       | byte (1) | Bytes in payload       |                        |
| PAYLOAD | byte (L) | Payload                |                        |

### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (N) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code | Description             |
| ----------- | ----------------------- |
| 0x9000      | Success                 |
| 0x68xx      | Syscall Error           |
| 0x6982      | Empty buffer            |
| 0x6a80      | Malformed data          |
| 0x6e00      | Bad Cla                 |
| 0x6e01      | Bad Ins                 |
| 0x6e02      | Bad P1/P2               |
| 0x6e03      | Bad Len                 |
| 0x6985      | User Cancelled          |
| 0xb007      | Bad transfer state      |
| 0xb008      | Signature failure       |
| 0xe000      | Panic                   |


## Commands definitions

### GetVersion

This command will return the app version

#### Command

| Field | Type     | Content                | Expected |
|-------|----------|------------------------|----------|
| CLA   | byte (1) | Application Identifier | 0x5A     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field     | Type     | Content          | Note                            |
| --------- | -------- | ---------------- | ------------------------------- |
| MAJOR     | byte (1) | Version Major    |                                 |
| MINOR     | byte (1) | Version Minor    |                                 |
| PATCH     | byte (1) | Version Patch    |                                 |
| SW1-SW2   | byte (2) | Return code      | see list of return codes        |

### GetPubKey

This command returns the public key corresponding to the private key found at the given [EIP-2645](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2645.md) path 

#### Command

| Field   | Type     | Content                   | Expected        |
|---------|----------|---------------------------|-----------------|
| CLA     | byte (1) | Application Identifier    | 0x5A            |
| INS     | byte (1) | Instruction ID            | 0x01            |
| P1      | byte (1) | Parameter 1               | if not 0, user will have to confirm          |
| P2      | byte (1) | Parameter 2               | ignored         |
| L       | byte (1) | Bytes in payload          | 0x18            |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000A55      |
| Path[1] | byte (4) | Derivation Path Data      |                 |
| Path[2] | byte (4) | Derivation Path Data      |                 |
| Path[3] | byte (4) | Derivation Path Data      |                 |
| Path[4] | byte (4) | Derivation Path Data      |                 |
| Path[5] | byte (4) | Derivation Path Data      |                 |

#### Response

| Field      | Type      | Content           | Note                     |
| ---------- | --------- | ----------------- | ------------------------ |
| PK_LEN     | byte (1)  | Bytes in PKEY     | 64                       |
| PKEY       | byte (64) | Public key bytes  | 32 (x) + 32 (y)          |
| SW1-SW2    | byte (2)  | Return code       | see list of return codes |

### Sign Hash

This command will return the signature of a Pedersen or Poseidon hash

#### Command #0: Set private key

| Field | Type     | Content                     | Expected          |
|-------|----------|-----------------------------|-------------------|
| CLA   | byte (1) | Application Identifier      | 0x5A              |
| INS   | byte (1) | Instruction ID              | 0x02              |
| P1    | byte (1) | Payload desc                | 0x00              |
| P2    | byte (1) | ignored                     |                   |
| L     | byte (1) | Bytes in payload            | (depends)         |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000A55        |
| Path[1] | byte (4) | Derivation Path Data      |                   |
| Path[2] | byte (4) | Derivation Path Data      |                   |
| Path[3] | byte (4) | Derivation Path Data      |                   |
| Path[4] | byte (4) | Derivation Path Data      |                   |
| Path[5] | byte (4) | Derivation Path Data      |                   |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #1: Send Hash

| Field | Type       | Content                     | Expected          |
|-------|------------|-----------------------------|-------------------|
| CLA   | byte (1)   | Application Identifier      | 0x5A              |
| INS   | byte (1)   | Instruction ID              | 0x02              |
| P1    | byte (1)   | Payload desc                | 0x01              |
| P2    | byte (1)   | ignored                     |                   |
| L     | byte (1)   | nb of bytes in payload      | 0x20              |
| Hash  | bytes (32) | hash                        |                   |

#### Response

| Field    | Type      | Content           | Note                                  |
|----------|-----------|-------------------|---------------------------------------|
| L        | byte (1)  | Sig Length        | 0x41 = 65                             |
| R        | byte (32) | Signature         | (R,S,V) encoded signature             |
| S        | byte (32) | Signature         | (R,S,V) encoded signature             |
| V        | byte (1)  | Signature         | (R,S,V) encoded signature             |
| SW1-SW2  | byte (2)  | Return code       | see list of return codes              |

### ML-DSA-44 signer (experimental)

These commands produce standard Pure ML-DSA-44 keys and signatures with an empty FIPS 204
context. The incoming Starknet hash is a canonical 32-byte big-endian felt, matching the
existing app display convention. The signer reverses it and signs the felt's exact 32-byte
little-endian representation expected by the Cairo verifier. It does not apply the Stark ECDSA
`poseidon_shift` transformation.

The key is path-specific and recovery-phrase-derived. Its 32-byte key-generation seed is:

```text
SHA-256("Starknet ML-DSA-44 seed v1" || secp256k1_BIP32_child_secret(path))
```

The accepted path is the same six-component EIP-2645 path used by the Stark signer. Seeded
key generation currently calls the C SDK v26.5.0 internal `MLDSA_internal_keygen` symbol
because `ledger_device_sdk` 1.36.1 exposes only randomized key generation. This unsupported
interface is pinned for this prototype and must be replaced by a public seeded-keygen API
before production use.

#### Transfer response

Public keys and signatures exceed the APDU response buffer, so every start/read response uses
the following frame. Integer fields are big-endian.

| Field | Type | Value |
|-------|------|-------|
| VERSION | byte (1) | `0x01` |
| ALGORITHM | byte (1) | `0x01` (ML-DSA-44) |
| KIND | byte (1) | `0x01` public key, `0x02` signature |
| SESSION | byte (4) | transfer session identifier |
| TOTAL_LEN | byte (2) | `1312` or `2420` |
| OFFSET | byte (2) | byte offset of this chunk |
| CHUNK_LEN | byte (1) | at most `240` |
| CHUNK | byte (CHUNK_LEN) | consecutive raw FIPS 204 bytes |

The first frame has offset zero. Further chunks are read at 240-byte-aligned offsets with the
same session identifier. Starting any new signing/key operation invalidates the old session.

#### Get ML-DSA-44 public key

| Field | Type | Expected |
|-------|------|----------|
| CLA | byte (1) | `0x5A` |
| INS | byte (1) | `0x09` |
| P1 | byte (1) | `0x00` silent, `0x01` confirm fingerprint |
| P2 | byte (1) | `0x00` |
| L | byte (1) | `0x18` |
| Path | byte (24) | six big-endian EIP-2645 components |

The device derives the 1,312-byte raw public key and returns its first transfer frame. With
confirmation enabled, it displays `SHA-256(public_key)` as an uppercase fingerprint.

#### Sign hash with ML-DSA-44

Initialize the signer path:

| Field | Type | Expected |
|-------|------|----------|
| CLA | byte (1) | `0x5A` |
| INS | byte (1) | `0x0A` |
| P1 | byte (1) | `0x00` |
| P2 | byte (1) | `0x00` |
| L | byte (1) | `0x18` |
| Path | byte (24) | six big-endian EIP-2645 components |

Then review and sign the hash:

| Field | Type | Expected |
|-------|------|----------|
| CLA | byte (1) | `0x5A` |
| INS | byte (1) | `0x0A` |
| P1 | byte (1) | `0x01` |
| P2 | byte (1) | `0x00` |
| L | byte (1) | `0x20` |
| HASH | byte (32) | canonical big-endian Starknet felt |

Blind signing must be enabled. After approval, the device returns the first frame of the raw
2,420-byte signature. ML-DSA signing is randomized, so repeated valid signatures may differ.

#### Read ML-DSA transfer

| Field | Type | Expected |
|-------|------|----------|
| CLA | byte (1) | `0x5A` |
| INS | byte (1) | `0x0B` |
| P1:P2 | byte (2) | 240-byte-aligned transfer offset |
| L | byte (1) | `0x04` |
| SESSION | byte (4) | session from the first frame |

The raw public key packs into 43 Cairo felts and the raw signature into 79 by interpreting each
consecutive 31-byte chunk as a little-endian integer. The last chunks contain 10 and 2 bytes,
respectively.


### Sign INVOKE Tx v3 (see [Starnet Tx v3](https://docs.starknet.io/architecture-and-concepts/network-architecture/transactions/#v3_hash_calculation))

This command will return the hash and signature of a Starknet INVOKE Tx version 3

#### Command #0: Set private key

| Field | Type     | Content                     | Expected          |
|-------|----------|-----------------------------|-------------------|
| CLA   | byte (1) | Application Identifier      | 0x5A              |
| INS   | byte (1) | Instruction ID              | 0x03              |
| P1    | byte (1) | Payload desc                | 0x00              |
| P2    | byte (1) | ignored                     |                   |
| L     | byte (1) | Bytes in payload            | (depends)         |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000A55        |
| Path[1] | byte (4) | Derivation Path Data      |                   |
| Path[2] | byte (4) | Derivation Path Data      |                   |
| Path[3] | byte (4) | Derivation Path Data      |                   |
| Path[4] | byte (4) | Derivation Path Data      |                   |
| Path[5] | byte (4) | Derivation Path Data      |                   |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #1: Send INVOKE Tx fields

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x03              |
| P1               | byte (1) | Payload desc                | 0x01              |
| P2               | byte (1) | ignored                     |                   |
| L                | byte (1) | Bytes in payload            | 0x80 (4x32 = 128) |
| SENDER ADDR      | byte (32)| sender address              | (depends)         |
| CHAIN_ID         | byte (32)| chain_id                    | (depends)         |
| NONCE            | byte (32)| nonce                       | (depends)         |
| DA MODE          | byte (32)| data_availability_mode      | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #2: Fees

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x03              |
| P1               | byte (1) | Payload desc                | 0x02              |
| P2               | byte (1) | ignored                     | 0x00              |
| L                | byte (1) | Bytes in payload            | 0x80              |
| TIP              | byte (32)| tip                         | (depends)         |
| L1 FEE           | byte (32)| l1_gas_bounds               | (depends)         |
| L2 FEE           | byte (32)| l2_gas_bounds               | (depends)         |
| L1 DATA          | byte (32)| l1_data_gas_bounds          | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #3: Send Paymaster data

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x03              |
| P1               | byte (1) | Payload desc                | 0x03              |
| P2               | byte (1) | ignored                     | 0x00              |
| L                | byte (1) | Bytes in payload            | 0x00              |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #4: Send Account Deployment data

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x03              |
| P1               | byte (1) | Payload desc                | 0x04              |
| P2               | byte (1) | ignored                     | 0x00              |
| L                | byte (1) | Bytes in payload            | 0x00              |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #4: Number of Calls

| Field            | Type       | Content                     | Expected          |
|------------------|------------|-----------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier      | 0x5A              |
| INS              | byte (1)   | Instruction ID              | 0x03              |
| P1               | byte (1)   | Payload desc                | 0x05              |
| P2               | byte (1)   | ignored                     | 0x00              |
| L                | byte (1)   | Bytes in payload            | 0x20              |
| Num of calls     | bytes (32) | Bytes in payload            | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #5: Call

##### New Call

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x03              |
| P1               | byte (1)   | Payload desc                                   | 0x05              |
| P2               | byte (1)   | New call                                       | 0x00              |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| TO               | bytes (32) | to                                             | (depends)         |
| SELECTOR         | bytes (32) | selector                                       | (depends)         |
| NB CALLDATA      | bytes (32) | nb_calldata                                    | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |

#### Response 

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

##### Add calldata to the current Call

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x03              |
| P1               | byte (1)   | Payload desc                                   | 0x05              |
| P2               | byte (1)   | Add calldata                                   | 0x01              |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |
| calldata         | bytes (32) | calldata #4                                    | (depends)         |
| calldata         | bytes (32) | calldata #5                                    | (depends)         |
| calldata         | bytes (32) | calldata #6                                    | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

##### End of calldata for the current Call

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x03              |
| P1               | byte (1)   | Payload desc                                   | 0x05              |
| P2               | byte (1)   | Last calldata                                  | 0x02              |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |
| calldata         | bytes (32) | calldata #4                                    | (depends)         |
| calldata         | bytes (32) | calldata #5                                    | (depends)         |
| calldata         | bytes (32) | calldata #6                                    | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |


#### Response (when Tx is complete)

| Field    | Type      | Content           | Note                                  |
|----------|-----------|-------------------|---------------------------------------|
| Tx Hash  | byte (32) | Tx Poseidon Hash  | 32 bytes                              |
| L        | byte (1)  | Sig Length        | 0x41 = 65                             |
| R        | byte (32) | Signature         | (R,S,V) encoded signature             |
| S        | byte (32) | Signature         | (R,S,V) encoded signature             |
| V        | byte (1)  | Signature         | (R,S,V) encoded signature             |
| SW1-SW2  | byte (2)  | Return code       | see list of return codes              |

### Sign Deploy Account Tx v3 (see [Starnet Deploy v3](https://docs.starknet.io/architecture-and-concepts/network-architecture/transactions/#v3_hash_calculation_3))

This command will return the hash and signature of a Starknet DEPLOY_ACCOUNT Tx version 3

#### Command #0: Set private key

| Field | Type     | Content                     | Expected          |
|-------|----------|-----------------------------|-------------------|
| CLA   | byte (1) | Application Identifier      | 0x5A              |
| INS   | byte (1) | Instruction ID              | 0x05              |
| P1    | byte (1) | Payload desc                | 0x00              |
| P2    | byte (1) | ignored                     |                   |
| L     | byte (1) | Bytes in payload            | (depends)         |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000A55        |
| Path[1] | byte (4) | Derivation Path Data      |                   |
| Path[2] | byte (4) | Derivation Path Data      |                   |
| Path[3] | byte (4) | Derivation Path Data      |                   |
| Path[4] | byte (4) | Derivation Path Data      |                   |
| Path[5] | byte (4) | Derivation Path Data      |                   |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #1: Send DEPLOY_ACCOUNT Tx fields


| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x05              |
| P1               | byte (1) | Payload desc                | 0x01              |
| P2               | byte (1) | ignored                     |                   |
| L                | byte (1) | Bytes in payload            | 0xC0              |
| CONTRACT ADDR    | byte (32)| contract_address            | (depends)         |
| CHAIN_ID         | byte (32)| chain_id                    | (depends)         |
| NONCE            | byte (32)| nonce                       | (depends)         |
| DA MODE          | byte (32)| data_availability_mode      | (depends)         |
| CLASS HASH       | byte (32)| class_hash                  | (depends)         |
| SALT             | byte (32)| contract_address_salt       | (depends)         |


#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #2: Fees

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x05              |
| P1               | byte (1) | Payload desc                | 0x02              |
| P2               | byte (1) | ignored                     | 0x00              |
| L                | byte (1) | Bytes in payload            |                   |
| TIP              | byte (32)| tip                         | (depends)         |
| L1 FEE           | byte (32)| l1_gas_bounds               | (depends)         |
| L2 FEE           | byte (32)| l2_gas_bounds               | (depends)         |
| L1 DATA          | byte (32)| l1_data_gas_bounds          | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #3: Send Paymaster data

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x05              |
| P1               | byte (1) | Payload desc                | 0x03              |
| P2               | byte (1) | ignored                     | 0x00              |
| L                | byte (1) | Bytes in payload            | 0x00              |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |


#### Command #4: Number of constructor calldata

| Field            | Type       | Content                     | Expected          |
|------------------|------------|-----------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier      | 0x5A              |
| INS              | byte (1)   | Instruction ID              | 0x05              |
| P1               | byte (1)   | Payload desc                | 0x04              |
| P2               | byte (1)   | ignored                     | 0x00              |
| L                | byte (1)   | Bytes in payload            | 0x20              |
| Num of calldata  | bytes (32) | Bytes in payload            | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #5: Constructor calldata

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x05              |
| P1               | byte (1)   | Payload desc                                   | 0x05              |
| P2               | byte (1)   | ignored                                        |                   |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |
| calldata         | bytes (32) | calldata #4                                    | (depends)         |
| calldata         | bytes (32) | calldata #5                                    | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Response (when Tx is complete)

| Field    | Type      | Content           | Note                                  |
|----------|-----------|-------------------|---------------------------------------|
| Tx Hash  | byte (32) | Tx Poseidon Hash  | 32 bytes                              |
| L        | byte (1)  | Sig Length        | 0x41 = 65                             |
| R        | byte (32) | Signature         | (R,S,V) encoded signature             |
| S        | byte (32) | Signature         | (R,S,V) encoded signature             |
| V        | byte (1)  | Signature         | (R,S,V) encoded signature             |
| SW1-SW2  | byte (2)  | Return code       | see list of return codes              |


### Sign INVOKE Tx v1 (see [Starnet Tx v1](https://docs.starknet.io/architecture-and-concepts/network-architecture/transactions/#v1_deprecated_hash_calculation))

This command will return the hash and signature of a Starknet INVOKE Tx version 1

#### Command #0: Set private key

| Field | Type     | Content                     | Expected          |
|-------|----------|-----------------------------|-------------------|
| CLA   | byte (1) | Application Identifier      | 0x5A              |
| INS   | byte (1) | Instruction ID              | 0x04              |
| P1    | byte (1) | Payload desc                | 0x00              |
| P2    | byte (1) | ignored                     |                   |
| L     | byte (1) | Bytes in payload            | (depends)         |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000A55        |
| Path[1] | byte (4) | Derivation Path Data      |                   |
| Path[2] | byte (4) | Derivation Path Data      |                   |
| Path[3] | byte (4) | Derivation Path Data      |                   |
| Path[4] | byte (4) | Derivation Path Data      |                   |
| Path[5] | byte (4) | Derivation Path Data      |                   |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #1: Send INVOKE Tx fields

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x04              |
| P1               | byte (1) | Payload desc                | 0x01              |
| P2               | byte (1) | ignored                     |                   |
| L                | byte (1) | Bytes in payload            | 0x80 (4x32 = 128) |
| SENDER ADDR      | byte (32)| sender address              | (depends)         |
| MAX FEE          | byte (32)| max fee                     | (depends)         |
| CHAIN_ID         | byte (32)| chain_id                    | (depends)         |
| NONCE            | byte (32)| nonce                       | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |


#### Command #2: Number of Calls

| Field            | Type       | Content                     | Expected          |
|------------------|------------|-----------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier      | 0x5A              |
| INS              | byte (1)   | Instruction ID              | 0x04              |
| P1               | byte (1)   | Payload desc                | 0x02              |
| P2               | byte (1)   | ignored                     | 0x00              |
| L                | byte (1)   | Bytes in payload            | 0x20              |
| Num of calls     | bytes (32) | Bytes in payload            | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #3: Call

##### New Call

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x04              |
| P1               | byte (1)   | Payload desc                                   | 0x03              |
| P2               | byte (1)   | New call                                       | 0x00              |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| TO               | bytes (32) | to                                             | (depends)         |
| SELECTOR         | bytes (32) | selector                                       | (depends)         |
| NB               | bytes (32) | nb_calldata                                    | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |

#### Response 

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

##### Add call data to the current Call

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x04              |
| P1               | byte (1)   | Payload desc                                   | 0x03              |
| P2               | byte (1)   | Add calldata                                   | 0x01              |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |
| calldata         | bytes (32) | calldata #4                                    | (depends)         |
| calldata         | bytes (32) | calldata #5                                    | (depends)         |
| calldata         | bytes (32) | calldata #6                                    | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

##### End of calldata for the current Call

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x04              |
| P1               | byte (1)   | Payload desc                                   | 0x03              |
| P2               | byte (1)   | End of calldata                                | 0x02              |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |
| calldata         | bytes (32) | calldata #4                                    | (depends)         |
| calldata         | bytes (32) | calldata #5                                    | (depends)         |
| calldata         | bytes (32) | calldata #6                                    | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |


#### Response (when Tx is complete)

| Field    | Type      | Content           | Note                                  |
|----------|-----------|-------------------|---------------------------------------|
| Tx Hash  | byte (32) | Tx Poseidon Hash  | 32 bytes                              |
| L        | byte (1)  | Sig Length        | 0x41 = 65                             |
| R        | byte (32) | Signature         | (R,S,V) encoded signature             |
| S        | byte (32) | Signature         | (R,S,V) encoded signature             |
| V        | byte (1)  | Signature         | (R,S,V) encoded signature             |
| SW1-SW2  | byte (2)  | Return code       | see list of return codes              |

### Sign DEPLOY_ACCOUNT Tx v1 (see [Starnet Deploy v1](https://docs.starknet.io/architecture-and-concepts/network-architecture/transactions/#v1_deprecated_hash_calculation_3))

This command will return the hash and signature of a Starknet DEPLOY_ACCOUNT Tx version 1

#### Command #0: Set private key

| Field | Type     | Content                     | Expected          |
|-------|----------|-----------------------------|-------------------|
| CLA   | byte (1) | Application Identifier      | 0x5A              |
| INS   | byte (1) | Instruction ID              | 0x06              |
| P1    | byte (1) | Payload desc                | 0x00              |
| P2    | byte (1) | ignored                     |                   |
| L     | byte (1) | Bytes in payload            | (depends)         |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000A55        |
| Path[1] | byte (4) | Derivation Path Data      |                   |
| Path[2] | byte (4) | Derivation Path Data      |                   |
| Path[3] | byte (4) | Derivation Path Data      |                   |
| Path[4] | byte (4) | Derivation Path Data      |                   |
| Path[5] | byte (4) | Derivation Path Data      |                   |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #1: Send DEPLOY_ACCOUNT Tx fields

| Field            | Type     | Content                     | Expected          |
|------------------|----------|-----------------------------|-------------------|
| CLA              | byte (1) | Application Identifier      | 0x5A              |
| INS              | byte (1) | Instruction ID              | 0x06              |
| P1               | byte (1) | Payload desc                | 0x01              |
| P2               | byte (1) | ignored                     |                   |
| L                | byte (1) | Bytes in payload            |                   |
| CONTRACT ADDR    | byte (32)| contract_address            | (depends)         |
| CLASS HASH       | byte (32)| class_hash                  | (depends)         |
| SALT             | byte (32)| contract_address_salt       | (depends)         |
| MAX FEE          | byte (32)| max_fee                     | (depends)         |
| CHAIN_ID         | byte (32)| chain_id                    | (depends)         |
| NONCE            | byte (32)| nonce                       | (depends)         |


#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #4: Number of constructor calldata

| Field            | Type       | Content                     | Expected          |
|------------------|------------|-----------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier      | 0x5A              |
| INS              | byte (1)   | Instruction ID              | 0x06              |
| P1               | byte (1)   | Payload desc                | 0x02              |
| P2               | byte (1)   | ignored                     | 0x00              |
| L                | byte (1)   | Bytes in payload            | 0x20              |
| Num of calldata  | bytes (32) | Bytes in payload            | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Command #5: Constructor calldata

| Field            | Type       | Content                                        | Expected          |
|------------------|------------|------------------------------------------------|-------------------|
| CLA              | byte (1)   | Application Identifier                         | 0x5A              |
| INS              | byte (1)   | Instruction ID                                 | 0x06              |
| P1               | byte (1)   | Payload desc                                   | 0x03              |
| P2               | byte (1)   | ignored                                        |                   |
| L                | byte (1)   | Bytes in payload                               | (depends)         |
| calldata         | bytes (32) | calldata #0                                    | (depends)         |
| calldata         | bytes (32) | calldata #1                                    | (depends)         |
| calldata         | bytes (32) | calldata #2                                    | (depends)         |
| calldata         | bytes (32) | calldata #3                                    | (depends)         |
| calldata         | bytes (32) | calldata #4                                    | (depends)         |
| calldata         | bytes (32) | calldata #5                                    | (depends)         |

#### Response

| Field    | Type      | Content     | Note                                  |
|----------|-----------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)  | Return code | see list of return codes              |

#### Response (when Tx is complete)

| Field    | Type      | Content           | Note                                  |
|----------|-----------|-------------------|---------------------------------------|
| Tx Hash  | byte (32) | Tx Poseidon Hash  | 32 bytes                              |
| L        | byte (1)  | Sig Length        | 0x41 = 65                             |
| R        | byte (32) | Signature         | (R,S,V) encoded signature             |
| S        | byte (32) | Signature         | (R,S,V) encoded signature             |
| V        | byte (1)  | Signature         | (R,S,V) encoded signature             |
| SW1-SW2  | byte (2)  | Return code       | see list of return codes              |
