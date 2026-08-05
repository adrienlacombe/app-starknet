# Ledger Starknet App
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

-------------------

Official Starknet application

-------------------

<img src="docs/LedgerXStarknetXRust.png"/>


This project contains the Starknet app (https://starkware.co/) for Ledger devices.

## Experimental ML-DSA-44 signer

The app exposes an experimental Pure ML-DSA-44 signer for interoperability with the
OpenZeppelin Cairo verifier. It derives a recoverable, path-specific key from the Ledger seed,
reviews the canonical Starknet hash on-device, and streams the standard 1,312-byte public key
and 2,420-byte signature over versioned APDUs. See the [APDU specification](docs/apdu.md) for
the byte order and transfer format.

This is test-contract support, not production Starknet account authorization. The current
Cairo ML-DSA-44 verifier costs roughly 803.5M L2 gas and 5.99M Cairo steps, above Starknet's
account-validation limits. Seeded key generation also uses the Ledger C SDK's internal
`MLDSA_internal_keygen` symbol until the Rust SDK provides a public equivalent. Do not place
funds at risk with this experimental path.

For more information:

- [How to build](docs/build.md)
- [How to test](docs/test.md)
- [APDU specification](docs/apdu.md)
