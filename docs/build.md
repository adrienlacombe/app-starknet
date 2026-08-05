Use [ledger_app_builder](https://github.com/LedgerHQ/ledger-app-builder) Docker container

Prerequisite:
```
# Pull Docker image container
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools
# Checkout LedgerHQ Starknet app repository
git clone https://github.com/LedgerHQ/app-starknet.git
```

Build for Nano S+/X/Stax/Flex:
```
docker run --rm -it -v "$(pwd -P):/apps" --publish 5001:5001 --publish 9999:9999 -e DISPLAY='host.docker.internal:0' -v '/tmp/.X11-unix:/tmp/.X11-unix' --privileged ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools
cd /apps/app-starknet/starknet
cargo clean
cargo ledger build nanosplus|nanox|stax|flex
```

The experimental ML-DSA signer is verified against C SDK v26.5.0 at commit
`db03d3e8e65825d2cfba4e68064a7b120eace416` (API level 26). Its seeded key generation
currently uses an internal C SDK symbol, so other C SDK releases are not supported until
Ledger exposes a public seeded-keygen API. The app enables the Rust SDK's optimized low-RAM
ML-DSA implementation, and the Cargo configuration reserves extra stack on Nano X by setting
its heap to 2 KiB; this follows the SDK guidance for the device's 28 KiB SRAM.
