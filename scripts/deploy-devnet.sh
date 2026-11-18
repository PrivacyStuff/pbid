#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo-build-sbf --no-default-features --features bpf-entrypoint
mkdir -p keys
if [ ! -f keys/pbid-keypair.json ]; then
  solana-keygen new --no-bip39-passphrase --silent -o keys/pbid-keypair.json
fi
solana program deploy target/deploy/pbid.so --program-id keys/pbid-keypair.json
solana-keygen pubkey keys/pbid-keypair.json
