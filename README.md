# pbid

Shielded bids on a public NFT. This repository is separate from pescrow. The bidding program is not a pescrow instruction.

```
pbid/
├── README.md
├── Cargo.toml                Pinocchio program
├── src/                      standard byte, classifiers, BPF entrypoint
├── tests/listing.rs          host tests for dispatch and refusals
├── examples/listing.md       account order for the list instruction
├── scripts/deploy-devnet.sh
└── keys/                     program keypair, gitignored
```

The devnet program id is `tkGNtSKLidw6evDw86n2VUieoJYmExXDXa4RgLdhjJq`. The desk that lists against this program lives in PrivacyStuff/website.

The reserve stays in the browser. Bid amounts are shown only to the seller. Listing locks the NFT with a standard-specific CPI, then marks the listing open.

## NFT standards

The program stores one standard byte and dispatches a different CPI. These are not interchangeable accounts. Core collection plugins are a constraint on Core, not a sixth standard.

1. **Metaplex Core** (`CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d`). One asset account. Transfer uses `TransferV1` (discriminator 14). Freeze, TransferDelegate, and royalty plugins refuse the listing before it is marked open.
2. **Legacy SPL + Metaplex Token Metadata** (`metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s`). Mint supply 1, decimals 0, token amount 1, token standard `NonFungible`. The lock is an SPL transfer of 1 into a PDA associated token account.
3. **Programmable NFT**. Same metadata program, token standard `ProgrammableNonFungible`. Rejected at listing. A raw SPL transfer is not used.
4. **Token-2022 NFT** (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`). `TransferChecked` of 1. A transfer hook or a permanent delegate refuses the listing.
5. **Compressed NFTs / Bubblegum** (`BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY`). Rejected at listing. A token account is not treated as the leaf.
