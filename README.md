# pbid

Shielded bids on a public NFT. This repository is separate from pescrow. The bidding program is not a pescrow instruction.

```
pbid/
├── README.md                 program notes for the contract author
├── website/                  Next.js desk (local preview only)
├── (not written) program     Pinocchio program, owned here
├── (not written) examples
├── (not written) scripts
└── (not written) tests
```

The program, examples, scripts, and tests belong at the repo root. They are not written yet. This repository does not assign a program id.

`website/` does not submit a chain transaction. The reserve stays in the browser. Bid amounts are shown only to the seller. Accept is gated in the client. Listing an NFT here does not lock it.

## NFT standards

The future program stores one standard byte and dispatches a different CPI. These are not interchangeable accounts. Core collection plugins are a constraint on Core, not a sixth standard.

1. **Metaplex Core** (`CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d`). One asset account. Transfer uses `TransferV1` (discriminator 14). Freeze, TransferDelegate, and royalty plugins can block a plain transfer.
2. **Legacy SPL + Metaplex Token Metadata** (`metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s`). Mint supply 1, decimals 0, token amount 1. The lock is an SPL transfer of 1 into a PDA associated token account. Token standard `NonFungible`.
3. **Programmable NFT (pNFT)**. Same metadata program, token standard `ProgrammableNonFungible`. Transfer must use Token Metadata Transfer plus authorization rules and the token record. A raw SPL transfer is the wrong CPI.
4. **Token-2022 NFT** (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`). `TransferChecked` of 1. A transfer hook can reject the CPI. A permanent delegate can move the token without the owner. Fail closed on hooks until they are modeled.
5. **Compressed NFTs / Bubblegum** (`BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY`). The asset is a leaf in a merkle tree. There is no token account. Transfer needs a proof, the tree, and the tree config.
