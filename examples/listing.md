# List instruction

Discriminator `0`, then the standard byte, then the deadline as a little-endian i64, then the seller X25519 public key. Forty-two bytes. A zero key is rejected.

Accounts:

0. Listing PDA, seeds `["listing", asset]`, writable
1. Seller, signer, writable
2. System program
3. Rent sysvar
4. Clock sysvar

Core (`1`): asset (writable), Core program, collection or the Core program id when there is no collection.

Legacy (`2`) and Token-2022 (`4`): mint, source token account, destination ATA, metadata (the mint itself for Token-2022), token program, metadata program (the token program itself for Token-2022), associated-token program.

Programmable (`3`) and compressed (`5`) return before the listing is marked open.

## Legacy bid instructions

The short bid PDA is `["bid", listing, bidder]` and is 108 bytes. Tag `2`, status `1` locked or `2` accepted, then bump, pay (`1` SOL, `2` SPL), listing, bidder, mint, amount as a little-endian u64. SOL is the mint `So11111111111111111111111111111111111111112`. These instructions escrow the amount in the clear.

| Tag | Name | Data |
| --- | --- | --- |
| `1` | Place | tag, amount u64 |
| `2` | Update | tag, amount u64 |
| `3` | Cancel | tag |
| `4` | Accept | tag |

Place and update, SOL: bid, bidder (signer), listing, system, rent, clock, mint.

Place and update, SPL: those seven, then the token program, the bidder's token account, the bid escrow ATA, the associated-token program.

Cancel, SOL: bid, bidder (signer), listing, system, mint.

Cancel, SPL: those five, then the token program, the escrow ATA, the bidder's token account, the associated-token program.

Accept: listing, seller (signer), bid, bidder (the stored destination, not a signer), system, rent, clock, then the NFT accounts, then the payment accounts when the mint is not SOL. The NFT accounts are the Core asset, Core program, and collection, or the mint, source ATA, bidder ATA, token program, and associated-token program. Payment accounts are the mint, token program, escrow ATA, seller ATA, and associated-token program.

Shipped errors stay at their old numbers. New codes start at 116. Proof failures are `124`, a replayed nullifier is `125`, a bad spend mode is `126`, a bad ciphertext is `127`, and a refund of an open listing is `128`.

## Note instructions

`pbid::job::run` builds the data for every note instruction. `scripts/devnet-e2e.mjs` shows the account lists in use.

Shield (`5`, 41 bytes: tag, amount u64, inner hash). Accounts: pool, funder signer, mint, funder token account, vault ATA, token program, associated-token program, system, rent, clock. The pool PDA is `["pool", mint]`. The amount and the funding wallet are public. The note owner, blinding, and secret are not.

Place (`1`, 485 bytes: tag, nullifier, bid commitment, change commitment, 132-byte seal, 256-byte proof). Accounts: bid, bidder signer, listing, pool, nullifier, system, rent, clock. The note bid is 268 bytes, tag `3`. No tokens move. A refunded bid slot takes a new place.

Accept (`4`, 353 bytes: tag, nullifier, output commitment, change commitment, proof). Accounts follow the legacy accept order through the NFT accounts, then the pool and the nullifier. The seller signs. The bid has to be locked. The NFT moves to the stored bidder after the proof checks.

Cancel listing (`6`, one byte). Accounts: listing, seller signer, clock. Each bidder later pulls their own note.

Refund (`7`, 353 bytes, same layout as accept). Accounts: bid, bidder signer, listing, pool, nullifier, system, rent. The bid has to be locked and must not be the accepted one.

Unshield (`8`, 329 bytes: tag, nullifier, change commitment, amount u64, proof). Accounts: pool, owner signer, nullifier, mint, vault, destination ATA, token program, associated-token program, system, rent. The amount is public and leaves the vault. The rest of the note stays shielded as change. The pool PDA signs the transfer.
