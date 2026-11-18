# Helius Privacy Rings (from GhostMessage write-up)

Source: https://github.com/narsixyz/ghost-message
Tested against **devnet** and `@heliuslabs/spr` **0.9.0-alpha**. Instruction tags and SDK behavior must not be assumed to match current mainnet. Experimental, unaudited.

## Model

Private balances are notes (UTXOs), not accounts. A note has owner, asset, amount, and blinding. The on-chain state is the note hash in a Merkle tree. Notes do not pay rent. A balance is the sum of notes the client can decrypt. A spend consumes whole notes and creates new notes (recipient plus change).

A nullifier is derived from the note and the owner's nullifier key and is published on spend. The Solana Privacy Program rejects a reused nullifier. That stops double-spend without revealing which note was spent.

Three keys:

- Signing authority: Ed25519 keypair, or a PDA promoted with `invoke_signed`. The nullifier key alone does not authorize a spend.
- Nullifier key: derive nullifiers and the spend proof.
- Viewing key: X25519. Encryption keys for notes come from it. Sharing it gives read-only visibility.

A shielded address is the Solana pubkey plus the public halves of the nullifier and viewing keys. A private payment needs that address, not only the wallet address.

Every `transact` carries a Groth16 proof: notes exist in the tree, belong to the owner, are unspent, and inputs balance outputs. The Helius prover builds the proof. The Privacy Program verifies it. One devnet claim used 139,226 CU. That is one measurement, not a constant.

## What the Default Ring hides

Confidentiality of asset and amount. Not anonymity.

- Sender is visible because they sign.
- On spr 0.9.0-alpha the Default Ring view tag is the recipient's 32-byte Solana pubkey, copied as-is. It identifies the wallet. It does not include nullifier or viewing keys, so it cannot decrypt the note.
- A deposit from a public balance shows source, asset, and amount.

Hiding the parties needs Anonymous Custom Rings, a separate capability.

## Two integrations

Client-level: the wallet owns the notes. The app talks to the Privacy Program through the SDK. The app program does not move the funds.

Program-level CPI: a PDA owns the note. The program decides who may spend it and when, then CPIs `transact` and signs with `invoke_signed`. A custom circuit is required only when the program must constrain the private outputs (split, third-party share, output rules). Signer checks plus `Clock` are enough for "who" and "when". The program cannot see the private outputs, so it cannot enforce them.

Helius's timelock example binds outputs with its own Groth16 circuit, then CPIs `transact`. It is not production-ready: insecure test keys, Zolana crates on Pinocchio 0.11 plus an allocator.

The Privacy Program accepts an owner that is either an Ed25519 signer or a PDA signing through `invoke_signed`. A note can be owned by a PDA. Only the owning program can spend it.

## GhostMessage held payment

Seeds: `["payment", payer, recipient, deadline]` plus canonical bump. `create_program_address` with the client-supplied bump. A wrong bump is a different PDA and does not own the funded note. The deadline is in the seeds, so an earlier deadline cannot unlock the same note.

1. Lock: payer creates a private transfer to the payment PDA's shielded address. View tag is the PDA, not the recipient. Neither party can spend it with a wallet signature.
2. Claim: recipient signs. Program derives the PDA and CPIs `transact` with `invoke_signed`. New note is for the recipient. No deadline on claim.
3. Refund: payer signs, and `Clock` must be past the deadline.

After the deadline both claim and refund are valid. First landing spend wins. The second republishes the nullifier and is rejected. If the recipient must not lose the payment, they claim before the deadline.

PDA key material: both parties derive the same viewing and nullifier keys with ECDH from their own viewing keys and the PDA address. Spend uses `LocalKeys.fromKeys` (PDA address plus those keys), not a keypair signer. The client wraps the SPP instruction in Claim or Refund and passes the PDA as a non-signer. The program promotes it during the CPI.

Devnet program id used in that write-up: `ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW`. Spec revision ca4cf4f documented transact tag 12. Deployed devnet and the SDK used tag 16. Match the deployed program.

CPI checks that mattered: target program id is the Privacy Program (account index 2 in their layout: payer, output tree, SPP, system), the payment PDA is in the forwarded accounts, account count and instruction data fit fixed buffers (24 accounts, 1,232 bytes after the one-byte tag). Rebuild metas, keep writable and signer flags, set signer on the PDA, prepend the transact tag, `invoke_signed`. Proof, nullifier, and note ownership are the Privacy Program's job.

Pinocchio 0.12, no allocator, stack buffers, `invoke_signed_with_bounds`.

What stayed public on a held payment:

- Amount and asset stay hidden.
- Lock: payer is the signer. Recipient is not in the lock. View tag is the PDA. An observer can only confirm a guessed recipient by re-deriving the PDA.
- Claim: recipient signs, and the payer pubkey is in the instruction data because the program needs it to derive the PDA. Both parties are then public.
- Public deposits stay visible.

Holding the payment changes when the parties show up. It does not make them anonymous.

## Why this matters for pbid

A clear amount, or lamports, on a bid PDA publishes the price. A Privacy Ring note owned by a PDA does not store the amount in the account. Other bidders see a commitment and a view tag, not the number.

Default Ring still identifies parties: the signer, and a view tag that is a wallet pubkey unless the output is owned by a PDA. A later claim that puts the counterparty in instruction data links them. Pool totals and public shield/unshield amounts stay visible. Anonymous Custom Rings are the path if the parties themselves must stay hidden.
