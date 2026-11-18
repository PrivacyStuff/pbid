//! Note pool transitions. A shield is the only public deposit: it names the
//! amount and a hash of the note's secrets, never the secrets. Place, accept,
//! and refund append an output and a change note and leave the vault total
//! unchanged. Unshield is the public exit and keeps its change shielded. The
//! bid account stores the commitment and the seller ciphertext, never the amount.

use crate::error::BidError;
use crate::instance::{mode_ok, Instance};
use crate::merkle::{empty_root, frontier_append, FRONTIER_LEN};
use crate::poseidon::{commitment_from_inner, require_canonical, Field};
use crate::state::{
    BID_ACCEPTED, BID_LOCKED, BID_REFUNDED, KIND_BALANCE, MODE_ACCEPT, MODE_BID, MODE_REFUND,
    MODE_UNSHIELD, NOTE_BID_LEN, OFF_ACCEPTED, OFF_NOTE_BIDDER, OFF_NOTE_COMMIT, OFF_NOTE_INDEX,
    OFF_NOTE_LISTING, OFF_NOTE_MINT, OFF_NOTE_SEAL, OFF_POOL_DEPOSITED, OFF_POOL_FRONTIER, OFF_POOL_INDEX,
    OFF_POOL_MINT, OFF_POOL_ROOT, OFF_STATUS, OFF_VIEW, POOL_LEN, SEAL_LEN, STATUS_CANCELLED, STATUS_OPEN,
    STATUS_SOLD, TAG_NOTE, TAG_POOL,
};

#[cfg(feature = "bpf-entrypoint")]
use crate::chain;
#[cfg(all(feature = "host-proof", not(feature = "bpf-entrypoint")))]
use crate::circuit;

/// The two commitments a spend appends. `output` is zero for an unshield.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outputs {
    pub output: Field,
    pub change: Field,
}

/// Writes an empty pool into `pool`, which has to be zeroed and `POOL_LEN` long.
pub fn init_pool(pool: &mut [u8], bump: u8, vault_bump: u8, mint: &[u8; 32]) -> Result<(), BidError> {
    if pool.len() != POOL_LEN || pool.iter().any(|byte| *byte != 0) {
        return Err(BidError::BadAccount);
    }
    pool[0] = TAG_POOL;
    pool[1] = bump;
    pool[2] = vault_bump;
    pool[OFF_POOL_MINT..OFF_POOL_MINT + 32].copy_from_slice(mint);
    pool[OFF_POOL_ROOT..OFF_POOL_ROOT + 32].copy_from_slice(&empty_root()?);
    Ok(())
}

/// `inner` is `note_inner(blinding, secret, owner, 0)`. The owner is hidden,
/// so a note can be funded from a wallet that never bids.
pub fn shield(pool: &mut [u8], amount: u64, inner: &Field) -> Result<(Field, u32), BidError> {
    if amount == 0 {
        return Err(BidError::AmountZero);
    }
    require_canonical(inner)?;
    let mint = pool_mint(pool)?;
    let commitment = commitment_from_inner(amount, &mint, KIND_BALANCE, inner)?;
    let index = append(pool, &commitment)?;
    let deposited = read_u64(pool, OFF_POOL_DEPOSITED)?.checked_add(amount).ok_or(BidError::BadAccount)?;
    write_u64(pool, OFF_POOL_DEPOSITED, deposited);
    Ok((commitment, index))
}

pub struct Place<'a> {
    pub listing: &'a [u8],
    pub listing_key: &'a [u8; 32],
    pub bidder: &'a [u8; 32],
    pub nullifier: &'a Field,
    pub outputs: Outputs,
    pub seal: &'a [u8],
    pub proof: &'a [u8],
    pub now: i64,
    pub bidder_signed: bool,
    pub bump: u8,
    pub nullifier_fresh: bool,
}

pub fn place_note(bid: &mut [u8], pool: &mut [u8], ix: &Place) -> Result<(), BidError> {
    if !ix.bidder_signed {
        return Err(BidError::NotSigner);
    }
    let seller = require_open(ix.listing, ix.now)?;
    if ix.listing.len() < OFF_VIEW + 32 || ix.listing[OFF_VIEW..OFF_VIEW + 32] == [0u8; 32] {
        return Err(BidError::BadCiphertext);
    }
    if ix.seal.len() != SEAL_LEN || ix.seal.iter().all(|byte| *byte == 0) {
        return Err(BidError::BadCiphertext);
    }
    if bid.len() != NOTE_BID_LEN {
        return Err(BidError::BadAccount);
    }
    let fresh_slot = bid.iter().all(|byte| *byte == 0);
    let refunded_slot = bid[0] == TAG_NOTE && bid[1] == BID_REFUNDED;
    if !fresh_slot && !refunded_slot {
        return Err(BidError::BidExists);
    }
    let mint = pool_mint(pool)?;
    let deposited = read_u64(pool, OFF_POOL_DEPOSITED)?;
    let spend = Spend {
        seller: &seller,
        listing: ix.listing_key,
        bidder: ix.bidder,
        mint: &mint,
        nullifier: ix.nullifier,
        outputs: ix.outputs,
        bound: &[0u8; 32],
        pub_amount: 0,
        mode: MODE_BID,
        proof: ix.proof,
        nullifier_fresh: ix.nullifier_fresh,
    };
    check_spend(pool, &spend)?;
    let index = append(pool, &ix.outputs.output)?;
    append(pool, &ix.outputs.change)?;
    if read_u64(pool, OFF_POOL_DEPOSITED)? != deposited {
        return Err(BidError::BadAccount);
    }
    bid[0] = TAG_NOTE;
    bid[1] = BID_LOCKED;
    bid[2] = ix.bump;
    bid[OFF_NOTE_LISTING..OFF_NOTE_LISTING + 32].copy_from_slice(ix.listing_key);
    bid[OFF_NOTE_BIDDER..OFF_NOTE_BIDDER + 32].copy_from_slice(ix.bidder);
    bid[OFF_NOTE_MINT..OFF_NOTE_MINT + 32].copy_from_slice(&mint);
    bid[OFF_NOTE_COMMIT..OFF_NOTE_COMMIT + 32].copy_from_slice(&ix.outputs.output);
    bid[OFF_NOTE_INDEX..OFF_NOTE_INDEX + 4].copy_from_slice(&index.to_le_bytes());
    bid[OFF_NOTE_SEAL..OFF_NOTE_SEAL + SEAL_LEN].copy_from_slice(ix.seal);
    Ok(())
}

pub struct Settle<'a> {
    pub listing_key: &'a [u8; 32],
    pub signer: &'a [u8; 32],
    pub nullifier: &'a Field,
    pub outputs: Outputs,
    pub proof: &'a [u8],
    pub signed: bool,
    pub nullifier_fresh: bool,
}

pub fn accept_note(
    listing: &mut [u8],
    bid: &mut [u8],
    pool: &mut [u8],
    ix: &Settle,
    now: i64,
    send_nft: &mut dyn FnMut([u8; 32]) -> Result<(), BidError>,
) -> Result<(), BidError> {
    if !ix.signed {
        return Err(BidError::NotSigner);
    }
    let stored = require_open(listing, now)?;
    if stored != *ix.signer {
        return Err(BidError::NotSigner);
    }
    let bidder = note_bidder(bid)?;
    if note_listing(bid)? != *ix.listing_key {
        return Err(BidError::BadAccount);
    }
    if bid[1] != BID_LOCKED {
        return Err(BidError::BidNotLocked);
    }
    let commitment = note_commit(bid)?;
    let mint = note_mint(bid)?;
    if mint != pool_mint(pool)? {
        return Err(BidError::WrongMint);
    }
    let spend = Spend {
        seller: ix.signer,
        listing: ix.listing_key,
        bidder: &bidder,
        mint: &mint,
        nullifier: ix.nullifier,
        outputs: ix.outputs,
        bound: &commitment,
        pub_amount: 0,
        mode: MODE_ACCEPT,
        proof: ix.proof,
        nullifier_fresh: ix.nullifier_fresh,
    };
    // The NFT moves only after the proof is known to match this bid. The pool
    // bytes change after the transfer so a failed transfer leaves the note.
    check_spend(pool, &spend)?;
    send_nft(bidder)?;
    append(pool, &ix.outputs.output)?;
    append(pool, &ix.outputs.change)?;
    listing[OFF_STATUS] = STATUS_SOLD;
    listing[OFF_ACCEPTED..OFF_ACCEPTED + 32].copy_from_slice(&commitment);
    bid[1] = BID_ACCEPTED;
    Ok(())
}

pub fn refund_note(listing: &[u8], bid: &mut [u8], pool: &mut [u8], ix: &Settle) -> Result<(), BidError> {
    if !ix.signed {
        return Err(BidError::NotSigner);
    }
    if note_bidder(bid)? != *ix.signer || note_listing(bid)? != *ix.listing_key {
        return Err(BidError::WrongBidder);
    }
    if bid[1] != BID_LOCKED {
        return Err(BidError::BidNotLocked);
    }
    if listing.len() != crate::state::LISTING_LEN || listing[0] != crate::state::TAG_LISTING {
        return Err(BidError::BadAccount);
    }
    match listing[OFF_STATUS] {
        // The bidder who locked the note can take it back while the listing is open.
        // The signer was already matched to the bid. A stranger never reaches this.
        STATUS_OPEN | STATUS_CANCELLED => {}
        STATUS_SOLD => {
            if read32(listing, OFF_ACCEPTED)? == note_commit(bid)? {
                return Err(BidError::AlreadySold);
            }
        }
        _ => return Err(BidError::NotOpen),
    }
    let seller = read32(listing, crate::state::OFF_SELLER)?;
    let mint = note_mint(bid)?;
    if mint != pool_mint(pool)? {
        return Err(BidError::WrongMint);
    }
    let commitment = note_commit(bid)?;
    let spend = Spend {
        seller: &seller,
        listing: ix.listing_key,
        bidder: ix.signer,
        mint: &mint,
        nullifier: ix.nullifier,
        outputs: ix.outputs,
        bound: &commitment,
        pub_amount: 0,
        mode: MODE_REFUND,
        proof: ix.proof,
        nullifier_fresh: ix.nullifier_fresh,
    };
    check_spend(pool, &spend)?;
    append(pool, &ix.outputs.output)?;
    append(pool, &ix.outputs.change)?;
    bid[1] = BID_REFUNDED;
    Ok(())
}

pub struct Exit<'a> {
    pub owner: &'a [u8; 32],
    pub mint: &'a [u8; 32],
    pub nullifier: &'a Field,
    pub change: &'a Field,
    pub amount: u64,
    pub proof: &'a [u8],
    pub owner_signed: bool,
    pub nullifier_fresh: bool,
}

pub fn unshield(pool: &mut [u8], ix: &Exit) -> Result<(), BidError> {
    if !ix.owner_signed {
        return Err(BidError::NotSigner);
    }
    if ix.amount == 0 {
        return Err(BidError::AmountZero);
    }
    if pool_mint(pool)? != *ix.mint {
        return Err(BidError::WrongMint);
    }
    let deposited = read_u64(pool, OFF_POOL_DEPOSITED)?;
    if ix.amount > deposited {
        return Err(BidError::BadAccount);
    }
    let spend = Spend {
        seller: &[0u8; 32],
        listing: &[0u8; 32],
        bidder: ix.owner,
        mint: ix.mint,
        nullifier: ix.nullifier,
        outputs: Outputs { output: [0u8; 32], change: *ix.change },
        bound: &[0u8; 32],
        pub_amount: ix.amount,
        mode: MODE_UNSHIELD,
        proof: ix.proof,
        nullifier_fresh: ix.nullifier_fresh,
    };
    check_spend(pool, &spend)?;
    append(pool, ix.change)?;
    write_u64(pool, OFF_POOL_DEPOSITED, deposited - ix.amount);
    Ok(())
}

pub fn cancel_listing(listing: &mut [u8], seller: &[u8; 32], seller_signed: bool, now: i64) -> Result<(), BidError> {
    if !seller_signed {
        return Err(BidError::NotSigner);
    }
    let stored = require_open(listing, now)?;
    if stored != *seller {
        return Err(BidError::NotSigner);
    }
    listing[OFF_STATUS] = STATUS_CANCELLED;
    Ok(())
}

struct Spend<'a> {
    seller: &'a [u8; 32],
    listing: &'a [u8; 32],
    bidder: &'a [u8; 32],
    mint: &'a [u8; 32],
    nullifier: &'a Field,
    outputs: Outputs,
    bound: &'a Field,
    pub_amount: u64,
    mode: u8,
    proof: &'a [u8],
    nullifier_fresh: bool,
}

fn check_spend(pool: &[u8], spend: &Spend) -> Result<(), BidError> {
    require_canonical(spend.nullifier)?;
    if !spend.nullifier_fresh {
        return Err(BidError::NoteSpent);
    }
    if !mode_ok(spend.mode) {
        return Err(BidError::BadMode);
    }
    let instance = Instance {
        old_root: read32(pool, OFF_POOL_ROOT)?,
        nullifier: *spend.nullifier,
        output: spend.outputs.output,
        change: spend.outputs.change,
        mode: spend.mode,
        listing: *spend.listing,
        bidder: *spend.bidder,
        seller: *spend.seller,
        mint: *spend.mint,
        bound: *spend.bound,
        pub_amount: spend.pub_amount,
    };
    verify_proof(&instance, spend.proof)
}

fn append(pool: &mut [u8], leaf: &Field) -> Result<u32, BidError> {
    require_canonical(leaf)?;
    pool_mint(pool)?;
    let index = read_u32(pool, OFF_POOL_INDEX)?;
    let next = index.checked_add(1).ok_or(BidError::BadAccount)?;
    let frontier = pool.get_mut(OFF_POOL_FRONTIER..OFF_POOL_FRONTIER + FRONTIER_LEN).ok_or(BidError::BadAccount)?;
    let root = frontier_append(frontier, index, leaf)?;
    pool[OFF_POOL_ROOT..OFF_POOL_ROOT + 32].copy_from_slice(&root);
    write_u32(pool, OFF_POOL_INDEX, next);
    Ok(index)
}

fn verify_proof(instance: &Instance, proof: &[u8]) -> Result<(), BidError> {
    #[cfg(feature = "bpf-entrypoint")]
    {
        chain::verify(instance, proof)
    }
    #[cfg(all(feature = "host-proof", not(feature = "bpf-entrypoint")))]
    {
        circuit::verify(instance, proof)
    }
    #[cfg(not(any(feature = "host-proof", feature = "bpf-entrypoint")))]
    {
        let _ = (instance, proof);
        Err(BidError::BadProof)
    }
}

fn require_open(listing: &[u8], now: i64) -> Result<[u8; 32], BidError> {
    if listing.len() != crate::state::LISTING_LEN || listing[0] != crate::state::TAG_LISTING {
        return Err(BidError::BadAccount);
    }
    match listing[OFF_STATUS] {
        STATUS_OPEN => {}
        STATUS_SOLD => return Err(BidError::AlreadySold),
        _ => return Err(BidError::NotOpen),
    }
    if read_i64(listing, crate::state::OFF_DEADLINE)? <= now {
        return Err(BidError::DeadlineNotFuture);
    }
    read32(listing, crate::state::OFF_SELLER)
}

fn note_bidder(bid: &[u8]) -> Result<[u8; 32], BidError> {
    if bid.len() != NOTE_BID_LEN || bid[0] != TAG_NOTE {
        return Err(BidError::NoBid);
    }
    read32(bid, OFF_NOTE_BIDDER)
}

fn note_listing(bid: &[u8]) -> Result<[u8; 32], BidError> {
    read32(bid, OFF_NOTE_LISTING)
}

fn note_commit(bid: &[u8]) -> Result<[u8; 32], BidError> {
    read32(bid, OFF_NOTE_COMMIT)
}

fn note_mint(bid: &[u8]) -> Result<[u8; 32], BidError> {
    read32(bid, OFF_NOTE_MINT)
}

fn pool_mint(pool: &[u8]) -> Result<[u8; 32], BidError> {
    if pool.len() != POOL_LEN || pool[0] != TAG_POOL {
        return Err(BidError::BadAccount);
    }
    read32(pool, OFF_POOL_MINT)
}

fn read32(data: &[u8], at: usize) -> Result<[u8; 32], BidError> {
    let bytes = data.get(at..at + 32).ok_or(BidError::BadAccount)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn read_u32(data: &[u8], at: usize) -> Result<u32, BidError> {
    let bytes = data.get(at..at + 4).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 4];
    sized.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(sized))
}

fn write_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u64(data: &[u8], at: usize) -> Result<u64, BidError> {
    let bytes = data.get(at..at + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(sized))
}

fn write_u64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_i64(data: &[u8], at: usize) -> Result<i64, BidError> {
    let bytes = data.get(at..at + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(i64::from_le_bytes(sized))
}
