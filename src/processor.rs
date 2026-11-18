//! Listing state changes. The NFT CPI runs before the status byte becomes open.

use crate::error::BidError;
use crate::standards::{prepare, ListInput};
use crate::state::{
    LockKind, BID_ACCEPTED, BID_LEN, BID_LOCKED, NATIVE_MINT, OFF_ASSET, OFF_BID_AMOUNT, OFF_VIEW,
    OFF_BID_BIDDER, OFF_BID_BUMP, OFF_BID_LISTING, OFF_BID_MINT, OFF_BID_PAY, OFF_BID_STATUS,
    OFF_BID_TAG, OFF_BUMP, OFF_DEADLINE, OFF_SELLER, OFF_STANDARD, OFF_STATUS, OFF_TAG, PAY_SOL,
    PAY_SPL, LISTING_LEN, STATUS_OPEN, STATUS_SOLD, TAG_BID, TAG_LISTING,
};

/// Fields written on the listing. Account bytes are not borrowed here.
pub struct OpenListing {
    pub seller: [u8; 32],
    pub asset: [u8; 32],
    pub standard: u8,
    pub deadline: i64,
    pub seller_is_signer: bool,
    /// X25519 public key bidders encrypt bid openings to.
    pub view: [u8; 32],
}

/// Validates the NFT, runs `transfer`, and only then marks the listing open.
/// A `transfer` error leaves `data` unchanged.
pub fn list_nft(
    data: &mut [u8],
    input: &ListInput<'_>,
    view: &[u8; 32],
    bump: u8,
    transfer: &mut dyn FnMut(LockKind) -> Result<(), BidError>,
) -> Result<(), BidError> {
    if data.len() != LISTING_LEN {
        return Err(BidError::BadAccount);
    }
    if data[OFF_STATUS] == STATUS_OPEN {
        return Err(BidError::AlreadyListed);
    }
    if data[OFF_STATUS] != 0 {
        return Err(BidError::BadAccount);
    }
    if !input.seller_is_signer {
        return Err(BidError::NotSigner);
    }
    let plan = prepare(input)?;
    transfer(plan.kind)?;
    commit_open(
        data,
        &OpenListing {
            seller: *input.seller,
            asset: *input.asset_address,
            standard: input.standard,
            deadline: input.deadline,
            seller_is_signer: input.seller_is_signer,
            view: *view,
        },
        bump,
    )
}

/// Writes the open listing. Call this only after the NFT CPI has returned ok.
pub fn commit_open(data: &mut [u8], open: &OpenListing, bump: u8) -> Result<(), BidError> {
    if data.len() != LISTING_LEN || !open.seller_is_signer || open.view == [0u8; 32] {
        return Err(if open.seller_is_signer && open.view != [0u8; 32] {
            BidError::BadAccount
        } else if !open.seller_is_signer {
            BidError::NotSigner
        } else {
            BidError::BadCiphertext
        });
    }
    if data[OFF_STATUS] == STATUS_OPEN {
        return Err(BidError::AlreadyListed);
    }
    if data[OFF_STATUS] != 0 {
        return Err(BidError::BadAccount);
    }
    data[OFF_TAG] = TAG_LISTING;
    data[OFF_STATUS] = STATUS_OPEN;
    data[OFF_STANDARD] = open.standard;
    data[OFF_BUMP] = bump;
    data[OFF_SELLER..OFF_SELLER + 32].copy_from_slice(&open.seller);
    data[OFF_ASSET..OFF_ASSET + 32].copy_from_slice(&open.asset);
    data[OFF_DEADLINE..OFF_DEADLINE + 8].copy_from_slice(&open.deadline.to_le_bytes());
    data[OFF_VIEW..OFF_VIEW + 32].copy_from_slice(&open.view);
    Ok(())
}

/// One leg of an accept. The NFT leg runs first. The funds leg names the seller.
pub enum SwapLeg {
    Nft([u8; 32]),
    Funds { amount: u64, seller: [u8; 32] },
}

/// Locks a bid on an open listing. `lock_funds` runs before any byte is written.
pub fn place_bid(
    listing: &[u8],
    bid: &mut [u8],
    listing_key: &[u8; 32],
    bidder: &[u8; 32],
    mint: &[u8; 32],
    amount: u64,
    now: i64,
    bidder_is_signer: bool,
    bump: u8,
    lock_funds: &mut dyn FnMut(u64, &[u8; 32]) -> Result<(), BidError>,
) -> Result<(), BidError> {
    if !bidder_is_signer {
        return Err(BidError::NotSigner);
    }
    let _seller = require_open(listing, now)?;
    if amount == 0 {
        return Err(BidError::AmountZero);
    }
    if *mint == [0u8; 32] || bid.len() != BID_LEN {
        return Err(BidError::BadAccount);
    }
    match bid_status(bid)? {
        0 => {}
        BID_LOCKED => {
            return Err(if bidder_of(bid)? == *bidder {
                BidError::BidExists
            } else {
                BidError::WrongBidder
            });
        }
        BID_ACCEPTED => return Err(BidError::BidNotLocked),
        _ => return Err(BidError::BadAccount),
    }
    lock_funds(amount, mint)?;
    bid[OFF_BID_TAG] = TAG_BID;
    bid[OFF_BID_STATUS] = BID_LOCKED;
    bid[OFF_BID_BUMP] = bump;
    bid[OFF_BID_PAY] = if *mint == NATIVE_MINT { PAY_SOL } else { PAY_SPL };
    bid[OFF_BID_LISTING..OFF_BID_LISTING + 32].copy_from_slice(listing_key);
    bid[OFF_BID_BIDDER..OFF_BID_BIDDER + 32].copy_from_slice(bidder);
    bid[OFF_BID_MINT..OFF_BID_MINT + 32].copy_from_slice(mint);
    write_amount(bid, amount);
    Ok(())
}

/// Replaces the amount on this bidder's locked bid. A failed settle leaves the old amount.
pub fn replace_bid(
    listing: &[u8],
    bid: &mut [u8],
    bidder: &[u8; 32],
    mint: &[u8; 32],
    new_amount: u64,
    now: i64,
    bidder_is_signer: bool,
    settle: &mut dyn FnMut(u64, u64) -> Result<(), BidError>,
) -> Result<(), BidError> {
    if !bidder_is_signer {
        return Err(BidError::NotSigner);
    }
    require_open(listing, now)?;
    require_locked_bidder(bid, bidder)?;
    if mint_of(bid)? != *mint {
        return Err(BidError::WrongMint);
    }
    if new_amount == 0 {
        return Err(BidError::AmountZero);
    }
    let old = amount_of(bid)?;
    settle(old, new_amount)?;
    write_amount(bid, new_amount);
    Ok(())
}

/// Returns the locked funds to the bidder stored on the account, then clears it.
pub fn cancel_bid(
    bid: &mut [u8],
    bidder: &[u8; 32],
    bidder_is_signer: bool,
    release: &mut dyn FnMut(u64, &[u8; 32]) -> Result<(), BidError>,
) -> Result<(), BidError> {
    if !bidder_is_signer {
        return Err(BidError::NotSigner);
    }
    require_locked_bidder(bid, bidder)?;
    let amount = amount_of(bid)?;
    let mint = mint_of(bid)?;
    release(amount, &mint)?;
    bid.fill(0);
    Ok(())
}

/// Moves the NFT to the bidder stored on the bid, then the funds to the seller.
/// Neither status byte changes until both legs return.
pub fn accept_bid(
    listing: &mut [u8],
    bid: &mut [u8],
    seller: &[u8; 32],
    seller_is_signer: bool,
    now: i64,
    swap: &mut dyn FnMut(SwapLeg) -> Result<(), BidError>,
) -> Result<(), BidError> {
    if !seller_is_signer {
        return Err(BidError::NotSigner);
    }
    let stored_seller = require_open(listing, now)?;
    if stored_seller != *seller {
        return Err(BidError::NotSigner);
    }
    if bid.len() != BID_LEN || bid[OFF_BID_TAG] != TAG_BID || bid[OFF_BID_STATUS] != BID_LOCKED {
        return Err(if bid.iter().all(|byte| *byte == 0) {
            BidError::NoBid
        } else {
            BidError::BidNotLocked
        });
    }
    let bidder = bidder_of(bid)?;
    let amount = amount_of(bid)?;
    swap(SwapLeg::Nft(bidder))?;
    swap(SwapLeg::Funds {
        amount,
        seller: *seller,
    })?;
    listing[OFF_STATUS] = STATUS_SOLD;
    bid[OFF_BID_STATUS] = BID_ACCEPTED;
    Ok(())
}

fn require_open(listing: &[u8], now: i64) -> Result<[u8; 32], BidError> {
    if listing.len() != LISTING_LEN || listing[OFF_TAG] != TAG_LISTING {
        return Err(BidError::BadAccount);
    }
    match listing[OFF_STATUS] {
        STATUS_OPEN => {}
        STATUS_SOLD => return Err(BidError::AlreadySold),
        _ => return Err(BidError::NotOpen),
    }
    let deadline = read_i64(listing, OFF_DEADLINE)?;
    if deadline <= now {
        return Err(BidError::DeadlineNotFuture);
    }
    Ok(pubkey_at(listing, OFF_SELLER)?)
}

fn require_locked_bidder(bid: &[u8], bidder: &[u8; 32]) -> Result<(), BidError> {
    if bid.len() != BID_LEN {
        return Err(BidError::BadAccount);
    }
    if bid[OFF_BID_TAG] != TAG_BID {
        return Err(if bid.iter().all(|byte| *byte == 0) {
            BidError::NoBid
        } else {
            BidError::BadAccount
        });
    }
    if bidder_of(bid)? != *bidder {
        return Err(BidError::WrongBidder);
    }
    if bid[OFF_BID_STATUS] != BID_LOCKED {
        return Err(BidError::BidNotLocked);
    }
    Ok(())
}

fn bid_status(bid: &[u8]) -> Result<u8, BidError> {
    if bid.len() != BID_LEN {
        return Err(BidError::BadAccount);
    }
    if bid.iter().all(|byte| *byte == 0) {
        return Ok(0);
    }
    if bid[OFF_BID_TAG] != TAG_BID {
        return Err(BidError::BadAccount);
    }
    Ok(bid[OFF_BID_STATUS])
}

fn bidder_of(bid: &[u8]) -> Result<[u8; 32], BidError> {
    pubkey_at(bid, OFF_BID_BIDDER)
}

fn mint_of(bid: &[u8]) -> Result<[u8; 32], BidError> {
    pubkey_at(bid, OFF_BID_MINT)
}

fn amount_of(bid: &[u8]) -> Result<u64, BidError> {
    let bytes = bid.get(OFF_BID_AMOUNT..OFF_BID_AMOUNT + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(sized))
}

fn write_amount(bid: &mut [u8], amount: u64) {
    bid[OFF_BID_AMOUNT..OFF_BID_AMOUNT + 8].copy_from_slice(&amount.to_le_bytes());
}

fn pubkey_at(data: &[u8], at: usize) -> Result<[u8; 32], BidError> {
    let bytes = data.get(at..at + 32).ok_or(BidError::BadAccount)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}

fn read_i64(data: &[u8], at: usize) -> Result<i64, BidError> {
    let bytes = data.get(at..at + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(i64::from_le_bytes(sized))
}
