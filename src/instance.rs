//! Public inputs of a join-split. One note goes in; a primary output and a
//! change note come out. The amount is public only for an unshield, which
//! names the number of tokens the vault pays.

use crate::error::BidError;
use crate::poseidon::{limbs, require_canonical, seller_mix, u64_field, Field};
use crate::state::{MODE_ACCEPT, MODE_BID, MODE_REFUND, MODE_UNSHIELD};

pub const PUBLIC_INPUTS: usize = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub old_root: Field,
    pub nullifier: Field,
    pub output: Field,
    pub change: Field,
    pub mode: u8,
    pub listing: [u8; 32],
    pub bidder: [u8; 32],
    pub seller: [u8; 32],
    pub mint: [u8; 32],
    pub bound: Field,
    pub pub_amount: u64,
}

impl Instance {
    /// Little-endian scalars in circuit order. A value at or above the
    /// modulus is refused, so a proof input has exactly one byte encoding.
    pub fn field_bytes(&self) -> Result<[Field; PUBLIC_INPUTS], BidError> {
        for value in [&self.old_root, &self.nullifier, &self.output, &self.change, &self.bound] {
            require_canonical(value)?;
        }
        let (listing_lo, listing_hi) = limbs(&self.listing);
        let (bidder_lo, bidder_hi) = limbs(&self.bidder);
        let (mint_lo, mint_hi) = limbs(&self.mint);
        Ok([
            self.old_root,
            self.nullifier,
            self.output,
            self.change,
            u64_field(u64::from(self.mode)),
            listing_lo,
            listing_hi,
            bidder_lo,
            bidder_hi,
            seller_mix(&self.seller)?,
            mint_lo,
            mint_hi,
            self.bound,
            u64_field(self.pub_amount),
        ])
    }
}

pub fn mode_ok(mode: u8) -> bool {
    matches!(mode, MODE_BID | MODE_ACCEPT | MODE_REFUND | MODE_UNSHIELD)
}
