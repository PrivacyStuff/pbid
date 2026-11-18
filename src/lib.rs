//! Shielded-bid listing. The seller locks an NFT they already hold.
//! Bid amounts live in notes. The listing account does not store them.

#![cfg_attr(feature = "bpf-entrypoint", no_std)]
extern crate alloc;

mod error;
mod instance;
mod merkle;
mod notes;
mod poseidon;
mod processor;
#[cfg(feature = "host-proof")]
mod circuit;
#[cfg(feature = "host-proof")]
pub mod job;
#[cfg(feature = "host-proof")]
mod seal;
#[cfg(feature = "host-proof")]
pub use seal::{open, seal, view_key};
mod standards;
mod state;

pub use error::BidError;
pub use instance::{Instance, PUBLIC_INPUTS};
pub use poseidon::{
    commitment_from_inner, is_canonical, merkle_node, note_commitment, note_inner, note_nullifier, nullifier, Field,
};
#[cfg(feature = "host-proof")]
pub use circuit::{
    instance_of, proving_key_path, proving_key_vk_bytes, prove, random_field, setup, verify, Opening, SpendWitness,
};
pub use merkle::NoteTree;
pub use notes::{accept_note, cancel_listing, init_pool, place_note, refund_note, shield, unshield, Exit, Outputs, Place, Settle};
pub use processor::{
    accept_bid, cancel_bid, commit_open, list_nft, place_bid, replace_bid, OpenListing, SwapLeg,
};
pub use standards::{
    prepare, ListInput, BUBBLEGUM_PROGRAM_ID, CORE_PROGRAM_ID, METADATA_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
};
pub use state::{
    LockKind, Plan, BID_ACCEPTED, BID_IX_LEN, BID_LEN, BID_LOCKED, BID_REFUNDED, BID_SEED, IX_ACCEPT, IX_CANCEL,
    IX_CANCEL_LISTING, IX_LIST, IX_PLACE, IX_REFUND, IX_SHIELD, IX_UNSHIELD, IX_UPDATE, LISTING_LEN, LISTING_SEED,
    LIST_IX_LEN, NATIVE_MINT, NULL_SEED, OFF_BID_AMOUNT, OFF_BID_BIDDER, OFF_BID_MINT, OFF_BID_STATUS, OFF_STANDARD,
    OFF_STATUS, PAY_SOL, PAY_SPL, PLACE_IX_LEN, POOL_SEED, SHIELD_IX_LEN, SPEND_HEAD, SPEND_IX_LEN,
    STANDARD_COMPRESSED, STANDARD_CORE, STANDARD_LEGACY, STANDARD_PNFT, STANDARD_TOKEN_2022, STATUS_CANCELLED,
    STATUS_OPEN, STATUS_SOLD, TAG_BID, TAG_LISTING, TAG_NOTE, KIND_BALANCE, KIND_BID, MODE_ACCEPT, MODE_BID,
    MODE_REFUND, MODE_UNSHIELD, NOTE_BID_LEN, OFF_ACCEPTED, OFF_NOTE_BIDDER, OFF_NOTE_COMMIT, OFF_NOTE_INDEX,
    OFF_NOTE_LISTING, OFF_NOTE_SEAL, OFF_POOL_DEPOSITED, OFF_POOL_INDEX, OFF_POOL_ROOT, OFF_VIEW, POOL_LEN,
    PROOF_LEN, SEAL_LEN, TAG_POOL, UNSHIELD_IX_LEN,
};

#[cfg(feature = "bpf-entrypoint")]
mod chain;
#[cfg(feature = "bpf-entrypoint")]
mod entrypoint;
