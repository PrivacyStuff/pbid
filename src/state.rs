/// One listing per asset. The status byte stays zero until the NFT CPI returns.
/// Bytes 76..108 are the seller X25519 key. Bytes 108..140 are the accepted
/// note commitment, zero until accept.
pub const LISTING_LEN: usize = 140;
pub const TAG_LISTING: u8 = 1;
pub const STATUS_OPEN: u8 = 1;
/// Set only after the NFT transfer and the winning note spend both return.
pub const STATUS_SOLD: u8 = 2;
/// Seller stopped the auction. Each bidder pulls their own note back.
pub const STATUS_CANCELLED: u8 = 3;
pub const IX_LIST: u8 = 0;
pub const IX_PLACE: u8 = 1;
pub const IX_UPDATE: u8 = 2;
pub const IX_CANCEL: u8 = 3;
pub const IX_ACCEPT: u8 = 4;
/// Public shield into the pool. The amount is visible; the note's owner and secrets are not.
pub const IX_SHIELD: u8 = 5;
pub const IX_CANCEL_LISTING: u8 = 6;
pub const IX_REFUND: u8 = 7;
/// Spend a balance note out of the vault. The amount is public on this exit.
pub const IX_UNSHIELD: u8 = 8;
/// List: tag, standard, deadline, seller X25519 key.
pub const LIST_IX_LEN: usize = 42;
/// Legacy place and update: tag plus a little-endian amount.
pub const BID_IX_LEN: usize = 9;
pub const LISTING_SEED: &[u8] = b"listing";
pub const BID_SEED: &[u8] = b"bid";
pub const POOL_SEED: &[u8] = b"pool";
pub const NULL_SEED: &[u8] = b"null";

/// Legacy clear bid. Devnet accounts of this size can still be cancelled.
pub const BID_LEN: usize = 108;
pub const TAG_BID: u8 = 2;
pub const BID_LOCKED: u8 = 1;
pub const BID_ACCEPTED: u8 = 2;
pub const PAY_SOL: u8 = 1;
pub const PAY_SPL: u8 = 2;

pub const OFF_BID_TAG: usize = 0;
pub const OFF_BID_STATUS: usize = 1;
pub const OFF_BID_BUMP: usize = 2;
pub const OFF_BID_PAY: usize = 3;
pub const OFF_BID_LISTING: usize = 4;
pub const OFF_BID_BIDDER: usize = 36;
pub const OFF_BID_MINT: usize = 68;
pub const OFF_BID_AMOUNT: usize = 100;

/// Wrapped SOL mint `So11111111111111111111111111111111111111112`. A bid in SOL names this mint.
pub const NATIVE_MINT: [u8; 32] = [
    6, 155, 136, 87, 254, 171, 129, 132, 251, 104, 127, 99, 70, 24, 192, 53, 218, 196, 57, 220, 26,
    235, 59, 85, 152, 160, 240, 0, 0, 0, 0, 1,
];

pub const OFF_TAG: usize = 0;
pub const OFF_STATUS: usize = 1;
pub const OFF_STANDARD: usize = 2;
pub const OFF_BUMP: usize = 3;
pub const OFF_SELLER: usize = 4;
pub const OFF_ASSET: usize = 36;
pub const OFF_DEADLINE: usize = 68;
pub const OFF_VIEW: usize = 76;
pub const OFF_ACCEPTED: usize = 108;

/// Note bid. The amount is not stored. The seller reads it from the ciphertext.
pub const TAG_NOTE: u8 = 3;
pub const TAG_POOL: u8 = 4;
pub const BID_REFUNDED: u8 = 3;
pub const MODE_BID: u8 = 1;
pub const MODE_ACCEPT: u8 = 2;
pub const MODE_REFUND: u8 = 3;
pub const MODE_UNSHIELD: u8 = 4;
pub const KIND_BALANCE: u8 = 0;
pub const KIND_BID: u8 = 1;
pub const MERKLE_DEPTH: usize = 20;
/// Groth16 proof, uncompressed: G1 || G2 || G1.
pub const PROOF_LEN: usize = 256;
/// amount || blinding || secret.
pub const SEAL_PLAIN: usize = 8 + 32 + 32;
/// ephemeral pubkey || nonce || ciphertext || Poly1305 tag.
pub const SEAL_LEN: usize = 32 + 12 + SEAL_PLAIN + 16;
pub const NOTE_BID_LEN: usize = 268;
pub const OFF_NOTE_LISTING: usize = 4;
pub const OFF_NOTE_BIDDER: usize = 36;
pub const OFF_NOTE_MINT: usize = 68;
pub const OFF_NOTE_COMMIT: usize = 100;
pub const OFF_NOTE_INDEX: usize = 132;
pub const OFF_NOTE_SEAL: usize = 136;

pub const POOL_LEN: usize = 720;
pub const OFF_POOL_MINT: usize = 4;
pub const OFF_POOL_ROOT: usize = 36;
pub const OFF_POOL_INDEX: usize = 68;
pub const OFF_POOL_DEPOSITED: usize = 72;
pub const OFF_POOL_FRONTIER: usize = 80;

/// Place, accept, and refund start with the tag, the nullifier, the output, and the change.
pub const SPEND_HEAD: usize = 1 + 32 + 32 + 32;
pub const PLACE_IX_LEN: usize = SPEND_HEAD + SEAL_LEN + PROOF_LEN;
pub const SPEND_IX_LEN: usize = SPEND_HEAD + PROOF_LEN;
/// Tag, amount, and the note's inner hash. The blinding and secret stay with the holder.
pub const SHIELD_IX_LEN: usize = 1 + 8 + 32;
/// Tag, nullifier, change commitment, amount, proof.
pub const UNSHIELD_IX_LEN: usize = 1 + 32 + 32 + 8 + PROOF_LEN;

pub const STANDARD_CORE: u8 = 1;
pub const STANDARD_LEGACY: u8 = 2;
pub const STANDARD_PNFT: u8 = 3;
pub const STANDARD_TOKEN_2022: u8 = 4;
pub const STANDARD_COMPRESSED: u8 = 5;

/// Which CPI a successful prepare is allowed to run. pNFT and cNFT never reach this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    CoreTransfer,
    SplTransfer,
    Token2022TransferChecked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub kind: LockKind,
    /// Set when the Core asset's update authority is a collection.
    pub collection: Option<[u8; 32]>,
}
