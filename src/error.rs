/// Failures a caller can hit. Custom codes start at 100 so they do not collide
/// with the runtime's `ProgramError` discriminants when mapped at the entrypoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BidError {
    NotSigner = 100,
    AlreadyListed = 101,
    /// The standard byte does not match the account that was passed.
    WrongStandard = 102,
    /// Programmable NFT transfer needs Token Metadata, auth rules, and the token record.
    PnftTransferNotImplemented = 103,
    /// A compressed NFT is a merkle leaf. This instruction does not take a proof.
    CnftProofNotImplemented = 104,
    /// A Token-2022 transfer hook would run inside the CPI. Fail closed.
    TransferHookRejected = 105,
    /// A permanent delegate can move the token without the owner.
    PermanentDelegateRejected = 106,
    /// A freeze plugin is frozen, or an external adapter can reject the transfer.
    /// Royalties and transfer delegates do not stop the owner's Core transfer.
    CorePluginBlocksTransfer = 107,
    /// The token move failed. The listing was not marked open.
    TransferFailed = 108,
    BadAccount = 109,
    NotRentExempt = 110,
    WrongProgram = 111,
    NotOwner = 112,
    DeadlineNotFuture = 113,
    /// Supply, decimals, or amount is not a single NFT.
    NotNft = 114,
    /// The mint cannot be transferred (non-transferable extension).
    ExtensionBlocksTransfer = 115,
    /// The listing is not open.
    NotOpen = 116,
    /// The signer is not the bidder stored on this bid.
    WrongBidder = 117,
    /// This bidder already has a locked bid on the listing.
    BidExists = 118,
    /// The bid account is missing or uninitialized.
    NoBid = 119,
    /// The listing was already sold.
    AlreadySold = 120,
    /// The mint account is not the mint stored on the bid.
    WrongMint = 121,
    /// A bid amount has to be greater than zero.
    AmountZero = 122,
    /// Update, cancel, and accept require a locked bid.
    BidNotLocked = 123,
    /// The join-split proof did not verify for these public inputs.
    BadProof = 124,
    /// This note was already spent.
    NoteSpent = 125,
    /// The instruction is not a bid, accept, refund, or unshield.
    BadMode = 126,
    /// The seller ciphertext is the wrong length or all zeros.
    BadCiphertext = 127,
    /// A bidder can pull a note back only after cancel, or after another bid wins.
    StillOpen = 128,
    /// A 32-byte field value is not below the BN254 scalar modulus. `n` and
    /// `n + r` are the same proof input, so only the canonical one is a nullifier.
    NonCanonical = 129,
    /// The Poseidon syscall refused the inputs.
    HashFailed = 130,
}

impl BidError {
    /// Stable numeric code returned to the runtime. Do not renumber a shipped code.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Text written to the program log before the custom error is returned.
    pub const fn as_str(self) -> &'static str {
        match self {
            BidError::NotSigner => "NotSigner",
            BidError::AlreadyListed => "AlreadyListed",
            BidError::WrongStandard => "WrongStandard",
            BidError::PnftTransferNotImplemented => "PnftTransferNotImplemented",
            BidError::CnftProofNotImplemented => "CnftProofNotImplemented",
            BidError::TransferHookRejected => "TransferHookRejected",
            BidError::PermanentDelegateRejected => "PermanentDelegateRejected",
            BidError::CorePluginBlocksTransfer => "CorePluginBlocksTransfer",
            BidError::TransferFailed => "TransferFailed",
            BidError::BadAccount => "BadAccount",
            BidError::NotRentExempt => "NotRentExempt",
            BidError::WrongProgram => "WrongProgram",
            BidError::NotOwner => "NotOwner",
            BidError::DeadlineNotFuture => "DeadlineNotFuture",
            BidError::NotNft => "NotNft",
            BidError::ExtensionBlocksTransfer => "ExtensionBlocksTransfer",
            BidError::NotOpen => "NotOpen",
            BidError::WrongBidder => "WrongBidder",
            BidError::BidExists => "BidExists",
            BidError::NoBid => "NoBid",
            BidError::AlreadySold => "AlreadySold",
            BidError::WrongMint => "WrongMint",
            BidError::AmountZero => "AmountZero",
            BidError::BidNotLocked => "BidNotLocked",
            BidError::BadProof => "BadProof",
            BidError::NoteSpent => "NoteSpent",
            BidError::BadMode => "BadMode",
            BidError::BadCiphertext => "BadCiphertext",
            BidError::StillOpen => "StillOpen",
            BidError::NonCanonical => "NonCanonical",
            BidError::HashFailed => "HashFailed",
        }
    }
}
