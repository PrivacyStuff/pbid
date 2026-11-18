//! Account parsers for the five NFT standards. They are not interchangeable.
//! A wrong owner or a wrong token-standard byte is `WrongStandard` before any CPI.

use crate::error::BidError;
use crate::state::{
    LockKind, Plan, STANDARD_COMPRESSED, STANDARD_CORE, STANDARD_LEGACY, STANDARD_PNFT,
    STANDARD_TOKEN_2022,
};

/// Metaplex Core `CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d`.
pub const CORE_PROGRAM_ID: [u8; 32] = [
    175, 84, 171, 16, 189, 151, 165, 66, 160, 158, 247, 179, 152, 137, 221, 12, 211, 148, 164, 204,
    233, 223, 166, 205, 201, 126, 190, 45, 35, 91, 167, 72,
];
/// SPL Token `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`.
pub const TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];
/// Token-2022 `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
pub const TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];
/// Token Metadata `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s`.
pub const METADATA_PROGRAM_ID: [u8; 32] = [
    11, 112, 101, 177, 227, 209, 124, 69, 56, 157, 82, 127, 107, 4, 195, 205, 88, 184, 108, 115, 26,
    160, 253, 181, 73, 182, 209, 188, 3, 248, 41, 70,
];
/// Bubblegum `BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY`.
pub const BUBBLEGUM_PROGRAM_ID: [u8; 32] = [
    152, 139, 128, 235, 121, 53, 40, 105, 178, 36, 116, 95, 89, 221, 191, 138, 38, 88, 202, 19,
    220, 104, 129, 33, 38, 53, 28, 174, 7, 193, 165, 165,
];

const KEY_ASSET: u8 = 1;
const KEY_PLUGIN_HEADER: u8 = 3;
const KEY_PLUGIN_REGISTRY: u8 = 4;
const KEY_COLLECTION: u8 = 5;
const METADATA_KEY: u8 = 4;
const TOKEN_STANDARD_NON_FUNGIBLE: u8 = 0;
const TOKEN_STANDARD_PNFT: u8 = 4;
const TOKEN_STANDARD_PNFT_EDITION: u8 = 5;
const MINT_BASE_LEN: usize = 82;
const MINT_SUPPLY: usize = 36;
const MINT_DECIMALS: usize = 44;
const MINT_INITIALIZED: usize = 45;
const ACCOUNT_TYPE_AT: usize = 165;
const TLV_START: usize = 166;
const ACCOUNT_TYPE_MINT: u8 = 1;
const EXT_NON_TRANSFERABLE: u16 = 9;
const EXT_PERMANENT_DELEGATE: u16 = 12;
const EXT_TRANSFER_HOOK: u16 = 14;
const TOKEN_ACCOUNT_STATE: usize = 108;
const TOKEN_INITIALIZED: u8 = 1;
const MAX_STRING: usize = 256;
const MAX_PLUGINS: u32 = 32;
/// Royalties and transfer delegates stay on the asset. They do not reject TransferV1 by the owner.
#[allow(dead_code)]
const PLUGIN_ROYALTIES: u8 = 0;
const PLUGIN_FREEZE: u8 = 1;
#[allow(dead_code)]
const PLUGIN_TRANSFER: u8 = 3;
const PLUGIN_PERM_FREEZE: u8 = 5;
#[allow(dead_code)]
const PLUGIN_PERM_TRANSFER: u8 = 7;
const PLUGIN_FREEZE_EXECUTE: u8 = 16;
const PLUGIN_PERM_FREEZE_EXECUTE: u8 = 17;

/// What the seller claims to be locking, plus the accounts that have to agree.
pub struct ListInput<'a> {
    pub seller: &'a [u8; 32],
    pub seller_is_signer: bool,
    pub standard: u8,
    pub deadline: i64,
    pub now: i64,
    pub asset_program: &'a [u8; 32],
    pub asset_data: &'a [u8],
    pub asset_address: &'a [u8; 32],
    pub token_program: Option<&'a [u8; 32]>,
    pub token_data: Option<&'a [u8]>,
    pub metadata_program: Option<&'a [u8; 32]>,
    pub metadata_data: Option<&'a [u8]>,
    pub collection_program: Option<&'a [u8; 32]>,
    pub collection_data: Option<&'a [u8]>,
    pub collection_address: Option<&'a [u8; 32]>,
}

/// Chooses the CPI, or a fail-closed error. Does not write the listing.
pub fn prepare(input: &ListInput<'_>) -> Result<Plan, BidError> {
    if !input.seller_is_signer {
        return Err(BidError::NotSigner);
    }
    if input.deadline <= input.now || *input.seller == [0u8; 32] || *input.asset_address == [0u8; 32]
    {
        return Err(if input.deadline <= input.now {
            BidError::DeadlineNotFuture
        } else {
            BidError::BadAccount
        });
    }
    // A compressed asset is a leaf, not a token account. Refuse before any token read.
    if input.standard == STANDARD_COMPRESSED || input.asset_program == &BUBBLEGUM_PROGRAM_ID {
        return Err(if input.standard == STANDARD_COMPRESSED {
            BidError::CnftProofNotImplemented
        } else {
            BidError::WrongStandard
        });
    }
    match input.standard {
        STANDARD_CORE => prepare_core(input),
        STANDARD_LEGACY => prepare_token(input, &TOKEN_PROGRAM_ID, false),
        STANDARD_PNFT => prepare_token(input, &TOKEN_PROGRAM_ID, true),
        STANDARD_TOKEN_2022 => prepare_token(input, &TOKEN_2022_PROGRAM_ID, false),
        _ => Err(BidError::WrongStandard),
    }
}

fn prepare_core(input: &ListInput<'_>) -> Result<Plan, BidError> {
    if input.asset_program != &CORE_PROGRAM_ID {
        return Err(BidError::WrongStandard);
    }
    let collection = read_core_asset(input.asset_data, input.seller)?;
    match (collection, input.collection_address, input.collection_data, input.collection_program) {
        (None, None, None, None) => {}
        (Some(expected), Some(passed), Some(data), Some(program)) => {
            if program != &CORE_PROGRAM_ID || passed != &expected {
                return Err(BidError::WrongStandard);
            }
            // Collection plugins constrain this Core asset. They are not another standard.
            read_core_collection(data)?;
        }
        _ => return Err(BidError::BadAccount),
    }
    Ok(Plan {
        kind: LockKind::CoreTransfer,
        collection,
    })
}

fn prepare_token(input: &ListInput<'_>, token_program: &[u8; 32], pnft: bool) -> Result<Plan, BidError> {
    if input.asset_program != token_program {
        return Err(BidError::WrongStandard);
    }
    require_mint_nft(input.asset_data)?;
    if token_program == &TOKEN_2022_PROGRAM_ID {
        reject_token_2022_extensions(input.asset_data)?;
    }
    let token = input.token_data.ok_or(BidError::BadAccount)?;
    let token_owner_program = input.token_program.ok_or(BidError::BadAccount)?;
    if token_owner_program != token_program {
        return Err(BidError::WrongStandard);
    }
    require_token_holder(token, input.asset_address, input.seller)?;
    if token_program == &TOKEN_PROGRAM_ID {
        let metadata = input.metadata_data.ok_or(BidError::BadAccount)?;
        let metadata_program = input.metadata_program.ok_or(BidError::BadAccount)?;
        if metadata_program != &METADATA_PROGRAM_ID {
            return Err(BidError::WrongProgram);
        }
        let standard = read_token_standard(metadata, input.asset_address)?;
        if pnft {
            if standard != TOKEN_STANDARD_PNFT && standard != TOKEN_STANDARD_PNFT_EDITION {
                return Err(BidError::WrongStandard);
            }
            // A raw SPL transfer is the wrong CPI. Do not pretend it locked the pNFT.
            return Err(BidError::PnftTransferNotImplemented);
        }
        if standard != TOKEN_STANDARD_NON_FUNGIBLE {
            return Err(if standard == TOKEN_STANDARD_PNFT || standard == TOKEN_STANDARD_PNFT_EDITION {
                BidError::WrongStandard
            } else {
                BidError::NotNft
            });
        }
        return Ok(Plan {
            kind: LockKind::SplTransfer,
            collection: None,
        });
    }
    if pnft {
        return Err(BidError::WrongStandard);
    }
    Ok(Plan {
        kind: LockKind::Token2022TransferChecked,
        collection: None,
    })
}

fn require_mint_nft(data: &[u8]) -> Result<(), BidError> {
    if data.len() < MINT_BASE_LEN {
        return Err(BidError::BadAccount);
    }
    let supply = read_u64_at(data, MINT_SUPPLY)?;
    if data[MINT_DECIMALS] != 0 || data[MINT_INITIALIZED] != 1 || supply != 1 {
        return Err(BidError::NotNft);
    }
    Ok(())
}

fn require_token_holder(data: &[u8], mint: &[u8; 32], seller: &[u8; 32]) -> Result<(), BidError> {
    if data.len() < TOKEN_ACCOUNT_STATE + 1 {
        return Err(BidError::BadAccount);
    }
    if data.get(..32) != Some(mint.as_slice()) {
        return Err(BidError::WrongStandard);
    }
    if data.get(32..64) != Some(seller.as_slice()) {
        return Err(BidError::NotOwner);
    }
    if read_u64_at(data, 64)? != 1 || data[TOKEN_ACCOUNT_STATE] != TOKEN_INITIALIZED {
        return Err(BidError::NotNft);
    }
    Ok(())
}

/// Token-2022 TLV. A hook program id or a nonzero permanent delegate refuses the move.
pub(crate) fn reject_token_2022_extensions(data: &[u8]) -> Result<(), BidError> {
    if data.len() == MINT_BASE_LEN {
        return Ok(());
    }
    if data.len() < TLV_START || data[ACCOUNT_TYPE_AT] != ACCOUNT_TYPE_MINT {
        return Err(BidError::BadAccount);
    }
    let mut at = TLV_START;
    while at < data.len() {
        if data.len() - at < 4 {
            return Err(BidError::BadAccount);
        }
        let kind = u16::from_le_bytes([data[at], data[at + 1]]);
        let len = u16::from_le_bytes([data[at + 2], data[at + 3]]) as usize;
        // Type 0 is uninitialized padding. A zero-length padding entry would otherwise spin.
        if kind == 0 {
            break;
        }
        at += 4;
        let body = data.get(at..at + len).ok_or(BidError::BadAccount)?;
        if kind == EXT_TRANSFER_HOOK {
            let program = body.get(32..64).ok_or(BidError::BadAccount)?;
            if program.iter().any(|byte| *byte != 0) {
                return Err(BidError::TransferHookRejected);
            }
        } else if kind == EXT_PERMANENT_DELEGATE {
            let delegate = body.get(..32).ok_or(BidError::BadAccount)?;
            if delegate.iter().any(|byte| *byte != 0) {
                return Err(BidError::PermanentDelegateRejected);
            }
        } else if kind == EXT_NON_TRANSFERABLE {
            return Err(BidError::ExtensionBlocksTransfer);
        }
        at += len;
    }
    Ok(())
}

fn read_token_standard(data: &[u8], mint: &[u8; 32]) -> Result<u8, BidError> {
    if data.first() != Some(&METADATA_KEY) || data.len() < 65 || data.get(33..65) != Some(mint.as_slice()) {
        return Err(BidError::BadAccount);
    }
    let mut at = 65;
    skip_borsh_string(data, &mut at)?;
    skip_borsh_string(data, &mut at)?;
    skip_borsh_string(data, &mut at)?;
    at = at.checked_add(2).ok_or(BidError::BadAccount)?;
    if at > data.len() {
        return Err(BidError::BadAccount);
    }
    let creators = *data.get(at).ok_or(BidError::BadAccount)?;
    at += 1;
    if creators == 1 {
        let count = read_u32(data, &mut at)?;
        let bytes = (count as usize).checked_mul(34).ok_or(BidError::BadAccount)?;
        at = at.checked_add(bytes).ok_or(BidError::BadAccount)?;
    } else if creators != 0 {
        return Err(BidError::BadAccount);
    }
    at = at.checked_add(2).ok_or(BidError::BadAccount)?;
    skip_option_byte(data, &mut at)?;
    let tag = *data.get(at).ok_or(BidError::BadAccount)?;
    if tag == 0 {
        return Err(BidError::NotNft);
    }
    if tag != 1 {
        return Err(BidError::BadAccount);
    }
    data.get(at + 1).copied().ok_or(BidError::BadAccount)
}

/// Returns the collection pubkey when the asset is in one.
fn read_core_asset(data: &[u8], seller: &[u8; 32]) -> Result<Option<[u8; 32]>, BidError> {
    if data.first() != Some(&KEY_ASSET) {
        return Err(BidError::WrongStandard);
    }
    let owner = data.get(1..33).ok_or(BidError::BadAccount)?;
    if owner != seller.as_slice() {
        return Err(BidError::NotOwner);
    }
    let mut at = 33;
    let tag = *data.get(at).ok_or(BidError::BadAccount)?;
    at += 1;
    let collection = match tag {
        0 => None,
        1 => {
            let _address = read_pubkey(data, &mut at)?;
            None
        }
        2 => Some(read_pubkey(data, &mut at)?),
        _ => return Err(BidError::BadAccount),
    };
    skip_borsh_string(data, &mut at)?;
    skip_borsh_string(data, &mut at)?;
    // `seq` is an option of u64, not a bare u64.
    let seq = *data.get(at).ok_or(BidError::BadAccount)?;
    at += 1;
    if seq == 1 {
        at = at.checked_add(8).ok_or(BidError::BadAccount)?;
    } else if seq != 0 {
        return Err(BidError::BadAccount);
    }
    scan_plugins(data, at)?;
    Ok(collection)
}

fn read_core_collection(data: &[u8]) -> Result<(), BidError> {
    if data.first() != Some(&KEY_COLLECTION) || data.len() < 33 {
        return Err(BidError::BadAccount);
    }
    let mut at = 33;
    skip_borsh_string(data, &mut at)?;
    skip_borsh_string(data, &mut at)?;
    at = at.checked_add(8).ok_or(BidError::BadAccount)?;
    scan_plugins(data, at)
}

fn scan_plugins(data: &[u8], base_end: usize) -> Result<(), BidError> {
    if base_end == data.len() {
        return Ok(());
    }
    if base_end > data.len() || data.get(base_end) != Some(&KEY_PLUGIN_HEADER) {
        return Err(BidError::CorePluginBlocksTransfer);
    }
    let offset_bytes = data.get(base_end + 1..base_end + 9).ok_or(BidError::BadAccount)?;
    let mut offset_arr = [0u8; 8];
    offset_arr.copy_from_slice(offset_bytes);
    let registry_at = u64::from_le_bytes(offset_arr) as usize;
    let header_end = base_end + 9;
    if registry_at < header_end || data.get(registry_at) != Some(&KEY_PLUGIN_REGISTRY) {
        return Err(BidError::CorePluginBlocksTransfer);
    }
    let mut at = registry_at + 1;
    let count = read_u32(data, &mut at)?;
    if count > MAX_PLUGINS {
        return Err(BidError::CorePluginBlocksTransfer);
    }
    for _ in 0..count {
        let kind = *data.get(at).ok_or(BidError::BadAccount)?;
        at += 1;
        at = skip_plugin_authority(data, at)?;
        let offset = read_u64_at(data, at)?;
        at = at.checked_add(8).ok_or(BidError::BadAccount)?;
        if at > data.len() {
            return Err(BidError::BadAccount);
        }
        // Royalties and transfer delegates do not stop TransferV1 by the owner.
        // Freeze plugins stop it only when the stored `frozen` byte is set.
        if freeze_plugin_is_frozen(data, kind, offset)? {
            return Err(BidError::CorePluginBlocksTransfer);
        }
    }
    let external = read_u32(data, &mut at)?;
    // An external adapter can reject the transfer. This pass does not execute those checks.
    if external != 0 {
        return Err(BidError::CorePluginBlocksTransfer);
    }
    Ok(())
}

fn freeze_plugin_is_frozen(data: &[u8], kind: u8, offset: u64) -> Result<bool, BidError> {
    if !matches!(
        kind,
        PLUGIN_FREEZE | PLUGIN_PERM_FREEZE | PLUGIN_FREEZE_EXECUTE | PLUGIN_PERM_FREEZE_EXECUTE
    ) {
        return Ok(false);
    }
    let at = usize::try_from(offset).map_err(|_| BidError::CorePluginBlocksTransfer)?;
    // The registry offset points at the plugin type. The next byte is `frozen`.
    if data.get(at) != Some(&kind) {
        return Err(BidError::CorePluginBlocksTransfer);
    }
    let frozen_at = at.checked_add(1).ok_or(BidError::CorePluginBlocksTransfer)?;
    match data.get(frozen_at) {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(BidError::CorePluginBlocksTransfer),
    }
}

fn skip_plugin_authority(data: &[u8], at: usize) -> Result<usize, BidError> {
    match data.get(at).copied() {
        Some(0 | 1 | 2) => Ok(at + 1),
        Some(3) => at.checked_add(33).ok_or(BidError::BadAccount),
        _ => Err(BidError::BadAccount),
    }
}

fn skip_borsh_string(data: &[u8], at: &mut usize) -> Result<(), BidError> {
    let len = read_u32(data, at)? as usize;
    if len > MAX_STRING {
        return Err(BidError::BadAccount);
    }
    *at = at.checked_add(len).ok_or(BidError::BadAccount)?;
    if *at > data.len() {
        return Err(BidError::BadAccount);
    }
    Ok(())
}

fn skip_option_byte(data: &[u8], at: &mut usize) -> Result<(), BidError> {
    match data.get(*at).copied() {
        Some(0) => {
            *at += 1;
            Ok(())
        }
        Some(1) => {
            *at = at.checked_add(2).ok_or(BidError::BadAccount)?;
            if *at > data.len() {
                return Err(BidError::BadAccount);
            }
            Ok(())
        }
        _ => Err(BidError::BadAccount),
    }
}

fn read_u32(data: &[u8], at: &mut usize) -> Result<u32, BidError> {
    let bytes = data.get(*at..*at + 4).ok_or(BidError::BadAccount)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    *at += 4;
    Ok(u32::from_le_bytes(arr))
}

fn read_u64_at(data: &[u8], at: usize) -> Result<u64, BidError> {
    let bytes = data.get(at..at + 8).ok_or(BidError::BadAccount)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(arr))
}

fn read_pubkey(data: &[u8], at: &mut usize) -> Result<[u8; 32], BidError> {
    let bytes = data.get(*at..*at + 32).ok_or(BidError::BadAccount)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    *at += 32;
    Ok(key)
}
