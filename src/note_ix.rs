//! On-chain accounts for the note pool. Place, accept, and refund do not move
//! tokens. Shield and unshield are the only instructions that do.

use pinocchio::cpi::{invoke_signed, Seed, Signer};
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{AccountView, Address};

use crate::error::BidError;
use crate::notes::{self, accept_note, cancel_listing, place_note, refund_note, shield, unshield, Exit, Outputs, Place, Settle};
use crate::poseidon::{require_canonical, Field};
use crate::standards::{TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};
use crate::state::{
    BID_SEED, IX_ACCEPT, IX_CANCEL_LISTING, IX_PLACE, IX_REFUND, IX_SHIELD, IX_UNSHIELD, LISTING_LEN, LISTING_SEED,
    NOTE_BID_LEN, NULL_SEED, OFF_ASSET, OFF_NOTE_BIDDER, OFF_NOTE_LISTING, OFF_NOTE_MINT, OFF_STANDARD, PLACE_IX_LEN,
    POOL_LEN, POOL_SEED, PROOF_LEN, SEAL_LEN, SHIELD_IX_LEN, SPEND_HEAD, SPEND_IX_LEN, STANDARD_CORE, STANDARD_LEGACY,
    STANDARD_TOKEN_2022, UNSHIELD_IX_LEN,
};

const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];
const RENT_ID: [u8; 32] = [
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161,
    253, 68, 227, 219, 217, 138, 0, 0, 0, 0,
];
const CLOCK_ID: [u8; 32] = [
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
];
const ATA_PROGRAM_ID: [u8; 32] = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
];
const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
const CLOCK_UNIX: usize = 32;
const ATA_CREATE: u8 = 1;
const TOKEN_TRANSFER_CHECKED: u8 = 12;
const TOKEN_AMOUNT_AT: usize = 64;
const MINT_DECIMALS_AT: usize = 44;

const SHIELD_ACCOUNTS: usize = 10;
const PLACE_ACCOUNTS: usize = 8;
const REFUND_ACCOUNTS: usize = 7;
const UNSHIELD_ACCOUNTS: usize = 10;
const CANCEL_ACCOUNTS: usize = 3;
const ACCEPT_HEAD: usize = 7;
const CORE_NFT_ACCOUNTS: usize = 3;
const TOKEN_NFT_ACCOUNTS: usize = 5;

pub fn handle(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    match data.first().copied() {
        Some(IX_SHIELD) if data.len() == SHIELD_IX_LEN => shield_ix(program_id, accounts, data),
        Some(IX_PLACE) if data.len() == PLACE_IX_LEN => place_ix(program_id, accounts, data),
        Some(IX_ACCEPT) if data.len() == SPEND_IX_LEN => accept_ix(program_id, accounts, data),
        Some(IX_REFUND) if data.len() == SPEND_IX_LEN => refund_ix(program_id, accounts, data),
        Some(IX_UNSHIELD) if data.len() == UNSHIELD_IX_LEN => unshield_ix(program_id, accounts, data),
        Some(IX_CANCEL_LISTING) if data.len() == 1 => cancel_ix(program_id, accounts),
        _ => Err(BidError::BadAccount),
    }
}

/// pool, depositor, mint, source, vault, token program, ATA program, system, rent, clock.
fn shield_ix(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    if accounts.len() != SHIELD_ACCOUNTS || !accounts[1].is_signer() {
        return Err(BidError::NotSigner);
    }
    require_system(&accounts[7])?;
    if accounts[8].address().as_array() != &RENT_ID || accounts[6].address().as_array() != &ATA_PROGRAM_ID {
        return Err(BidError::BadAccount);
    }
    let token_program = token_program_id(&accounts[5])?;
    if !accounts[2].owned_by(&Address::new_from_array(token_program)) {
        return Err(BidError::WrongMint);
    }
    let mint = *accounts[2].address().as_array();
    ensure_pool(program_id, accounts, 0, 1, 7, 8, &mint)?;
    let amount = read_u64(data, 1)?;
    let inner = read32(data, 9)?;
    require_canonical(&inner)?;
    move_into_vault(accounts, &mint, &token_program, amount)?;
    let mut pool = copy(accounts, 0, POOL_LEN)?;
    shield(&mut pool, amount, &inner)?;
    write(accounts, 0, &pool)
}

/// bid, bidder, listing, pool, nullifier, system, rent, clock.
fn place_ix(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    if accounts.len() != PLACE_ACCOUNTS || !accounts[1].is_signer() || !accounts[0].is_writable() {
        return Err(BidError::NotSigner);
    }
    require_system(&accounts[5])?;
    if accounts[6].address().as_array() != &RENT_ID || accounts[7].address().as_array() != &CLOCK_ID {
        return Err(BidError::BadAccount);
    }
    let now = clock(&accounts[7])?;
    let listing = copy(accounts, 2, LISTING_LEN)?;
    let listing_key = require_listing(program_id, &accounts[2], &listing)?;
    let bidder = *accounts[1].address().as_array();
    let (bid_pda, bump) = Address::find_program_address(&[BID_SEED, &listing_key, &bidder], program_id);
    if accounts[0].address() != &bid_pda {
        return Err(BidError::BadAccount);
    }
    if accounts[0].data_len() == 0 {
        create_pda(accounts, 1, 0, 5, 6, program_id, NOTE_BID_LEN, &[BID_SEED, &listing_key, &bidder], bump)?;
    }
    if !accounts[0].owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    let pool_mint = pool_mint_of(program_id, &accounts[3])?;
    require_pool(program_id, &accounts[3], &pool_mint)?;
    let parts = SpendParts::parse(data, PLACE_IX_LEN, Some(SEAL_LEN))?;
    let fresh = nullifier_is_fresh(program_id, &accounts[4], &parts.nullifier)?;
    let mut bid = copy_array::<NOTE_BID_LEN>(accounts, 0)?;
    let mut pool = copy(accounts, 3, POOL_LEN)?;
    let seal = &data[SPEND_HEAD..SPEND_HEAD + SEAL_LEN];
    place_note(
        &mut bid,
        &mut pool,
        &Place {
            listing: &listing,
            listing_key: &listing_key,
            bidder: &bidder,
            nullifier: &parts.nullifier,
            outputs: parts.outputs,
            seal,
            proof: parts.proof,
            now,
            bidder_signed: true,
            bump,
            nullifier_fresh: fresh,
        },
    )?;
    create_nullifier(program_id, accounts, 1, 4, 5, 6, &parts.nullifier)?;
    write(accounts, 0, &bid)?;
    write(accounts, 3, &pool)
}

/// listing, seller, bid, bidder, system, rent, clock, NFT accounts, pool, nullifier.
fn accept_ix(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    if accounts.len() < ACCEPT_HEAD + CORE_NFT_ACCOUNTS + 2 || !accounts[1].is_signer() {
        return Err(BidError::NotSigner);
    }
    require_system(&accounts[4])?;
    if accounts[5].address().as_array() != &RENT_ID || accounts[6].address().as_array() != &CLOCK_ID {
        return Err(BidError::BadAccount);
    }
    let now = clock(&accounts[6])?;
    let mut listing = copy(accounts, 0, LISTING_LEN)?;
    let listing_key = require_listing(program_id, &accounts[0], &listing)?;
    let asset = key_at(&listing, OFF_ASSET)?;
    let nft_len = match listing[OFF_STANDARD] {
        STANDARD_CORE => CORE_NFT_ACCOUNTS,
        STANDARD_LEGACY | STANDARD_TOKEN_2022 => TOKEN_NFT_ACCOUNTS,
        _ => return Err(BidError::WrongStandard),
    };
    let pool_at = ACCEPT_HEAD + nft_len;
    if accounts.len() != pool_at + 2 {
        return Err(BidError::BadAccount);
    }
    let mut bid = copy_array::<NOTE_BID_LEN>(accounts, 2)?;
    require_note_bid(program_id, &accounts[2], &bid, &listing_key)?;
    let mint = key_at(&bid, OFF_NOTE_MINT)?;
    require_pool(program_id, &accounts[pool_at], &mint)?;
    let parts = SpendParts::parse(data, SPEND_IX_LEN, None)?;
    let fresh = nullifier_is_fresh(program_id, &accounts[pool_at + 1], &parts.nullifier)?;
    let mut pool = copy(accounts, pool_at, POOL_LEN)?;
    let seller = *accounts[1].address().as_array();
    let standard = listing[OFF_STANDARD];
    let listing_bump = listing[crate::state::OFF_BUMP];
    accept_note(
        &mut listing,
        &mut bid,
        &mut pool,
        &Settle {
            listing_key: &listing_key,
            signer: &seller,
            nullifier: &parts.nullifier,
            outputs: parts.outputs,
            proof: parts.proof,
            signed: true,
            nullifier_fresh: fresh,
        },
        now,
        &mut |bidder| super::bid_ix::send_nft(accounts, &bidder, &asset, standard, listing_bump),
    )?;
    create_nullifier(program_id, accounts, 1, pool_at + 1, 4, 5, &parts.nullifier)?;
    write(accounts, 0, &listing)?;
    write(accounts, 2, &bid)?;
    write(accounts, pool_at, &pool)
}

/// bid, bidder, listing, pool, nullifier, system, rent.
fn refund_ix(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    if accounts.len() != REFUND_ACCOUNTS || !accounts[1].is_signer() {
        return Err(BidError::NotSigner);
    }
    require_system(&accounts[5])?;
    if accounts[6].address().as_array() != &RENT_ID {
        return Err(BidError::BadAccount);
    }
    let listing = copy(accounts, 2, LISTING_LEN)?;
    let listing_key = require_listing(program_id, &accounts[2], &listing)?;
    let bidder = *accounts[1].address().as_array();
    let mut bid = copy_array::<NOTE_BID_LEN>(accounts, 0)?;
    require_note_bid(program_id, &accounts[0], &bid, &listing_key)?;
    require_pool(program_id, &accounts[3], &key_at(&bid, OFF_NOTE_MINT)?)?;
    let parts = SpendParts::parse(data, SPEND_IX_LEN, None)?;
    let fresh = nullifier_is_fresh(program_id, &accounts[4], &parts.nullifier)?;
    let mut pool = copy(accounts, 3, POOL_LEN)?;
    refund_note(
        &listing,
        &mut bid,
        &mut pool,
        &Settle {
            listing_key: &listing_key,
            signer: &bidder,
            nullifier: &parts.nullifier,
            outputs: parts.outputs,
            proof: parts.proof,
            signed: true,
            nullifier_fresh: fresh,
        },
    )?;
    create_nullifier(program_id, accounts, 1, 4, 5, 6, &parts.nullifier)?;
    write(accounts, 0, &bid)?;
    write(accounts, 3, &pool)
}

/// pool, owner, nullifier, mint, vault, destination, token program, ATA program, system, rent.
fn unshield_ix(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    if accounts.len() != UNSHIELD_ACCOUNTS || !accounts[1].is_signer() {
        return Err(BidError::NotSigner);
    }
    require_system(&accounts[8])?;
    if accounts[9].address().as_array() != &RENT_ID || accounts[7].address().as_array() != &ATA_PROGRAM_ID {
        return Err(BidError::BadAccount);
    }
    let token_program = token_program_id(&accounts[6])?;
    let mint = *accounts[3].address().as_array();
    let owner = *accounts[1].address().as_array();
    let pool_bump = require_pool(program_id, &accounts[0], &mint)?;
    let nullifier = read32(data, 1)?;
    let change = read32(data, 33)?;
    require_canonical(&nullifier)?;
    require_canonical(&change)?;
    let amount = read_u64(data, 65)?;
    let proof = &data[73..73 + PROOF_LEN];
    let fresh = nullifier_is_fresh(program_id, &accounts[2], &nullifier)?;
    let mut pool = copy(accounts, 0, POOL_LEN)?;
    unshield(
        &mut pool,
        &Exit {
            owner: &owner,
            mint: &mint,
            nullifier: &nullifier,
            change: &change,
            amount,
            proof,
            owner_signed: true,
            nullifier_fresh: fresh,
        },
    )?;
    move_out_of_vault(accounts, &mint, &token_program, amount, pool_bump)?;
    create_nullifier(program_id, accounts, 1, 2, 8, 9, &nullifier)?;
    write(accounts, 0, &pool)
}

/// listing, seller, clock.
fn cancel_ix(program_id: &Address, accounts: &mut [AccountView]) -> Result<(), BidError> {
    if accounts.len() != CANCEL_ACCOUNTS || !accounts[1].is_signer() {
        return Err(BidError::NotSigner);
    }
    if accounts[2].address().as_array() != &CLOCK_ID {
        return Err(BidError::BadAccount);
    }
    let mut listing = copy(accounts, 0, LISTING_LEN)?;
    require_listing(program_id, &accounts[0], &listing)?;
    cancel_listing(&mut listing, accounts[1].address().as_array(), true, clock(&accounts[2])?)?;
    write(accounts, 0, &listing)
}

struct SpendParts<'a> {
    nullifier: Field,
    outputs: Outputs,
    proof: &'a [u8],
}

impl<'a> SpendParts<'a> {
    fn parse(data: &'a [u8], len: usize, seal: Option<usize>) -> Result<Self, BidError> {
        if data.len() != len {
            return Err(BidError::BadAccount);
        }
        let nullifier = read32(data, 1)?;
        let output = read32(data, 33)?;
        let change = read32(data, 65)?;
        for value in [&nullifier, &output, &change] {
            require_canonical(value)?;
        }
        let proof_at = SPEND_HEAD + seal.unwrap_or(0);
        let proof = data.get(proof_at..proof_at + PROOF_LEN).ok_or(BidError::BadAccount)?;
        Ok(Self { nullifier, outputs: Outputs { output, change }, proof })
    }
}

/// The listing PDA for the asset it stores, owned by this program.
fn require_listing(program_id: &Address, account: &AccountView, listing: &[u8]) -> Result<[u8; 32], BidError> {
    let asset = key_at(listing, OFF_ASSET)?;
    let (pda, _) = Address::find_program_address(&[LISTING_SEED, &asset], program_id);
    if account.address() != &pda || !account.owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    Ok(*pda.as_array())
}

/// A note bid at its own PDA, owned by this program, on this listing.
fn require_note_bid(program_id: &Address, account: &AccountView, bid: &[u8], listing_key: &[u8; 32]) -> Result<(), BidError> {
    if key_at(bid, OFF_NOTE_LISTING)? != *listing_key {
        return Err(BidError::BadAccount);
    }
    let bidder = key_at(bid, OFF_NOTE_BIDDER)?;
    let (pda, _) = Address::find_program_address(&[BID_SEED, listing_key, &bidder], program_id);
    if account.address() != &pda || !account.owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    Ok(())
}

/// The pool PDA for `mint`, owned by this program. Returns its bump.
fn require_pool(program_id: &Address, account: &AccountView, mint: &[u8; 32]) -> Result<u8, BidError> {
    let (pda, bump) = Address::find_program_address(&[POOL_SEED, mint], program_id);
    if account.address() != &pda || !account.owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    Ok(bump)
}

fn ensure_pool(
    program_id: &Address,
    accounts: &mut [AccountView],
    pool: usize,
    payer: usize,
    system: usize,
    rent: usize,
    mint: &[u8; 32],
) -> Result<(), BidError> {
    let (pda, bump) = Address::find_program_address(&[POOL_SEED, mint], program_id);
    if accounts[pool].address() != &pda {
        return Err(BidError::BadAccount);
    }
    if accounts[pool].data_len() == 0 {
        create_pda(accounts, payer, pool, system, rent, program_id, POOL_LEN, &[POOL_SEED, mint], bump)?;
        let mut data = accounts[pool].try_borrow_mut().map_err(|_| BidError::BadAccount)?;
        notes::init_pool(&mut data, bump, 0, mint)?;
    }
    if !accounts[pool].owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    Ok(())
}

fn create_nullifier(
    program_id: &Address,
    accounts: &mut [AccountView],
    payer: usize,
    nullifier_account: usize,
    system: usize,
    rent: usize,
    nullifier: &Field,
) -> Result<(), BidError> {
    if accounts[nullifier_account].data_len() != 0 {
        return Err(BidError::NoteSpent);
    }
    let (pda, bump) = Address::find_program_address(&[NULL_SEED, nullifier], program_id);
    if accounts[nullifier_account].address() != &pda {
        return Err(BidError::BadAccount);
    }
    create_pda(accounts, payer, nullifier_account, system, rent, program_id, 1, &[NULL_SEED, nullifier], bump)?;
    write(accounts, nullifier_account, &[1])
}

fn nullifier_is_fresh(program_id: &Address, account: &AccountView, nullifier: &Field) -> Result<bool, BidError> {
    let (pda, _) = Address::find_program_address(&[NULL_SEED, nullifier], program_id);
    if account.address() != &pda {
        return Err(BidError::BadAccount);
    }
    Ok(account.data_len() == 0 && account.owned_by(&Address::new_from_array(SYSTEM_PROGRAM_ID)))
}

fn pool_mint_of(program_id: &Address, pool: &AccountView) -> Result<[u8; 32], BidError> {
    if !pool.owned_by(program_id) || pool.data_len() != POOL_LEN {
        return Err(BidError::BadAccount);
    }
    let data = pool.try_borrow().map_err(|_| BidError::BadAccount)?;
    key_at(&data, crate::state::OFF_POOL_MINT)
}

/// The vault has to grow by exactly `amount`. A fee or hook on the mint would
/// otherwise credit the pool with tokens it never received.
fn move_into_vault(accounts: &mut [AccountView], mint: &[u8; 32], token_program: &[u8; 32], amount: u64) -> Result<(), BidError> {
    let token = Address::new_from_array(*token_program);
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let mint_key = Address::new_from_array(*mint);
    let pool = *accounts[0].address();
    let (vault, _) = Address::find_program_address(&[pool.as_array(), token.as_array(), mint_key.as_array()], &ata_program);
    if accounts[4].address() != &vault {
        return Err(BidError::BadAccount);
    }
    create_ata(accounts, 1, 4, 0, 2, 7, 5, 6)?;
    let before = token_amount(&accounts[4])?;
    token_transfer(accounts, 3, 4, 1, 2, 5, amount, None)?;
    let after = token_amount(&accounts[4])?;
    if after.checked_sub(before) != Some(amount) {
        return Err(BidError::TransferFailed);
    }
    Ok(())
}

fn move_out_of_vault(
    accounts: &mut [AccountView],
    mint: &[u8; 32],
    token_program: &[u8; 32],
    amount: u64,
    pool_bump: u8,
) -> Result<(), BidError> {
    let token = Address::new_from_array(*token_program);
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let mint_key = Address::new_from_array(*mint);
    let pool = *accounts[0].address();
    let owner = *accounts[1].address();
    let (vault, _) = Address::find_program_address(&[pool.as_array(), token.as_array(), mint_key.as_array()], &ata_program);
    let (dest, _) = Address::find_program_address(&[owner.as_array(), token.as_array(), mint_key.as_array()], &ata_program);
    if accounts[4].address() != &vault || accounts[5].address() != &dest {
        return Err(BidError::BadAccount);
    }
    create_ata(accounts, 1, 5, 1, 3, 8, 6, 7)?;
    token_transfer(accounts, 4, 5, 0, 3, 6, amount, Some((mint, pool_bump)))
}

fn token_amount(account: &AccountView) -> Result<u64, BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    read_u64(&data, TOKEN_AMOUNT_AT)
}

#[allow(clippy::too_many_arguments)]
fn create_ata(
    accounts: &mut [AccountView],
    payer: usize,
    ata: usize,
    owner: usize,
    mint: usize,
    system: usize,
    token: usize,
    ata_program: usize,
) -> Result<(), BidError> {
    if accounts[ata_program].address().as_array() != &ATA_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let program = Address::new_from_array(ATA_PROGRAM_ID);
    let data = [ATA_CREATE];
    let payer_key = *accounts[payer].address();
    let ata_key = *accounts[ata].address();
    let owner_key = *accounts[owner].address();
    let mint_key = *accounts[mint].address();
    let system_key = *accounts[system].address();
    let token_key = *accounts[token].address();
    let metas = [
        InstructionAccount::writable_signer(&payer_key),
        InstructionAccount::writable(&ata_key),
        InstructionAccount::readonly(&owner_key),
        InstructionAccount::readonly(&mint_key),
        InstructionAccount::readonly(&system_key),
        InstructionAccount::readonly(&token_key),
    ];
    let instruction = InstructionView { program_id: &program, data: &data, accounts: &metas };
    let views = [&accounts[payer], &accounts[ata], &accounts[owner], &accounts[mint], &accounts[system], &accounts[token]];
    invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed)
}

#[allow(clippy::too_many_arguments)]
fn token_transfer(
    accounts: &mut [AccountView],
    source: usize,
    dest: usize,
    authority: usize,
    mint: usize,
    token: usize,
    amount: u64,
    pool: Option<(&[u8; 32], u8)>,
) -> Result<(), BidError> {
    let program = *accounts[token].address();
    let mut data = [0u8; 10];
    data[0] = TOKEN_TRANSFER_CHECKED;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    data[9] = mint_decimals(&accounts[mint])?;
    let source_key = *accounts[source].address();
    let mint_key = *accounts[mint].address();
    let dest_key = *accounts[dest].address();
    let authority_key = *accounts[authority].address();
    let metas = [
        InstructionAccount::writable(&source_key),
        InstructionAccount::readonly(&mint_key),
        InstructionAccount::writable(&dest_key),
        InstructionAccount::readonly_signer(&authority_key),
    ];
    let instruction = InstructionView { program_id: &program, data: &data, accounts: &metas };
    let views = [&accounts[source], &accounts[mint], &accounts[dest], &accounts[authority]];
    match pool {
        Some((mint_bytes, bump)) => {
            let bump_byte = [bump];
            let seeds = [Seed::from(POOL_SEED), Seed::from(mint_bytes), Seed::from(&bump_byte)];
            let signer = Signer::from(&seeds);
            invoke_signed(&instruction, &views, &[signer]).map_err(|_| BidError::TransferFailed)
        }
        None => invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed),
    }
}

#[allow(clippy::too_many_arguments)]
fn create_pda(
    accounts: &mut [AccountView],
    payer: usize,
    account: usize,
    system: usize,
    rent: usize,
    program_id: &Address,
    space: usize,
    seeds_in: &[&[u8]],
    bump: u8,
) -> Result<(), BidError> {
    if accounts[system].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let lamports = rent_minimum(&accounts[rent], space)?;
    let mut data = [0u8; 52];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&(space as u64).to_le_bytes());
    data[20..52].copy_from_slice(program_id.as_array());
    let system_key = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let payer_key = *accounts[payer].address();
    let account_key = *accounts[account].address();
    let metas = [InstructionAccount::writable_signer(&payer_key), InstructionAccount::writable_signer(&account_key)];
    let instruction = InstructionView { program_id: &system_key, data: &data, accounts: &metas };
    let bump_byte = [bump];
    let mut seed_refs: alloc::vec::Vec<Seed> = seeds_in.iter().copied().map(Seed::from).collect();
    seed_refs.push(Seed::from(&bump_byte));
    let signer = Signer::from(seed_refs.as_slice());
    let views = [&accounts[payer], &accounts[account]];
    invoke_signed(&instruction, &views, &[signer]).map_err(|_| BidError::NotRentExempt)
}

/// Rent sysvar: lamports per byte-year (u64), then the exemption threshold (f64).
fn rent_minimum(account: &AccountView, space: usize) -> Result<u64, BidError> {
    const THRESHOLD_AT: usize = 8;
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    let rate = read_u64(&data, 0)?;
    let threshold = f64::from_le_bytes(
        data.get(THRESHOLD_AT..THRESHOLD_AT + 8)
            .ok_or(BidError::NotRentExempt)?
            .try_into()
            .map_err(|_| BidError::NotRentExempt)?,
    );
    let bytes = (space as u64).checked_add(ACCOUNT_STORAGE_OVERHEAD).ok_or(BidError::NotRentExempt)?;
    let per_year = bytes.checked_mul(rate).ok_or(BidError::NotRentExempt)?;
    if !(threshold.is_finite() && threshold >= 0.0) {
        return Err(BidError::NotRentExempt);
    }
    Ok((per_year as f64 * threshold) as u64)
}

fn clock(account: &AccountView) -> Result<i64, BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    let bytes = data.get(CLOCK_UNIX..CLOCK_UNIX + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(i64::from_le_bytes(sized))
}

fn copy(accounts: &[AccountView], index: usize, len: usize) -> Result<alloc::vec::Vec<u8>, BidError> {
    let data = accounts[index].try_borrow().map_err(|_| BidError::BadAccount)?;
    if data.len() != len {
        return Err(BidError::BadAccount);
    }
    Ok(data.to_vec())
}

fn copy_array<const N: usize>(accounts: &[AccountView], index: usize) -> Result<[u8; N], BidError> {
    let bytes = copy(accounts, index, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn write(accounts: &mut [AccountView], index: usize, bytes: &[u8]) -> Result<(), BidError> {
    let mut data = accounts[index].try_borrow_mut().map_err(|_| BidError::BadAccount)?;
    if data.len() != bytes.len() {
        return Err(BidError::BadAccount);
    }
    data.copy_from_slice(bytes);
    Ok(())
}

fn key_at(data: &[u8], at: usize) -> Result<[u8; 32], BidError> {
    read32(data, at)
}

fn read32(data: &[u8], at: usize) -> Result<[u8; 32], BidError> {
    let bytes = data.get(at..at + 32).ok_or(BidError::BadAccount)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}

fn read_u64(data: &[u8], at: usize) -> Result<u64, BidError> {
    let bytes = data.get(at..at + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(sized))
}

fn require_system(account: &AccountView) -> Result<(), BidError> {
    if account.address().as_array() != &SYSTEM_PROGRAM_ID {
        Err(BidError::WrongProgram)
    } else {
        Ok(())
    }
}

fn mint_decimals(account: &AccountView) -> Result<u8, BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    data.get(MINT_DECIMALS_AT).copied().ok_or(BidError::BadAccount)
}

fn token_program_id(account: &AccountView) -> Result<[u8; 32], BidError> {
    let id = *account.address().as_array();
    if id == TOKEN_PROGRAM_ID || id == TOKEN_2022_PROGRAM_ID {
        Ok(id)
    } else {
        Err(BidError::WrongProgram)
    }
}
