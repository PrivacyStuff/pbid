//! Bid accounts. Every CPI checks the program id. Status bytes are copied back
//! only after the NFT leg and the funds leg both return.
//!
//! Rent: a bid PDA is created at the rent-exempt minimum for `BID_LEN`. Locked
//! SOL is extra lamports on top of that minimum. A balance under the minimum
//! is `NotRentExempt` and does not change the bid. Closing a bid returns the
//! rent, and any leftover lamports, to the bidder.

use pinocchio::cpi::{invoke_signed, Seed, Signer};
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{AccountView, Address};

use crate::error::BidError;
use crate::processor::{accept_bid, cancel_bid, place_bid, replace_bid, SwapLeg};
use crate::standards::{TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};
use crate::state::{
    BID_IX_LEN, BID_LEN, BID_SEED, IX_ACCEPT, IX_CANCEL, IX_PLACE, IX_UPDATE, LISTING_LEN,
    LISTING_SEED, NATIVE_MINT, OFF_ASSET, OFF_BID_MINT, OFF_BUMP, OFF_STANDARD, PAY_SOL,
    STANDARD_CORE, STANDARD_LEGACY, STANDARD_TOKEN_2022,
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
const CORE_PROGRAM_ID: [u8; 32] = [
    175, 84, 171, 16, 189, 151, 165, 66, 160, 158, 247, 179, 152, 137, 221, 12, 211, 148, 164, 204,
    233, 223, 166, 205, 201, 126, 190, 45, 35, 91, 167, 72,
];

const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
const CLOCK_UNIX: usize = 32;
const SPL_TRANSFER: u8 = 3;
const SPL_TRANSFER_CHECKED: u8 = 12;
const SPL_CLOSE: u8 = 9;
const ATA_CREATE_IDEMPOTENT: u8 = 1;
const TRANSFER_V1_DATA: [u8; 2] = [14, 0];
const TOKEN_AMOUNT: usize = 64;
const TOKEN_STATE: usize = 108;
const TOKEN_FROZEN: u8 = 2;

const P_BID: usize = 0;
const P_BIDDER: usize = 1;
const P_LISTING: usize = 2;
const P_SYSTEM: usize = 3;
const P_RENT: usize = 4;
const P_CLOCK: usize = 5;
const P_MINT: usize = 6;
const P_TOKEN: usize = 7;
const P_SOURCE: usize = 8;
const P_ESCROW: usize = 9;
const P_ATA: usize = 10;

const A_LISTING: usize = 0;
const A_SELLER: usize = 1;
const A_BID: usize = 2;
const A_BIDDER: usize = 3;
const A_SYSTEM: usize = 4;
const A_RENT: usize = 5;
const A_CLOCK: usize = 6;
const A_NFT: usize = 7;

pub fn handle(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    match data.first().copied() {
        Some(IX_PLACE) if data.len() == BID_IX_LEN => place(program_id, accounts, data),
        Some(IX_UPDATE) if data.len() == BID_IX_LEN => update(program_id, accounts, data),
        Some(IX_CANCEL) if data.len() == 1 => cancel(program_id, accounts),
        Some(IX_ACCEPT) if data.len() == 1 => accept(program_id, accounts),
        _ => Err(BidError::BadAccount),
    }
}

fn place(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    let (listing_key, bidder, mint, bump, now) = bid_header(program_id, accounts, true)?;
    let amount = read_amount(data)?;
    let listing = copy_len(&accounts[P_LISTING], LISTING_LEN)?;
    let mut bid = copy_bid(&accounts[P_BID])?;
    place_bid(
        &listing,
        &mut bid,
        &listing_key,
        &bidder,
        &mint,
        amount,
        now,
        true,
        bump,
        &mut |amount, mint| lock_payment(program_id, accounts, amount, mint, &listing_key, &bidder, bump),
    )?;
    write_back(&mut accounts[P_BID], &bid)
}

fn update(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), BidError> {
    let (listing_key, bidder, mint, bump, now) = bid_header(program_id, accounts, false)?;
    let amount = read_amount(data)?;
    let listing = copy_len(&accounts[P_LISTING], LISTING_LEN)?;
    let mut bid = copy_bid(&accounts[P_BID])?;
    same_bid(&bid, &listing_key, &bidder, &mint)?;
    replace_bid(&listing, &mut bid, &bidder, &mint, amount, now, true, &mut |old, new| {
        settle_payment(accounts, old, new, &mint, &listing_key, &bidder, bump)
    })?;
    write_back(&mut accounts[P_BID], &bid)
}

fn cancel(program_id: &Address, accounts: &mut [AccountView]) -> Result<(), BidError> {
    if accounts.len() != 5 && accounts.len() != 9 {
        return Err(BidError::BadAccount);
    }
    require_signer(&accounts[P_BIDDER])?;
    if accounts[P_SYSTEM].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let bidder = *accounts[P_BIDDER].address().as_array();
    let listing_key = *accounts[P_LISTING].address().as_array();
    let mint = *accounts[P_MINT].address().as_array();
    let (pda, bump) = Address::find_program_address(&[BID_SEED, &listing_key, &bidder], program_id);
    if accounts[P_BID].address() != &pda || !accounts[P_BID].is_writable() {
        return Err(BidError::BadAccount);
    }
    let mut bid = copy_bid(&accounts[P_BID])?;
    same_bid(&bid, &listing_key, &bidder, &mint)?;
    let sol = mint == NATIVE_MINT;
    if sol != (accounts.len() == 5) {
        return Err(BidError::WrongMint);
    }
    cancel_bid(&mut bid, &bidder, true, &mut |amount, mint| {
        release_payment(accounts, amount, mint, &listing_key, &bidder, bump)
    })?;
    // The scratch is cleared only after the funds move. Closing returns rent to the bidder.
    close_into(accounts, P_BID, P_BIDDER)
}

fn accept(program_id: &Address, accounts: &mut [AccountView]) -> Result<(), BidError> {
    if accounts.len() < A_NFT {
        return Err(BidError::BadAccount);
    }
    require_signer(&accounts[A_SELLER])?;
    if !accounts[A_LISTING].is_writable() || !accounts[A_BID].is_writable() {
        return Err(BidError::BadAccount);
    }
    if accounts[A_SYSTEM].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    if accounts[A_RENT].address().as_array() != &RENT_ID || accounts[A_CLOCK].address().as_array() != &CLOCK_ID
    {
        return Err(BidError::BadAccount);
    }
    let now = read_clock(&accounts[A_CLOCK])?;
    let seller = *accounts[A_SELLER].address().as_array();
    let mut listing = copy_len(&accounts[A_LISTING], LISTING_LEN)?;
    let mut bid = copy_bid(&accounts[A_BID])?;
    let asset = pubkey_at(&listing, OFF_ASSET)?;
    let (listing_pda, listing_bump) = Address::find_program_address(&[LISTING_SEED, &asset], program_id);
    if accounts[A_LISTING].address() != &listing_pda || !accounts[A_LISTING].owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    if listing[OFF_BUMP] != listing_bump {
        return Err(BidError::BadAccount);
    }
    let bidder = pubkey_at(&bid, crate::state::OFF_BID_BIDDER)?;
    let (bid_pda, bid_bump) = Address::find_program_address(&[BID_SEED, listing_pda.as_array(), &bidder], program_id);
    if accounts[A_BID].address() != &bid_pda || !accounts[A_BID].owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    // The destination account has to be the bidder stored on the bid. A swapped pubkey stops here.
    if accounts[A_BIDDER].address().as_array() != &bidder {
        return Err(BidError::BadAccount);
    }
    let listing_key = *listing_pda.as_array();
    if pubkey_at(&bid, crate::state::OFF_BID_LISTING)? != listing_key {
        return Err(BidError::BadAccount);
    }
    let standard = listing[OFF_STANDARD];
    accept_bid(&mut listing, &mut bid, &seller, true, now, &mut |leg| match leg {
        SwapLeg::Nft(bidder) => send_nft(accounts, &bidder, &asset, standard, listing_bump),
        SwapLeg::Funds { amount, seller } => {
            if accounts[A_SELLER].address().as_array() != &seller {
                return Err(BidError::NotSigner);
            }
            pay_seller(accounts, amount, &listing_key, &bidder, bid_bump, standard)
        }
    })?;
    write_back(&mut accounts[A_LISTING], &listing)?;
    write_back(&mut accounts[A_BID], &bid)
}

fn bid_header(
    program_id: &Address,
    accounts: &[AccountView],
    creating: bool,
) -> Result<([u8; 32], [u8; 32], [u8; 32], u8, i64), BidError> {
    let sol = accounts.get(P_MINT).map(|account| account.address().as_array() == &NATIVE_MINT).unwrap_or(false);
    let expected = if sol { 7 } else { 11 };
    if accounts.len() != expected {
        return Err(BidError::BadAccount);
    }
    require_signer(&accounts[P_BIDDER])?;
    if !accounts[P_BID].is_writable() {
        return Err(BidError::BadAccount);
    }
    if accounts[P_SYSTEM].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    if accounts[P_RENT].address().as_array() != &RENT_ID || accounts[P_CLOCK].address().as_array() != &CLOCK_ID {
        return Err(BidError::BadAccount);
    }
    if !sol {
        let token_program = payment_program(&accounts[P_TOKEN])?;
        if accounts[P_ATA].address().as_array() != &ATA_PROGRAM_ID {
            return Err(BidError::WrongProgram);
        }
        if !owned(&accounts[P_MINT], &token_program) {
            return Err(BidError::WrongMint);
        }
        // A hook, permanent delegate, or non-transferable mint must not run inside this lock.
        if token_program == TOKEN_2022_PROGRAM_ID {
            let data = accounts[P_MINT].try_borrow().map_err(|_| BidError::BadAccount)?;
            crate::standards::reject_token_2022_extensions(&data)?;
        }
    }
    let listing_bytes = copy_len(&accounts[P_LISTING], LISTING_LEN)?;
    let asset = pubkey_at(&listing_bytes, OFF_ASSET)?;
    let (listing_pda, _) = Address::find_program_address(&[LISTING_SEED, &asset], program_id);
    if accounts[P_LISTING].address() != &listing_pda || !accounts[P_LISTING].owned_by(program_id) {
        return Err(BidError::BadAccount);
    }
    let listing_key = *listing_pda.as_array();
    let bidder = *accounts[P_BIDDER].address().as_array();
    let (bid_pda, bump) = Address::find_program_address(&[BID_SEED, &listing_key, &bidder], program_id);
    if accounts[P_BID].address() != &bid_pda {
        return Err(BidError::BadAccount);
    }
    if creating {
        let empty = accounts[P_BID].data_len() == 0 && owned(&accounts[P_BID], &SYSTEM_PROGRAM_ID);
        let existing = accounts[P_BID].owned_by(program_id) && accounts[P_BID].data_len() == BID_LEN;
        if !empty && !existing {
            return Err(BidError::BadAccount);
        }
    } else if !accounts[P_BID].owned_by(program_id) || accounts[P_BID].data_len() != BID_LEN {
        return Err(BidError::NoBid);
    }
    let mint = *accounts[P_MINT].address().as_array();
    let now = read_clock(&accounts[P_CLOCK])?;
    Ok((listing_key, bidder, mint, bump, now))
}

fn lock_payment(
    program_id: &Address,
    accounts: &mut [AccountView],
    amount: u64,
    mint: &[u8; 32],
    listing: &[u8; 32],
    bidder: &[u8; 32],
    bump: u8,
) -> Result<(), BidError> {
    if accounts[P_BID].data_len() == 0 {
        let rent = rent_of(&accounts[P_RENT], BID_LEN)?;
        create_bid(program_id, accounts, listing, bidder, bump, rent)?;
    }
    let rent = rent_of(&accounts[P_RENT], BID_LEN)?;
    if !accounts[P_BID].owned_by(program_id) || accounts[P_BID].data_len() != BID_LEN || accounts[P_BID].lamports() < rent
    {
        return Err(BidError::NotRentExempt);
    }
    if *mint == NATIVE_MINT {
        system_transfer(accounts, P_BIDDER, P_BID, P_SYSTEM, amount)?;
        // Rent stays put. The locked SOL is the extra balance above it.
        if accounts[P_BID].lamports() < rent.checked_add(amount).ok_or(BidError::NotRentExempt)? {
            return Err(BidError::NotRentExempt);
        }
        return Ok(());
    }
    move_tokens(accounts, amount, false, None)
}

fn settle_payment(
    accounts: &mut [AccountView],
    old: u64,
    new: u64,
    mint: &[u8; 32],
    listing: &[u8; 32],
    bidder: &[u8; 32],
    bump: u8,
) -> Result<(), BidError> {
    if new == old {
        return Ok(());
    }
    if *mint == NATIVE_MINT {
        let rent = rent_of(&accounts[P_RENT], BID_LEN)?;
        if new > old {
            system_transfer(accounts, P_BIDDER, P_BID, P_SYSTEM, new - old)?;
        } else {
            move_lamports_at(accounts, P_BID, P_BIDDER, old - new)?;
        }
        if accounts[P_BID].lamports() < rent {
            return Err(BidError::NotRentExempt);
        }
        return Ok(());
    }
    if new > old {
        move_tokens(accounts, new - old, false, None)
    } else {
        let seeds = bid_seeds(listing, bidder, bump);
        move_tokens(accounts, old - new, true, Some(&seeds))
    }
}

fn release_payment(
    accounts: &mut [AccountView],
    amount: u64,
    mint: &[u8; 32],
    listing: &[u8; 32],
    bidder: &[u8; 32],
    bump: u8,
) -> Result<(), BidError> {
    if *mint == NATIVE_MINT {
        return move_lamports_at(accounts, P_BID, P_BIDDER, amount);
    }
    const TOKEN: usize = 5;
    const ESCROW: usize = 6;
    const DEST: usize = 7;
    const ATA: usize = 8;
    let token_program_id = payment_program(&accounts[TOKEN])?;
    if accounts[ATA].address().as_array() != &ATA_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    if !owned(&accounts[P_MINT], &token_program_id) {
        return Err(BidError::WrongMint);
    }
    if token_program_id == TOKEN_2022_PROGRAM_ID {
        let data = accounts[P_MINT].try_borrow().map_err(|_| BidError::BadAccount)?;
        crate::standards::reject_token_2022_extensions(&data)?;
    }
    let token_program = Address::new_from_array(token_program_id);
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let mint_key = *accounts[P_MINT].address();
    let bid = *accounts[P_BID].address();
    let (escrow, _) = Address::find_program_address(
        &[bid.as_array(), token_program.as_array(), mint_key.as_array()],
        &ata_program,
    );
    let (dest, _) = Address::find_program_address(
        &[bidder, token_program.as_array(), mint_key.as_array()],
        &ata_program,
    );
    if accounts[ESCROW].address() != &escrow || accounts[DEST].address() != &dest {
        return Err(BidError::BadAccount);
    }
    let seeds = bid_seeds(listing, bidder, bump);
    create_ata_at(accounts, P_BIDDER, DEST, P_BIDDER, P_MINT, P_SYSTEM, TOKEN, ATA)?;
    transfer_amount(accounts, ESCROW, DEST, P_BID, P_MINT, TOKEN, amount, true, Some(&seeds))?;
    close_token(accounts, ESCROW, P_BIDDER, P_BID, TOKEN, Some(&seeds))
}

pub(crate) fn send_nft(
    accounts: &mut [AccountView],
    bidder: &[u8; 32],
    asset: &[u8; 32],
    standard: u8,
    listing_bump: u8,
) -> Result<(), BidError> {
    if accounts[A_BIDDER].address().as_array() != bidder {
        return Err(BidError::BadAccount);
    }
    match standard {
        STANDARD_CORE => send_core(accounts, bidder, asset, listing_bump),
        STANDARD_LEGACY | STANDARD_TOKEN_2022 => send_token_nft(accounts, bidder, asset, standard, listing_bump),
        _ => Err(BidError::WrongStandard),
    }
}

fn send_core(
    accounts: &mut [AccountView],
    bidder: &[u8; 32],
    asset: &[u8; 32],
    listing_bump: u8,
) -> Result<(), BidError> {
    if accounts.len() < A_NFT + 3 {
        return Err(BidError::BadAccount);
    }
    if accounts[A_NFT + 1].address().as_array() != &CORE_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    if accounts[A_NFT].address().as_array() != asset || !owned(&accounts[A_NFT], &CORE_PROGRAM_ID) {
        return Err(BidError::WrongStandard);
    }
    let data = accounts[A_NFT].try_borrow().map_err(|_| BidError::BadAccount)?;
    let (owner, collection) = core_owner_collection(&data)?;
    drop(data);
    if owner != *accounts[A_LISTING].address().as_array() {
        return Err(BidError::NotOwner);
    }
    match collection {
        Some(key) => {
            if accounts[A_NFT + 2].address().as_array() != &key || !owned(&accounts[A_NFT + 2], &CORE_PROGRAM_ID) {
                return Err(BidError::WrongStandard);
            }
        }
        None => {
            if accounts[A_NFT + 2].address().as_array() != &CORE_PROGRAM_ID {
                return Err(BidError::BadAccount);
            }
        }
    }
    let core = Address::new_from_array(CORE_PROGRAM_ID);
    let asset_key = *accounts[A_NFT].address();
    let collection_key = *accounts[A_NFT + 2].address();
    let payer = *accounts[A_SELLER].address();
    let authority = *accounts[A_LISTING].address();
    let new_owner = *accounts[A_BIDDER].address();
    if new_owner.as_array() != bidder {
        return Err(BidError::BadAccount);
    }
    let system = Address::new_from_array(SYSTEM_PROGRAM_ID);
    // Authority is the listing PDA, which owns the asset. The payer only funds the Core CPI.
    let metas = [
        InstructionAccount::writable(&asset_key),
        InstructionAccount::readonly(&collection_key),
        InstructionAccount::writable_signer(&payer),
        InstructionAccount::readonly_signer(&authority),
        InstructionAccount::readonly(&new_owner),
        InstructionAccount::readonly(&system),
        InstructionAccount::readonly(&core),
    ];
    let instruction = InstructionView {
        program_id: &core,
        data: &TRANSFER_V1_DATA,
        accounts: &metas,
    };
    let views = [
        &accounts[A_NFT],
        &accounts[A_NFT + 2],
        &accounts[A_SELLER],
        &accounts[A_LISTING],
        &accounts[A_BIDDER],
        &accounts[A_SYSTEM],
        &accounts[A_NFT + 1],
    ];
    let bump_byte = [listing_bump];
    let seeds = [Seed::from(LISTING_SEED), Seed::from(asset), Seed::from(&bump_byte)];
    let signer = Signer::from(&seeds);
    invoke_signed(&instruction, &views, &[signer]).map_err(|_| BidError::TransferFailed)
}

fn send_token_nft(
    accounts: &mut [AccountView],
    bidder: &[u8; 32],
    asset: &[u8; 32],
    standard: u8,
    listing_bump: u8,
) -> Result<(), BidError> {
    if accounts.len() < A_NFT + 5 {
        return Err(BidError::BadAccount);
    }
    let token_id = if standard == STANDARD_TOKEN_2022 {
        TOKEN_2022_PROGRAM_ID
    } else {
        TOKEN_PROGRAM_ID
    };
    if accounts[A_NFT + 3].address().as_array() != &token_id || accounts[A_NFT + 4].address().as_array() != &ATA_PROGRAM_ID
    {
        return Err(BidError::WrongProgram);
    }
    if accounts[A_NFT].address().as_array() != asset || !owned(&accounts[A_NFT], &token_id) {
        return Err(BidError::WrongStandard);
    }
    let token_program = Address::new_from_array(token_id);
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let mint = Address::new_from_array(*asset);
    let listing = *accounts[A_LISTING].address();
    let (source, _) = Address::find_program_address(
        &[listing.as_array(), token_program.as_array(), mint.as_array()],
        &ata_program,
    );
    let (dest, _) = Address::find_program_address(
        &[bidder, token_program.as_array(), mint.as_array()],
        &ata_program,
    );
    if accounts[A_NFT + 1].address() != &source || accounts[A_NFT + 2].address() != &dest {
        return Err(BidError::BadAccount);
    }
    create_ata_at(accounts, A_SELLER, A_NFT + 2, A_BIDDER, A_NFT, A_SYSTEM, A_NFT + 3, A_NFT + 4)?;
    let seeds = listing_seeds(asset, listing_bump);
    transfer_amount(
        accounts,
        A_NFT + 1,
        A_NFT + 2,
        A_LISTING,
        A_NFT,
        A_NFT + 3,
        1,
        standard == STANDARD_TOKEN_2022,
        Some(&seeds),
    )
}

fn pay_seller(
    accounts: &mut [AccountView],
    amount: u64,
    listing: &[u8; 32],
    bidder: &[u8; 32],
    bid_bump: u8,
    standard: u8,
) -> Result<(), BidError> {
    let nft_len: usize = if standard == STANDARD_CORE { 3 } else { 5 };
    let pay = A_NFT + nft_len;
    let mint = pubkey_at_account(&accounts[A_BID])?;
    if mint == NATIVE_MINT {
        if accounts.len() != pay {
            return Err(BidError::BadAccount);
        }
        let rent = rent_of(&accounts[A_RENT], BID_LEN)?;
        move_lamports_at(accounts, A_BID, A_SELLER, amount)?;
        if accounts[A_BID].lamports() < rent {
            return Err(BidError::NotRentExempt);
        }
        return Ok(());
    }
    if accounts.len() != pay + 5 {
        return Err(BidError::BadAccount);
    }
    let token_program_id = payment_program(&accounts[pay + 1])?;
    if accounts[pay].address().as_array() != &mint || !owned(&accounts[pay], &token_program_id) {
        return Err(BidError::WrongMint);
    }
    if accounts[pay + 4].address().as_array() != &ATA_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    if token_program_id == TOKEN_2022_PROGRAM_ID {
        let data = accounts[pay].try_borrow().map_err(|_| BidError::BadAccount)?;
        crate::standards::reject_token_2022_extensions(&data)?;
    }
    let _ = listing;
    let seeds = bid_seeds(listing, bidder, bid_bump);
    // Seller's receive account is derived from the seller signer, not from a free destination.
    let token_program = Address::new_from_array(token_program_id);
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let mint_key = Address::new_from_array(mint);
    let bid = *accounts[A_BID].address();
    let (escrow, _) = Address::find_program_address(
        &[bid.as_array(), token_program.as_array(), mint_key.as_array()],
        &ata_program,
    );
    let seller = *accounts[A_SELLER].address();
    let (dest, _) = Address::find_program_address(
        &[seller.as_array(), token_program.as_array(), mint_key.as_array()],
        &ata_program,
    );
    if accounts[pay + 2].address() != &escrow || accounts[pay + 3].address() != &dest {
        return Err(BidError::BadAccount);
    }
    create_ata_at(accounts, A_SELLER, pay + 3, A_SELLER, pay, A_SYSTEM, pay + 1, pay + 4)?;
    transfer_amount(accounts, pay + 2, pay + 3, A_BID, pay, pay + 1, amount, true, Some(&seeds))
}

struct PdaSeeds {
    bump: [u8; 1],
    left: [u8; 32],
    right: [u8; 32],
    kind: SeedKind,
}

enum SeedKind {
    Bid,
    Listing,
}

fn bid_seeds(listing: &[u8; 32], bidder: &[u8; 32], bump: u8) -> PdaSeeds {
    PdaSeeds {
        bump: [bump],
        left: *listing,
        right: *bidder,
        kind: SeedKind::Bid,
    }
}

fn listing_seeds(asset: &[u8; 32], bump: u8) -> PdaSeeds {
    PdaSeeds {
        bump: [bump],
        left: *asset,
        right: [0u8; 32],
        kind: SeedKind::Listing,
    }
}

/// Place and update use a fixed account list. The escrow is the bid PDA's ATA.
fn move_tokens(
    accounts: &mut [AccountView],
    amount: u64,
    from_escrow: bool,
    seeds: Option<&PdaSeeds>,
) -> Result<(), BidError> {
    let token_program_id = payment_program(&accounts[P_TOKEN])?;
    let token_program_key = Address::new_from_array(token_program_id);
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let mint_key = *accounts[P_MINT].address();
    let escrow_owner = *accounts[P_BID].address();
    let (escrow, _) = Address::find_program_address(
        &[escrow_owner.as_array(), token_program_key.as_array(), mint_key.as_array()],
        &ata_program,
    );
    let bidder = *accounts[P_BIDDER].address();
    let (bidder_ata, _) = Address::find_program_address(
        &[bidder.as_array(), token_program_key.as_array(), mint_key.as_array()],
        &ata_program,
    );
    if accounts[P_ESCROW].address() != &escrow || accounts[P_SOURCE].address() != &bidder_ata {
        return Err(BidError::BadAccount);
    }
    if !from_escrow {
        require_token_owner(&accounts[P_SOURCE], mint_key.as_array(), bidder.as_array(), &token_program_id)?;
    }
    create_ata_at(accounts, P_BIDDER, P_ESCROW, P_BID, P_MINT, P_SYSTEM, P_TOKEN, P_ATA)?;
    if from_escrow {
        transfer_amount(accounts, P_ESCROW, P_SOURCE, P_BID, P_MINT, P_TOKEN, amount, true, seeds)
    } else {
        transfer_amount(accounts, P_SOURCE, P_ESCROW, P_BIDDER, P_MINT, P_TOKEN, amount, true, None)
    }
}

fn require_token_owner(
    account: &AccountView,
    mint: &[u8; 32],
    owner: &[u8; 32],
    token_program: &[u8; 32],
) -> Result<(), BidError> {
    if !owned(account, token_program) {
        return Err(BidError::WrongProgram);
    }
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    if data.len() < TOKEN_AMOUNT + 8 {
        return Err(BidError::BadAccount);
    }
    if data.get(..32) != Some(mint) {
        return Err(BidError::WrongMint);
    }
    if data.get(32..64) != Some(owner) {
        return Err(BidError::NotOwner);
    }
    if data.get(TOKEN_STATE) == Some(&TOKEN_FROZEN) {
        return Err(BidError::TransferFailed);
    }
    Ok(())
}

fn transfer_amount(
    accounts: &mut [AccountView],
    source: usize,
    dest: usize,
    authority: usize,
    mint: usize,
    token_program: usize,
    amount: u64,
    checked: bool,
    seeds: Option<&PdaSeeds>,
) -> Result<(), BidError> {
    let program_bytes = *accounts[token_program].address().as_array();
    if program_bytes != TOKEN_PROGRAM_ID && program_bytes != TOKEN_2022_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let program = Address::new_from_array(program_bytes);
    let source_key = *accounts[source].address();
    let dest_key = *accounts[dest].address();
    let authority_key = *accounts[authority].address();
    let mint_key = *accounts[mint].address();
    if checked {
        let mut data = [0u8; 10];
        data[0] = SPL_TRANSFER_CHECKED;
        data[1..9].copy_from_slice(&amount.to_le_bytes());
        let decimals = mint_decimals(&accounts[mint])?;
        data[9] = decimals;
        let metas = [
            InstructionAccount::writable(&source_key),
            InstructionAccount::readonly(&mint_key),
            InstructionAccount::writable(&dest_key),
            InstructionAccount::readonly_signer(&authority_key),
        ];
        let instruction = InstructionView {
            program_id: &program,
            data: &data,
            accounts: &metas,
        };
        let views = [
            &accounts[source],
            &accounts[mint],
            &accounts[dest],
            &accounts[authority],
        ];
        invoke_with(seeds, &instruction, &views)
    } else {
        let mut data = [0u8; 9];
        data[0] = SPL_TRANSFER;
        data[1..9].copy_from_slice(&amount.to_le_bytes());
        let metas = [
            InstructionAccount::writable(&source_key),
            InstructionAccount::writable(&dest_key),
            InstructionAccount::readonly_signer(&authority_key),
        ];
        let instruction = InstructionView {
            program_id: &program,
            data: &data,
            accounts: &metas,
        };
        let views = [&accounts[source], &accounts[dest], &accounts[authority]];
        invoke_with(seeds, &instruction, &views)
    }
}

fn invoke_with<const N: usize>(
    seeds: Option<&PdaSeeds>,
    instruction: &InstructionView<'_, '_, '_, '_>,
    views: &[&AccountView; N],
) -> Result<(), BidError> {
    match seeds {
        None => invoke_signed(instruction, views, &[]).map_err(|_| BidError::TransferFailed),
        Some(pda) => match pda.kind {
            SeedKind::Bid => {
                let bump = pda.bump;
                let seeds = [
                    Seed::from(BID_SEED),
                    Seed::from(&pda.left),
                    Seed::from(&pda.right),
                    Seed::from(&bump),
                ];
                let signer = Signer::from(&seeds);
                invoke_signed(instruction, views, &[signer]).map_err(|_| BidError::TransferFailed)
            }
            SeedKind::Listing => {
                let bump = pda.bump;
                let seeds = [Seed::from(LISTING_SEED), Seed::from(&pda.left), Seed::from(&bump)];
                let signer = Signer::from(&seeds);
                invoke_signed(instruction, views, &[signer]).map_err(|_| BidError::TransferFailed)
            }
        },
    }
}

fn create_ata_at(
    accounts: &mut [AccountView],
    payer: usize,
    ata: usize,
    owner: usize,
    mint: usize,
    system: usize,
    token_program: usize,
    ata_program_index: usize,
) -> Result<(), BidError> {
    if accounts[ata_program_index].address().as_array() != &ATA_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    if accounts[system].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let program_bytes = *accounts[token_program].address().as_array();
    if program_bytes != TOKEN_PROGRAM_ID && program_bytes != TOKEN_2022_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let data = [ATA_CREATE_IDEMPOTENT];
    let payer_key = *accounts[payer].address();
    let ata_key = *accounts[ata].address();
    let owner_key = *accounts[owner].address();
    let mint_key = *accounts[mint].address();
    let system_key = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let token_key = Address::new_from_array(program_bytes);
    let metas = [
        InstructionAccount::writable_signer(&payer_key),
        InstructionAccount::writable(&ata_key),
        InstructionAccount::readonly(&owner_key),
        InstructionAccount::readonly(&mint_key),
        InstructionAccount::readonly(&system_key),
        InstructionAccount::readonly(&token_key),
    ];
    let instruction = InstructionView {
        program_id: &ata_program,
        data: &data,
        accounts: &metas,
    };
    let views = [
        &accounts[payer],
        &accounts[ata],
        &accounts[owner],
        &accounts[mint],
        &accounts[system],
        &accounts[token_program],
    ];
    invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed)
}

fn close_token(
    accounts: &mut [AccountView],
    token: usize,
    dest: usize,
    owner: usize,
    token_program: usize,
    seeds: Option<&PdaSeeds>,
) -> Result<(), BidError> {
    let program_bytes = *accounts[token_program].address().as_array();
    if program_bytes != TOKEN_PROGRAM_ID && program_bytes != TOKEN_2022_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let program = Address::new_from_array(program_bytes);
    let data = [SPL_CLOSE];
    let token_key = *accounts[token].address();
    let dest_key = *accounts[dest].address();
    let owner_key = *accounts[owner].address();
    let metas = [
        InstructionAccount::writable(&token_key),
        InstructionAccount::writable(&dest_key),
        InstructionAccount::readonly_signer(&owner_key),
    ];
    let instruction = InstructionView {
        program_id: &program,
        data: &data,
        accounts: &metas,
    };
    let views = [&accounts[token], &accounts[dest], &accounts[owner]];
    invoke_with(seeds, &instruction, &views)
}

fn create_bid(
    program_id: &Address,
    accounts: &mut [AccountView],
    listing: &[u8; 32],
    bidder: &[u8; 32],
    bump: u8,
    lamports: u64,
) -> Result<(), BidError> {
    let mut data = [0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&(BID_LEN as u64).to_le_bytes());
    data[20..52].copy_from_slice(program_id.as_array());
    let system = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let bid = *accounts[P_BID].address();
    let payer = *accounts[P_BIDDER].address();
    let metas = [
        InstructionAccount::writable_signer(&payer),
        InstructionAccount::writable_signer(&bid),
    ];
    let instruction = InstructionView {
        program_id: &system,
        data: &data,
        accounts: &metas,
    };
    let bump_byte = [bump];
    let seeds = [
        Seed::from(BID_SEED),
        Seed::from(listing),
        Seed::from(bidder),
        Seed::from(&bump_byte),
    ];
    let signer = Signer::from(&seeds);
    let views = [&accounts[P_BIDDER], &accounts[P_BID]];
    if accounts[P_SYSTEM].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    // Rent is taken from the bidder. A short balance fails before any token or SOL bid is locked.
    invoke_signed(&instruction, &views, &[signer]).map_err(|_| BidError::NotRentExempt)
}

fn system_transfer(
    accounts: &mut [AccountView],
    from: usize,
    to: usize,
    system_index: usize,
    amount: u64,
) -> Result<(), BidError> {
    if accounts[system_index].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let mut data = [0u8; 12];
    data[..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..].copy_from_slice(&amount.to_le_bytes());
    let system = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let from_key = *accounts[from].address();
    let to_key = *accounts[to].address();
    let metas = [
        InstructionAccount::writable_signer(&from_key),
        InstructionAccount::writable(&to_key),
    ];
    let instruction = InstructionView {
        program_id: &system,
        data: &data,
        accounts: &metas,
    };
    let views = [&accounts[from], &accounts[to]];
    invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed)
}

fn move_lamports_at(accounts: &mut [AccountView], from: usize, to: usize, amount: u64) -> Result<(), BidError> {
    if from == to || amount == 0 {
        return Err(BidError::BadAccount);
    }
    let (src, dst) = pair_mut(accounts, from, to)?;
    let left = src.lamports().checked_sub(amount).ok_or(BidError::NotRentExempt)?;
    let right = dst.lamports().checked_add(amount).ok_or(BidError::BadAccount)?;
    src.set_lamports(left);
    dst.set_lamports(right);
    Ok(())
}

fn close_into(accounts: &mut [AccountView], from: usize, to: usize) -> Result<(), BidError> {
    let (src, dst) = pair_mut(accounts, from, to)?;
    let amount = src.lamports();
    let right = dst.lamports().checked_add(amount).ok_or(BidError::BadAccount)?;
    src.set_lamports(0);
    dst.set_lamports(right);
    src.close().map_err(|_| BidError::BadAccount)
}

fn pair_mut(accounts: &mut [AccountView], left: usize, right: usize) -> Result<(&mut AccountView, &mut AccountView), BidError> {
    if left == right || left >= accounts.len() || right >= accounts.len() {
        return Err(BidError::BadAccount);
    }
    if left < right {
        let (head, tail) = accounts.split_at_mut(right);
        Ok((&mut head[left], &mut tail[0]))
    } else {
        let (head, tail) = accounts.split_at_mut(left);
        Ok((&mut tail[0], &mut head[right]))
    }
}

fn same_bid(bid: &[u8], listing: &[u8; 32], bidder: &[u8; 32], mint: &[u8; 32]) -> Result<(), BidError> {
    if pubkey_at(bid, crate::state::OFF_BID_LISTING)? != *listing {
        return Err(BidError::BadAccount);
    }
    if pubkey_at(bid, crate::state::OFF_BID_BIDDER)? != *bidder {
        return Err(BidError::WrongBidder);
    }
    if pubkey_at(bid, OFF_BID_MINT)? != *mint {
        return Err(BidError::WrongMint);
    }
    let pay = *bid.get(crate::state::OFF_BID_PAY).ok_or(BidError::BadAccount)?;
    let expect = if *mint == NATIVE_MINT { PAY_SOL } else { crate::state::PAY_SPL };
    if pay != expect {
        return Err(BidError::WrongMint);
    }
    Ok(())
}

fn copy_bid(account: &AccountView) -> Result<[u8; BID_LEN], BidError> {
    let mut out = [0u8; BID_LEN];
    if account.data_len() == 0 {
        return Ok(out);
    }
    if account.data_len() != BID_LEN {
        return Err(BidError::BadAccount);
    }
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    out.copy_from_slice(&data);
    Ok(out)
}

fn copy_len(account: &AccountView, len: usize) -> Result<[u8; LISTING_LEN], BidError> {
    if len != LISTING_LEN || account.data_len() != LISTING_LEN {
        return Err(BidError::BadAccount);
    }
    let mut out = [0u8; LISTING_LEN];
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    out.copy_from_slice(&data);
    Ok(out)
}

fn write_back(account: &mut AccountView, bytes: &[u8]) -> Result<(), BidError> {
    if account.data_len() != bytes.len() {
        return Err(BidError::BadAccount);
    }
    account.try_borrow_mut().map_err(|_| BidError::BadAccount)?.copy_from_slice(bytes);
    Ok(())
}

fn require_signer(account: &AccountView) -> Result<(), BidError> {
    if account.is_signer() && account.is_writable() {
        Ok(())
    } else {
        Err(BidError::NotSigner)
    }
}

/// SPL Token or Token-2022. Any other program id is refused before a transfer.
fn payment_program(account: &AccountView) -> Result<[u8; 32], BidError> {
    let id = *account.address().as_array();
    if id == TOKEN_PROGRAM_ID || id == TOKEN_2022_PROGRAM_ID {
        Ok(id)
    } else {
        Err(BidError::WrongProgram)
    }
}

fn owned(account: &AccountView, owner: &[u8; 32]) -> bool {
    account.owned_by(&Address::new_from_array(*owner))
}

fn read_clock(account: &AccountView) -> Result<i64, BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    let bytes = data.get(CLOCK_UNIX..CLOCK_UNIX + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(i64::from_le_bytes(sized))
}

fn read_amount(data: &[u8]) -> Result<u64, BidError> {
    let bytes = data.get(1..9).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(sized))
}

fn pubkey_at(data: &[u8], at: usize) -> Result<[u8; 32], BidError> {
    let bytes = data.get(at..at + 32).ok_or(BidError::BadAccount)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}

fn pubkey_at_account(account: &AccountView) -> Result<[u8; 32], BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    pubkey_at(&data, OFF_BID_MINT)
}

fn mint_decimals(account: &AccountView) -> Result<u8, BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    data.get(44).copied().ok_or(BidError::BadAccount)
}

/// `Rent` sysvar bytes. The older layout stores a 2.0 multiplier after the rate.
fn rent_of(account: &AccountView, account_len: usize) -> Result<u64, BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    if data.len() < 8 {
        return Err(BidError::NotRentExempt);
    }
    let mut rate_bytes = [0u8; 8];
    rate_bytes.copy_from_slice(&data[..8]);
    let rate = u64::from_le_bytes(rate_bytes);
    let multiplier = if data.len() >= 16 && data[8..16] == [0, 0, 0, 0, 0, 0, 0, 0x40] {
        2
    } else {
        1
    };
    let bytes = (account_len as u64)
        .checked_add(ACCOUNT_STORAGE_OVERHEAD)
        .ok_or(BidError::NotRentExempt)?;
    bytes
        .checked_mul(rate)
        .and_then(|value| value.checked_mul(multiplier))
        .ok_or(BidError::NotRentExempt)
}

fn core_owner_collection(data: &[u8]) -> Result<([u8; 32], Option<[u8; 32]>), BidError> {
    if data.first() != Some(&1) {
        return Err(BidError::WrongStandard);
    }
    let owner = pubkey_at(data, 1)?;
    let tag = *data.get(33).ok_or(BidError::BadAccount)?;
    let collection = match tag {
        0 | 1 => None,
        2 => Some(pubkey_at(data, 34)?),
        _ => return Err(BidError::BadAccount),
    };
    Ok((owner, collection))
}
