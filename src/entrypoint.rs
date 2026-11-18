//! BPF entrypoint. Ownership and program ids are checked before the CPI.
//! Listing bytes are copied back only after that CPI returns.

use pinocchio::cpi::{invoke_signed, Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{
    default_allocator, nostd_panic_handler, program_entrypoint, AccountView, Address,
    ProgramResult,
};

use crate::error::BidError;
use crate::processor::{commit_open, OpenListing};
use crate::standards::{
    prepare, ListInput, BUBBLEGUM_PROGRAM_ID, CORE_PROGRAM_ID, METADATA_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
};
use crate::state::{
    LockKind, IX_ACCEPT, IX_CANCEL, IX_CANCEL_LISTING, IX_LIST, IX_PLACE, IX_REFUND, IX_SHIELD,
    IX_UNSHIELD, IX_UPDATE, LISTING_LEN, LISTING_SEED, LIST_IX_LEN, BID_IX_LEN, OFF_STATUS,
    STANDARD_COMPRESSED, STANDARD_CORE, STANDARD_LEGACY, STANDARD_PNFT, STANDARD_TOKEN_2022,
    STATUS_OPEN,
};

#[path = "bid_ix.rs"]
mod bid_ix;
#[path = "note_ix.rs"]
mod note_ix;

program_entrypoint!(process_instruction);
default_allocator!();
nostd_panic_handler!();

/// Associated token program `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`.
const ATA_PROGRAM_ID: [u8; 32] = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
];
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];
/// `SysvarRent111111111111111111111111111111111`
const RENT_ID: [u8; 32] = [
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161,
    253, 68, 227, 219, 217, 138, 0, 0, 0, 0,
];
/// `SysvarC1ock11111111111111111111111111111111`
const CLOCK_ID: [u8; 32] = [
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
];
/// Bytes the rent sysvar adds on top of the account data length.
const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
const CLOCK_UNIX: usize = 32;
/// listing, seller, system, rent, clock.
const HEAD: usize = 5;

/// `TransferV1` discriminator 14, then Borsh `None` for the compression proof.
const TRANSFER_V1_DATA: [u8; 2] = [14, 0];
const SPL_TRANSFER: u8 = 3;
const SPL_TRANSFER_CHECKED: u8 = 12;
const ATA_CREATE_IDEMPOTENT: u8 = 1;

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data.first().copied() {
        Some(IX_PLACE | IX_UPDATE) if instruction_data.len() == BID_IX_LEN => {
            return bid_ix::handle(program_id, accounts, instruction_data).map_err(map_error);
        }
        Some(IX_CANCEL | IX_ACCEPT) if instruction_data.len() == 1 => {
            return bid_ix::handle(program_id, accounts, instruction_data).map_err(map_error);
        }
        Some(IX_SHIELD | IX_PLACE | IX_ACCEPT | IX_REFUND | IX_UNSHIELD | IX_CANCEL_LISTING) => {
            return note_ix::handle(program_id, accounts, instruction_data).map_err(map_error);
        }
        Some(IX_LIST) if instruction_data.len() == LIST_IX_LEN => {}
        _ => return Err(ProgramError::InvalidInstructionData),
    }
    let standard = instruction_data[1];
    let mut deadline_bytes = [0u8; 8];
    deadline_bytes.copy_from_slice(
        instruction_data
            .get(2..10)
            .ok_or(ProgramError::InvalidInstructionData)?,
    );
    let deadline = i64::from_le_bytes(deadline_bytes);
    let mut view = [0u8; 32];
    view.copy_from_slice(
        instruction_data
            .get(10..42)
            .ok_or(ProgramError::InvalidInstructionData)?,
    );
    list(program_id, accounts, standard, deadline, view).map_err(map_error)
}

fn list(
    program_id: &Address,
    accounts: &mut [AccountView],
    standard: u8,
    deadline: i64,
    view: [u8; 32],
) -> Result<(), BidError> {
    if accounts.len() < HEAD {
        return Err(BidError::BadAccount);
    }
    let seller_key = *accounts[1].address().as_array();
    if !accounts[1].is_signer() || !accounts[1].is_writable() || !accounts[0].is_writable() {
        return Err(BidError::NotSigner);
    }
    if accounts[2].address().as_array() != &SYSTEM_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    if accounts[3].address().as_array() != &RENT_ID || accounts[4].address().as_array() != &CLOCK_ID
    {
        return Err(BidError::BadAccount);
    }
    // A cNFT is not a token account. Refuse before deriving a listing or reading a mint.
    if standard == STANDARD_COMPRESSED {
        return Err(BidError::CnftProofNotImplemented);
    }
    let now = read_clock(&accounts[4])?;
    let asset_key = *accounts.get(HEAD).ok_or(BidError::BadAccount)?.address().as_array();
    let (pda, bump) = Address::find_program_address(&[LISTING_SEED, &asset_key], program_id);
    if accounts[0].address() != &pda {
        return Err(BidError::BadAccount);
    }

    let mut scratch = [0u8; LISTING_LEN];
    if accounts[0].owned_by(program_id) && accounts[0].data_len() == LISTING_LEN {
        let existing = accounts[0].try_borrow().map_err(|_| BidError::BadAccount)?;
        scratch.copy_from_slice(&existing);
        drop(existing);
        if scratch[OFF_STATUS] == STATUS_OPEN {
            return Err(BidError::AlreadyListed);
        }
    } else if accounts[0].data_len() != 0 || !owned_by_bytes(&accounts[0], &SYSTEM_PROGRAM_ID) {
        return Err(BidError::BadAccount);
    }

    // Classify while the data borrows are alive, then drop them before any CPI.
    let plan = prepare_accounts(accounts, &seller_key, &asset_key, standard, deadline, now)?;

    if accounts[0].data_len() == 0 {
        let rent_data = accounts[3].try_borrow().map_err(|_| BidError::BadAccount)?;
        let rent = rent_minimum(&rent_data)?;
        drop(rent_data);
        create_listing(program_id, accounts, &asset_key, bump, rent)?;
    }
    let rent_data = accounts[3].try_borrow().map_err(|_| BidError::BadAccount)?;
    let rent = rent_minimum(&rent_data)?;
    drop(rent_data);
    if accounts[0].lamports() < rent
        || !accounts[0].owned_by(program_id)
        || accounts[0].data_len() != LISTING_LEN
    {
        return Err(BidError::NotRentExempt);
    }

    match plan.kind {
        LockKind::CoreTransfer => transfer_core(accounts, &pda)?,
        LockKind::SplTransfer => transfer_spl(accounts, &pda, &asset_key, false)?,
        LockKind::Token2022TransferChecked => transfer_spl(accounts, &pda, &asset_key, true)?,
    }
    commit_open(
        &mut scratch,
        &OpenListing {
            seller: seller_key,
            asset: asset_key,
            standard,
            deadline,
            seller_is_signer: true,
            view,
        },
        bump,
    )?;
    accounts[0]
        .try_borrow_mut()
        .map_err(|_| BidError::BadAccount)?
        .copy_from_slice(&scratch);
    Ok(())
}

fn prepare_accounts(
    accounts: &[AccountView],
    seller: &[u8; 32],
    asset: &[u8; 32],
    standard: u8,
    deadline: i64,
    now: i64,
) -> Result<crate::state::Plan, BidError> {
    match standard {
        STANDARD_CORE => {
            if accounts.len() < HEAD + 3 {
                return Err(BidError::BadAccount);
            }
            let core = &accounts[HEAD + 1];
            if core.address().as_array() != &CORE_PROGRAM_ID {
                return Err(BidError::WrongProgram);
            }
            if !accounts[HEAD].is_writable() || !owned_by_bytes(&accounts[HEAD], &CORE_PROGRAM_ID) {
                return Err(BidError::WrongStandard);
            }
            let asset_data = accounts[HEAD].try_borrow().map_err(|_| BidError::BadAccount)?;
            let collection_account = &accounts[HEAD + 2];
            let placeholder = collection_account.address().as_array() == &CORE_PROGRAM_ID;
            if !placeholder && !owned_by_bytes(collection_account, &CORE_PROGRAM_ID) {
                return Err(BidError::WrongStandard);
            }
            let collection_data = if placeholder {
                None
            } else {
                Some(
                    collection_account
                        .try_borrow()
                        .map_err(|_| BidError::BadAccount)?,
                )
            };
            let collection_address = *collection_account.address().as_array();
            prepare(&ListInput {
                seller,
                seller_is_signer: true,
                standard,
                deadline,
                now,
                asset_program: &CORE_PROGRAM_ID,
                asset_data: &asset_data,
                asset_address: asset,
                token_program: None,
                token_data: None,
                metadata_program: None,
                metadata_data: None,
                collection_program: if placeholder { None } else { Some(&CORE_PROGRAM_ID) },
                collection_data: collection_data.as_deref(),
                collection_address: if placeholder {
                    None
                } else {
                    Some(&collection_address)
                },
            })
        }
        STANDARD_LEGACY | STANDARD_PNFT | STANDARD_TOKEN_2022 => {
            if accounts.len() < HEAD + 7 {
                return Err(BidError::BadAccount);
            }
            let expected = if standard == STANDARD_TOKEN_2022 {
                TOKEN_2022_PROGRAM_ID
            } else {
                TOKEN_PROGRAM_ID
            };
            if accounts[HEAD + 4].address().as_array() != &expected {
                return Err(BidError::WrongProgram);
            }
            if accounts[HEAD + 6].address().as_array() != &ATA_PROGRAM_ID {
                return Err(BidError::WrongProgram);
            }
            if !owned_by_bytes(&accounts[HEAD], &expected)
                || !owned_by_bytes(&accounts[HEAD + 1], &expected)
            {
                return Err(BidError::WrongStandard);
            }
            let metadata_is_needed = standard != STANDARD_TOKEN_2022;
            if metadata_is_needed {
                if accounts[HEAD + 5].address().as_array() != &METADATA_PROGRAM_ID {
                    return Err(BidError::WrongProgram);
                }
                let metadata_program = Address::new_from_array(METADATA_PROGRAM_ID);
                let mint = Address::new_from_array(*asset);
                let (metadata_pda, _) = Address::find_program_address(
                    &[b"metadata", metadata_program.as_array(), mint.as_array()],
                    &metadata_program,
                );
                // A stand-in metadata account could claim NonFungible while the real one is a pNFT.
                if accounts[HEAD + 3].address() != &metadata_pda
                    || !accounts[HEAD + 3].owned_by(&metadata_program)
                {
                    return Err(BidError::BadAccount);
                }
            }
            let mint_data = accounts[HEAD].try_borrow().map_err(|_| BidError::BadAccount)?;
            let token_data = accounts[HEAD + 1]
                .try_borrow()
                .map_err(|_| BidError::BadAccount)?;
            let metadata_data = if metadata_is_needed {
                Some(
                    accounts[HEAD + 3]
                        .try_borrow()
                        .map_err(|_| BidError::BadAccount)?,
                )
            } else {
                None
            };
            prepare(&ListInput {
                seller,
                seller_is_signer: true,
                standard,
                deadline,
                now,
                asset_program: &expected,
                asset_data: &mint_data,
                asset_address: asset,
                token_program: Some(&expected),
                token_data: Some(&token_data),
                metadata_program: if metadata_is_needed {
                    Some(&METADATA_PROGRAM_ID)
                } else {
                    None
                },
                metadata_data: metadata_data.as_deref(),
                collection_program: None,
                collection_data: None,
                collection_address: None,
            })
        }
        _ => Err(BidError::WrongStandard),
    }
}

fn owned_by_bytes(account: &AccountView, owner: &[u8; 32]) -> bool {
    account.owned_by(&Address::new_from_array(*owner))
}

fn read_clock(account: &AccountView) -> Result<i64, BidError> {
    let data = account.try_borrow().map_err(|_| BidError::BadAccount)?;
    let bytes = data.get(CLOCK_UNIX..CLOCK_UNIX + 8).ok_or(BidError::BadAccount)?;
    let mut sized = [0u8; 8];
    sized.copy_from_slice(bytes);
    Ok(i64::from_le_bytes(sized))
}

/// The on-chain rent account is either 8 bytes of lamports-per-byte, or the older
/// layout whose next 8 bytes are the 2.0 exemption threshold. The listing must clear it.
fn rent_minimum(data: &[u8]) -> Result<u64, BidError> {
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
    let bytes = (LISTING_LEN as u64)
        .checked_add(ACCOUNT_STORAGE_OVERHEAD)
        .ok_or(BidError::NotRentExempt)?;
    bytes
        .checked_mul(rate)
        .and_then(|value| value.checked_mul(multiplier))
        .ok_or(BidError::NotRentExempt)
}

fn create_listing(
    program_id: &Address,
    accounts: &mut [AccountView],
    asset: &[u8; 32],
    bump: u8,
    lamports: u64,
) -> Result<(), BidError> {
    let mut data = [0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&(LISTING_LEN as u64).to_le_bytes());
    data[20..52].copy_from_slice(program_id.as_array());
    let system = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let listing = *accounts[0].address();
    let seller = *accounts[1].address();
    let metas = [
        InstructionAccount::writable_signer(&seller),
        InstructionAccount::writable_signer(&listing),
    ];
    let instruction = InstructionView {
        program_id: &system,
        data: &data,
        accounts: &metas,
    };
    let bump_byte = [bump];
    let seeds = [
        Seed::from(LISTING_SEED),
        Seed::from(asset),
        Seed::from(&bump_byte),
    ];
    let signer = Signer::from(&seeds);
    let views = [&accounts[1], &accounts[0]];
    // Rent is pulled from the seller into the PDA. A short balance fails here, before the NFT moves.
    invoke_signed(&instruction, &views, &[signer]).map_err(|_| BidError::NotRentExempt)
}

fn transfer_core(accounts: &mut [AccountView], new_owner: &Address) -> Result<(), BidError> {
    if accounts[HEAD + 1].address().as_array() != &CORE_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    let core = Address::new_from_array(CORE_PROGRAM_ID);
    let asset = *accounts[HEAD].address();
    let collection = *accounts[HEAD + 2].address();
    let payer = *accounts[1].address();
    let system = Address::new_from_array(SYSTEM_PROGRAM_ID);
    // Authority and the log wrapper are omitted. Core treats its own program id
    // as None and then resolves the transfer authority from the payer, who is the owner.
    // The update authority only edits attributes. It does not approve this transfer.
    let metas = [
        InstructionAccount::writable(&asset),
        InstructionAccount::readonly(&collection),
        InstructionAccount::writable_signer(&payer),
        InstructionAccount::readonly(&core),
        InstructionAccount::readonly(new_owner),
        InstructionAccount::readonly(&system),
        InstructionAccount::readonly(&core),
    ];
    let instruction = InstructionView {
        program_id: &core,
        data: &TRANSFER_V1_DATA,
        accounts: &metas,
    };
    let views = [
        &accounts[HEAD],
        &accounts[HEAD + 2],
        &accounts[1],
        &accounts[HEAD + 1],
        &accounts[0],
        &accounts[2],
        &accounts[HEAD + 1],
    ];
    invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed)
}

fn transfer_spl(
    accounts: &mut [AccountView],
    listing: &Address,
    mint_key: &[u8; 32],
    token_2022: bool,
) -> Result<(), BidError> {
    let expected = if token_2022 {
        TOKEN_2022_PROGRAM_ID
    } else {
        TOKEN_PROGRAM_ID
    };
    if accounts[HEAD + 4].address().as_array() != &expected
        || accounts[HEAD + 6].address().as_array() != &ATA_PROGRAM_ID
    {
        return Err(BidError::WrongProgram);
    }
    let token_program = Address::new_from_array(expected);
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let mint = Address::new_from_array(*mint_key);
    let (ata, _) = Address::find_program_address(
        &[listing.as_array(), token_program.as_array(), mint.as_array()],
        &ata_program,
    );
    if accounts[HEAD + 2].address() != &ata {
        return Err(BidError::BadAccount);
    }
    if !accounts[HEAD].owned_by(&token_program) || !accounts[HEAD + 1].owned_by(&token_program) {
        return Err(BidError::WrongStandard);
    }
    create_ata(accounts, listing, &mint, &token_program)?;
    let source = *accounts[HEAD + 1].address();
    let dest = *accounts[HEAD + 2].address();
    let seller = *accounts[1].address();
    if token_2022 {
        let mut data = [0u8; 10];
        data[0] = SPL_TRANSFER_CHECKED;
        data[1..9].copy_from_slice(&1u64.to_le_bytes());
        let metas = [
            InstructionAccount::writable(&source),
            InstructionAccount::readonly(&mint),
            InstructionAccount::writable(&dest),
            InstructionAccount::readonly_signer(&seller),
        ];
        let instruction = InstructionView {
            program_id: &token_program,
            data: &data,
            accounts: &metas,
        };
        let views = [
            &accounts[HEAD + 1],
            &accounts[HEAD],
            &accounts[HEAD + 2],
            &accounts[1],
        ];
        invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed)
    } else {
        let mut data = [0u8; 9];
        data[0] = SPL_TRANSFER;
        data[1..9].copy_from_slice(&1u64.to_le_bytes());
        let metas = [
            InstructionAccount::writable(&source),
            InstructionAccount::writable(&dest),
            InstructionAccount::readonly_signer(&seller),
        ];
        let instruction = InstructionView {
            program_id: &token_program,
            data: &data,
            accounts: &metas,
        };
        let views = [&accounts[HEAD + 1], &accounts[HEAD + 2], &accounts[1]];
        invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed)
    }
}

fn create_ata(
    accounts: &mut [AccountView],
    owner: &Address,
    mint: &Address,
    token_program: &Address,
) -> Result<(), BidError> {
    let ata_program = Address::new_from_array(ATA_PROGRAM_ID);
    let ata = *accounts[HEAD + 2].address();
    let payer = *accounts[1].address();
    let system = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let data = [ATA_CREATE_IDEMPOTENT];
    let metas = [
        InstructionAccount::writable_signer(&payer),
        InstructionAccount::writable(&ata),
        InstructionAccount::readonly(owner),
        InstructionAccount::readonly(mint),
        InstructionAccount::readonly(&system),
        InstructionAccount::readonly(token_program),
    ];
    let instruction = InstructionView {
        program_id: &ata_program,
        data: &data,
        accounts: &metas,
    };
    let token_account = if token_program.as_array() == &TOKEN_2022_PROGRAM_ID {
        &accounts[HEAD + 4]
    } else {
        &accounts[HEAD + 4]
    };
    let views = [
        &accounts[1],
        &accounts[HEAD + 2],
        &accounts[0],
        &accounts[HEAD],
        &accounts[2],
        token_account,
    ];
    // The seller already signed the outer transaction. The ATA program checks its own id.
    if accounts[HEAD + 6].address().as_array() != &ATA_PROGRAM_ID {
        return Err(BidError::WrongProgram);
    }
    invoke_signed(&instruction, &views, &[]).map_err(|_| BidError::TransferFailed)
}

fn map_error(error: BidError) -> ProgramError {
    log_bid_error(error);
    ProgramError::Custom(error.code())
}

fn log_bid_error(error: BidError) {
    let message = error.as_str();
    // The bytes are a program static. The syscall copies `len` of them into the log.
    unsafe {
        pinocchio::syscalls::sol_log_(message.as_ptr(), message.len() as u64);
    }
}

// Silence the unused import if a future edit drops the bubblegum constant from this file.
#[allow(dead_code)]
fn _bubblegum_is_not_a_token_account() -> &'static [u8; 32] {
    &BUBBLEGUM_PROGRAM_ID
}
