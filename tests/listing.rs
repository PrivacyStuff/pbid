use pbid::{
    list_nft, BidError, ListInput, LockKind, BUBBLEGUM_PROGRAM_ID, CORE_PROGRAM_ID,
    METADATA_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, LISTING_LEN, OFF_STANDARD,
    OFF_STATUS, STANDARD_COMPRESSED, STANDARD_CORE, STANDARD_LEGACY, STANDARD_PNFT,
    STANDARD_TOKEN_2022, STATUS_OPEN,
};

const SELLER: [u8; 32] = [7u8; 32];
const VIEW: [u8; 32] = [11u8; 32];
const MINT: [u8; 32] = [9u8; 32];
const COLLECTION: [u8; 32] = [4u8; 32];

#[test]
fn dispatches_each_lockable_standard() {
    let core = core_asset(&SELLER, None, None);
    assert_eq!(lock(core_input(&core, None, None)).0.unwrap(), LockKind::CoreTransfer);

    let attributes = core_asset(&SELLER, None, Some(6));
    assert_eq!(
        lock(core_input(&attributes, None, None)).0.unwrap(),
        LockKind::CoreTransfer
    );

    let legacy = legacy_input(0);
    assert_eq!(lock(legacy).0.unwrap(), LockKind::SplTransfer);

    let token22 = token22_input(mint_bytes(), None);
    assert_eq!(lock(token22).0.unwrap(), LockKind::Token2022TransferChecked);
}

#[test]
fn rejects_hook_permanent_delegate_pnft_and_cnft() {
    let hook = token22_input(extension_mint(14, 64, true), None);
    assert_eq!(lock(hook).0.unwrap_err(), BidError::TransferHookRejected);

    let delegate = token22_input(extension_mint(12, 32, true), None);
    assert_eq!(lock(delegate).0.unwrap_err(), BidError::PermanentDelegateRejected);

    let mut called = false;
    let pnft_as_legacy = legacy_input(4);
    let (result, data) = lock_flag(pnft_as_legacy, &mut called);
    assert_eq!(result.unwrap_err(), BidError::WrongStandard);
    assert!(!called);
    assert_eq!(data[OFF_STATUS], 0);

    let claimed = ListInput {
        standard: STANDARD_PNFT,
        ..legacy_input(4)
    };
    assert_eq!(
        lock(claimed).0.unwrap_err(),
        BidError::PnftTransferNotImplemented
    );

    let compressed = ListInput {
        standard: STANDARD_COMPRESSED,
        asset_program: &BUBBLEGUM_PROGRAM_ID,
        asset_data: &[],
        asset_address: &MINT,
        token_program: None,
        token_data: None,
        metadata_program: None,
        metadata_data: None,
        ..base_input()
    };
    let mut called = false;
    let (result, data) = lock_flag(compressed, &mut called);
    assert_eq!(result.unwrap_err(), BidError::CnftProofNotImplemented);
    assert!(!called);
    assert_eq!(data[OFF_STATUS], 0);
}

#[test]
fn wrong_standard_is_not_the_other_cpi() {
    let core = core_asset(&SELLER, None, None);
    let mut claimed_legacy = core_input(&core, None, None);
    claimed_legacy.standard = STANDARD_LEGACY;
    claimed_legacy.asset_program = &CORE_PROGRAM_ID;
    assert_eq!(lock(claimed_legacy).0.unwrap_err(), BidError::WrongStandard);

    let legacy_mint_as_token22 = token22_input(mint_bytes(), None);
    let mut swapped = legacy_mint_as_token22;
    swapped.standard = STANDARD_LEGACY;
    swapped.asset_program = &TOKEN_2022_PROGRAM_ID;
    assert_eq!(lock(swapped).0.unwrap_err(), BidError::WrongStandard);

    let raw_pnft = legacy_input(4);
    assert_eq!(lock(raw_pnft).0.unwrap_err(), BidError::WrongStandard);
}

#[test]
fn failed_transfer_does_not_open_the_listing() {
    let mut called = false;
    let (result, data) = lock_with(legacy_input(0), &mut |kind| {
        called = true;
        assert_eq!(kind, LockKind::SplTransfer);
        Err(BidError::TransferFailed)
    });
    assert!(called);
    assert_eq!(result.unwrap_err(), BidError::TransferFailed);
    assert_eq!(data[OFF_STATUS], 0);
    assert_eq!(data, [0u8; LISTING_LEN]);
}

#[test]
fn royalty_and_transfer_plugins_can_be_listed() {
    assert_eq!(BidError::CorePluginBlocksTransfer.code(), 107);
    assert_eq!(BidError::CorePluginBlocksTransfer.as_str(), "CorePluginBlocksTransfer");
    for kind in [0u8, 3, 7] {
        let asset = core_asset(&SELLER, None, Some(kind));
        let (result, data) = lock(core_input(&asset, None, None));
        assert_eq!(result.unwrap(), LockKind::CoreTransfer);
        assert_eq!(data[OFF_STATUS], STATUS_OPEN);
    }
    let unfrozen = core_with_freeze(&SELLER, 5, 0);
    let (result, data) = lock(core_input(&unfrozen, None, None));
    assert_eq!(result.unwrap(), LockKind::CoreTransfer);
    assert_eq!(data[OFF_STATUS], STATUS_OPEN);

    // The live collection has an unfrozen permanent freeze delegate and a permanent transfer delegate.
    let asset = core_asset(&SELLER, Some(COLLECTION), None);
    let collection = collection_with(&[(5, &[0]), (7, &[]), (8, &[])]);
    let (result, data) = lock(core_input(&asset, Some(&collection), Some(&COLLECTION)));
    assert_eq!(result.unwrap(), LockKind::CoreTransfer);
    assert_eq!(data[OFF_STATUS], STATUS_OPEN);
}

#[test]
fn frozen_core_plugin_does_not_open_the_listing() {
    let asset = core_asset(&SELLER, Some(COLLECTION), None);
    let collection = collection_with(&[(5, &[1])]);
    let mut called = false;
    let (result, data) = lock_flag(
        core_input(&asset, Some(&collection), Some(&COLLECTION)),
        &mut called,
    );
    assert_eq!(result.unwrap_err(), BidError::CorePluginBlocksTransfer);
    assert!(!called);
    assert_eq!(data[OFF_STATUS], 0);

    let mut external = core_asset(&SELLER, None, Some(6));
    let len = external.len();
    external[len - 4..].copy_from_slice(&1u32.to_le_bytes());
    let mut called = false;
    let (result, data) = lock_flag(core_input(&external, None, None), &mut called);
    assert_eq!(result.unwrap_err(), BidError::CorePluginBlocksTransfer);
    assert!(!called);
    assert_eq!(data[OFF_STATUS], 0);
}

#[test]
fn signer_is_required_and_duplicate_is_rejected() {
    let mut input = legacy_input(0);
    input.seller_is_signer = false;
    let mut called = false;
    let (result, data) = lock_flag(input, &mut called);
    assert_eq!(result.unwrap_err(), BidError::NotSigner);
    assert!(!called);
    assert_eq!(data[OFF_STATUS], 0);

    let mut existing = [0u8; LISTING_LEN];
    existing[OFF_STATUS] = STATUS_OPEN;
    existing[OFF_STANDARD] = STANDARD_LEGACY;
    let mut called = false;
    let err = list_nft(&mut existing, &legacy_input(0), &VIEW, 1, &mut |_| {
        called = true;
        Ok(())
    });
    assert_eq!(err.unwrap_err(), BidError::AlreadyListed);
    assert!(!called);
    assert_eq!(existing[OFF_STATUS], STATUS_OPEN);
    assert_eq!(existing[OFF_STANDARD], STANDARD_LEGACY);
}

fn lock(input: ListInput<'_>) -> (Result<LockKind, BidError>, [u8; LISTING_LEN]) {
    let mut called = LockKind::SplTransfer;
    let mut saw = false;
    let mut data = [0u8; LISTING_LEN];
    let result = list_nft(&mut data, &input, &VIEW, 3, &mut |kind| {
        saw = true;
        called = kind;
        Ok(())
    });
    if result.is_err() {
        assert!(!saw);
    }
    (result.map(|_| called), data)
}

fn lock_flag(
    input: ListInput<'_>,
    called: &mut bool,
) -> (Result<(), BidError>, [u8; LISTING_LEN]) {
    lock_with(input, &mut |_| {
        *called = true;
        Ok(())
    })
}

fn lock_with(
    input: ListInput<'_>,
    transfer: &mut dyn FnMut(LockKind) -> Result<(), BidError>,
) -> (Result<(), BidError>, [u8; LISTING_LEN]) {
    let mut data = [0u8; LISTING_LEN];
    let result = list_nft(&mut data, &input, &VIEW, 3, transfer);
    (result, data)
}

fn base_input() -> ListInput<'static> {
    ListInput {
        seller: &SELLER,
        seller_is_signer: true,
        standard: STANDARD_CORE,
        deadline: 50,
        now: 10,
        asset_program: &CORE_PROGRAM_ID,
        asset_data: &[],
        asset_address: &MINT,
        token_program: None,
        token_data: None,
        metadata_program: None,
        metadata_data: None,
        collection_program: None,
        collection_data: None,
        collection_address: None,
    }
}

fn core_input<'a>(
    asset: &'a [u8],
    collection: Option<&'a [u8]>,
    collection_address: Option<&'a [u8; 32]>,
) -> ListInput<'a> {
    ListInput {
        standard: STANDARD_CORE,
        asset_program: &CORE_PROGRAM_ID,
        asset_data: asset,
        asset_address: &MINT,
        collection_program: collection.map(|_| &CORE_PROGRAM_ID),
        collection_data: collection,
        collection_address,
        ..base_input()
    }
}

fn legacy_input(token_standard: u8) -> ListInput<'static> {
    // Leaked so the test input can be 'static. The process ends with the test binary.
    let mint = Box::leak(mint_bytes().into_boxed_slice());
    let token = Box::leak(token_account().into_boxed_slice());
    let metadata = Box::leak(metadata_account(token_standard).into_boxed_slice());
    ListInput {
        standard: STANDARD_LEGACY,
        asset_program: &TOKEN_PROGRAM_ID,
        asset_data: mint,
        asset_address: &MINT,
        token_program: Some(&TOKEN_PROGRAM_ID),
        token_data: Some(token),
        metadata_program: Some(&METADATA_PROGRAM_ID),
        metadata_data: Some(metadata),
        ..base_input()
    }
}

fn token22_input(mint: Vec<u8>, token_standard: Option<u8>) -> ListInput<'static> {
    let _ = token_standard;
    let mint = Box::leak(mint.into_boxed_slice());
    let token = Box::leak(token_account().into_boxed_slice());
    ListInput {
        standard: STANDARD_TOKEN_2022,
        asset_program: &TOKEN_2022_PROGRAM_ID,
        asset_data: mint,
        asset_address: &MINT,
        token_program: Some(&TOKEN_2022_PROGRAM_ID),
        token_data: Some(token),
        ..base_input()
    }
}

fn mint_bytes() -> Vec<u8> {
    let mut data = vec![0u8; 82];
    data[36] = 1;
    data[45] = 1;
    data
}

fn extension_mint(kind: u16, body: usize, nonzero_tail: bool) -> Vec<u8> {
    let mut data = mint_bytes();
    data.resize(166, 0);
    data[165] = 1;
    data.extend(kind.to_le_bytes());
    data.extend((body as u16).to_le_bytes());
    let mut payload = vec![0u8; body];
    if nonzero_tail {
        if let Some(last) = payload.last_mut() {
            *last = 1;
        }
    }
    data.extend(payload);
    data
}

fn token_account() -> Vec<u8> {
    let mut data = vec![0u8; 165];
    data[..32].copy_from_slice(&MINT);
    data[32..64].copy_from_slice(&SELLER);
    data[64] = 1;
    data[108] = 1;
    data
}

fn metadata_account(token_standard: u8) -> Vec<u8> {
    let mut data = vec![4u8];
    data.extend([3u8; 32]);
    data.extend(MINT);
    push_string(&mut data, b"N");
    push_string(&mut data, b"S");
    push_string(&mut data, b"u");
    data.extend(0u16.to_le_bytes());
    data.push(0);
    data.push(0);
    data.push(0);
    data.push(0);
    data.push(1);
    data.push(token_standard);
    data
}

fn core_asset(owner: &[u8; 32], collection: Option<[u8; 32]>, plugin: Option<u8>) -> Vec<u8> {
    let mut data = vec![1u8];
    data.extend(owner);
    match collection {
        None => data.push(0),
        Some(key) => {
            data.push(2);
            data.extend(key);
        }
    }
    push_string(&mut data, b"N");
    push_string(&mut data, b"u");
    data.push(0);
    if let Some(kind) = plugin {
        let header_at = data.len();
        data.push(3);
        let registry_at = header_at + 9;
        data.extend((registry_at as u64).to_le_bytes());
        data.push(4);
        data.extend(1u32.to_le_bytes());
        data.push(kind);
        data.push(0);
        data.extend(0u64.to_le_bytes());
        data.extend(0u32.to_le_bytes());
    }
    data
}

fn core_with_freeze(owner: &[u8; 32], kind: u8, frozen: u8) -> Vec<u8> {
    let mut data = core_asset(owner, None, None);
    append_plugins(&mut data, &[(kind, &[frozen])]);
    data
}

fn collection_with(plugins: &[(u8, &[u8])]) -> Vec<u8> {
    let mut data = collection_bytes(None);
    append_plugins(&mut data, plugins);
    data
}

fn append_plugins(data: &mut Vec<u8>, plugins: &[(u8, &[u8])]) {
    data.push(3);
    let offset_slot = data.len();
    data.extend(0u64.to_le_bytes());
    let registry_at = data.len();
    data[offset_slot..offset_slot + 8].copy_from_slice(&(registry_at as u64).to_le_bytes());
    data.push(4);
    data.extend((plugins.len() as u32).to_le_bytes());
    let records_at = data.len();
    for _ in plugins {
        data.extend([0u8; 10]);
    }
    data.extend(0u32.to_le_bytes());
    for (index, (kind, body)) in plugins.iter().enumerate() {
        let body_at = data.len();
        data.push(*kind);
        data.extend_from_slice(body);
        let rec = records_at + index * 10;
        data[rec] = *kind;
        data[rec + 1] = 0;
        data[rec + 2..rec + 10].copy_from_slice(&(body_at as u64).to_le_bytes());
    }
}

fn collection_bytes(plugin: Option<u8>) -> Vec<u8> {
    let mut data = vec![5u8];
    data.extend([8u8; 32]);
    push_string(&mut data, b"C");
    push_string(&mut data, b"u");
    data.extend(0u32.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    if let Some(kind) = plugin {
        let header_at = data.len();
        data.push(3);
        let registry_at = header_at + 9;
        data.extend((registry_at as u64).to_le_bytes());
        data.push(4);
        data.extend(1u32.to_le_bytes());
        data.push(kind);
        data.push(0);
        data.extend(0u64.to_le_bytes());
        data.extend(0u32.to_le_bytes());
    }
    data
}

fn push_string(data: &mut Vec<u8>, bytes: &[u8]) {
    data.extend((bytes.len() as u32).to_le_bytes());
    data.extend(bytes);
}
