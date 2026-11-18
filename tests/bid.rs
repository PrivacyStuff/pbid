use pbid::{
    accept_bid, cancel_bid, place_bid, replace_bid, BidError, SwapLeg, BID_ACCEPTED, BID_LOCKED,
    BID_LEN, TAG_LISTING,
    IX_ACCEPT, IX_CANCEL, IX_PLACE, IX_UPDATE, LISTING_LEN, NATIVE_MINT, OFF_BID_AMOUNT,
    OFF_BID_MINT, OFF_BID_STATUS, OFF_STATUS, STATUS_OPEN, STATUS_SOLD,
};

const SELLER: [u8; 32] = [7u8; 32];
const BIDDER: [u8; 32] = [8u8; 32];
const OTHER: [u8; 32] = [6u8; 32];
const LISTING: [u8; 32] = [3u8; 32];
const MINT: [u8; 32] = [9u8; 32];
const NOW: i64 = 10;
const DEADLINE: i64 = 50;

#[test]
fn shipped_error_codes_stay_put() {
    assert_eq!(BidError::NotSigner.code(), 100);
    assert_eq!(BidError::CorePluginBlocksTransfer.code(), 107);
    assert_eq!(BidError::ExtensionBlocksTransfer.code(), 115);
    assert_eq!(BidError::NotOpen.code(), 116);
    assert_eq!(BidError::BidNotLocked.code(), 123);
    assert_eq!(IX_PLACE, 1);
    assert_eq!(IX_UPDATE, 2);
    assert_eq!(IX_CANCEL, 3);
    assert_eq!(IX_ACCEPT, 4);
}

#[test]
fn create_locks_amount_and_mint() {
    let mut bid = [0u8; BID_LEN];
    let mut locked = false;
    place_bid(
        &open_listing(),
        &mut bid,
        &LISTING,
        &BIDDER,
        &MINT,
        40,
        NOW,
        true,
        2,
        &mut |amount, mint| {
            locked = true;
            assert_eq!(amount, 40);
            assert_eq!(mint, &MINT);
            Ok(())
        },
    )
    .unwrap();
    assert!(locked);
    assert_eq!(bid[OFF_BID_STATUS], BID_LOCKED);
    assert_eq!(amount(&bid), 40);
    assert_eq!(&bid[OFF_BID_MINT..OFF_BID_MINT + 32], &MINT);
}

#[test]
fn replace_keeps_the_old_amount_when_settle_fails() {
    let mut bid = locked_bid(25);
    let mut called = false;
    let err = replace_bid(
        &open_listing(),
        &mut bid,
        &BIDDER,
        &MINT,
        80,
        NOW,
        true,
        &mut |_, _| {
            called = true;
            Err(BidError::TransferFailed)
        },
    );
    assert_eq!(err.unwrap_err(), BidError::TransferFailed);
    assert!(called);
    assert_eq!(amount(&bid), 25);
    assert_eq!(bid[OFF_BID_STATUS], BID_LOCKED);
}

#[test]
fn a_second_bidder_cannot_overwrite() {
    let mut bid = locked_bid(25);
    let mut called = false;
    let err = replace_bid(&open_listing(), &mut bid, &OTHER, &MINT, 1, NOW, true, &mut |_, _| {
        called = true;
        Ok(())
    });
    assert_eq!(err.unwrap_err(), BidError::WrongBidder);
    assert!(!called);
    assert_eq!(amount(&bid), 25);

    let mut called = false;
    let err = cancel_bid(&mut bid, &OTHER, true, &mut |_, _| {
        called = true;
        Ok(())
    });
    assert_eq!(err.unwrap_err(), BidError::WrongBidder);
    assert!(!called);
    assert_eq!(amount(&bid), 25);
    assert_eq!(bid[OFF_BID_STATUS], BID_LOCKED);
}

#[test]
fn the_seller_cannot_cancel_someone_elses_bid() {
    let mut bid = locked_bid(25);
    let mut called = false;
    let err = cancel_bid(&mut bid, &SELLER, true, &mut |_, _| {
        called = true;
        Ok(())
    });
    assert_eq!(err.unwrap_err(), BidError::WrongBidder);
    assert!(!called);
    assert_eq!(bid, locked_bid(25));
}

#[test]
fn the_bidder_cancel_returns_the_locked_mint() {
    let mut bid = locked_bid(25);
    let mut released = None;
    cancel_bid(&mut bid, &BIDDER, true, &mut |amount, mint| {
        released = Some((amount, *mint));
        Ok(())
    })
    .unwrap();
    assert_eq!(released, Some((25, MINT)));
    assert_eq!(bid, [0u8; BID_LEN]);
}

#[test]
fn accept_sends_the_nft_to_the_stored_bidder_then_the_funds_to_the_seller() {
    let mut listing = open_listing();
    let mut bid = locked_bid(25);
    let mut order = Vec::new();
    accept_bid(&mut listing, &mut bid, &SELLER, true, NOW, &mut |leg| {
        match leg {
            SwapLeg::Nft(to) => {
                order.push("nft");
                assert_eq!(to, BIDDER);
            }
            SwapLeg::Funds { amount, seller } => {
                order.push("funds");
                assert_eq!(amount, 25);
                assert_eq!(seller, SELLER);
            }
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(order, ["nft", "funds"]);
    assert_eq!(listing[OFF_STATUS], STATUS_SOLD);
    assert_eq!(bid[OFF_BID_STATUS], BID_ACCEPTED);
}

#[test]
fn a_failed_nft_transfer_leaves_the_bid_locked() {
    let mut listing = open_listing();
    let original = locked_bid(25);
    let mut bid = original;
    let mut funds = false;
    let err = accept_bid(&mut listing, &mut bid, &SELLER, true, NOW, &mut |leg| match leg {
        SwapLeg::Nft(_) => Err(BidError::TransferFailed),
        SwapLeg::Funds { .. } => {
            funds = true;
            Ok(())
        }
    });
    assert_eq!(err.unwrap_err(), BidError::TransferFailed);
    assert!(!funds);
    assert_eq!(listing[OFF_STATUS], STATUS_OPEN);
    assert_eq!(bid, original);
}

#[test]
fn a_failed_funds_transfer_does_not_mark_the_listing_sold() {
    let mut listing = open_listing();
    let original = locked_bid(25);
    let mut bid = original;
    let mut nft = false;
    let err = accept_bid(&mut listing, &mut bid, &SELLER, true, NOW, &mut |leg| match leg {
        SwapLeg::Nft(to) => {
            nft = true;
            assert_eq!(to, BIDDER);
            Ok(())
        }
        SwapLeg::Funds { .. } => Err(BidError::TransferFailed),
    });
    assert_eq!(err.unwrap_err(), BidError::TransferFailed);
    assert!(nft);
    assert_eq!(listing[OFF_STATUS], STATUS_OPEN);
    assert_eq!(bid[OFF_BID_STATUS], BID_LOCKED);
    assert_eq!(bid, original);
}

#[test]
fn a_stranger_cannot_accept() {
    let mut listing = open_listing();
    let original = locked_bid(25);
    let mut bid = original;
    let err = accept_bid(&mut listing, &mut bid, &OTHER, true, NOW, &mut |_| Ok(()));
    assert_eq!(err.unwrap_err(), BidError::NotSigner);
    assert_eq!(listing[OFF_STATUS], STATUS_OPEN);
    assert_eq!(bid, original);
}

#[test]
fn sol_mint_is_named_on_the_bid() {
    let mut bid = [0u8; BID_LEN];
    place_bid(
        &open_listing(),
        &mut bid,
        &LISTING,
        &BIDDER,
        &NATIVE_MINT,
        1,
        NOW,
        true,
        1,
        &mut |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(&bid[OFF_BID_MINT..OFF_BID_MINT + 32], &NATIVE_MINT);
}

fn open_listing() -> [u8; LISTING_LEN] {
    let mut data = [0u8; LISTING_LEN];
    data[0] = TAG_LISTING;
    data[OFF_STATUS] = STATUS_OPEN;
    data[2] = 1;
    data[4..36].copy_from_slice(&SELLER);
    data[36..68].copy_from_slice(&[4u8; 32]);
    data[68..76].copy_from_slice(&DEADLINE.to_le_bytes());
    data
}

fn locked_bid(value: u64) -> [u8; BID_LEN] {
    let mut bid = [0u8; BID_LEN];
    place_bid(
        &open_listing(),
        &mut bid,
        &LISTING,
        &BIDDER,
        &MINT,
        value,
        NOW,
        true,
        2,
        &mut |_, _| Ok(()),
    )
    .unwrap();
    bid
}

fn amount(bid: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&bid[OFF_BID_AMOUNT..OFF_BID_AMOUNT + 8]);
    u64::from_le_bytes(bytes)
}
