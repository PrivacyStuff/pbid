//! Note pool transitions on the host, with real Groth16 proofs. The vault total
//! changes only on shield and unshield, a bid account never holds a clear
//! amount, and every spend appends an output and a change note.
//!
//! Needs the proving key from `cargo run --release --example gen_vk`.

use pbid::{
    accept_note, init_pool, open, place_note, prove, proving_key_vk_bytes, random_field, refund_note, seal, shield,
    unshield, view_key, BidError, Exit, Field, Instance, NoteTree, Opening, Outputs, Place, Settle, SpendWitness,
    BID_ACCEPTED, BID_LOCKED, BID_REFUNDED, KIND_BID, LISTING_LEN, MODE_ACCEPT, MODE_BID, MODE_REFUND,
    MODE_UNSHIELD, NOTE_BID_LEN, OFF_ACCEPTED, OFF_NOTE_COMMIT, OFF_NOTE_SEAL, OFF_POOL_DEPOSITED, OFF_POOL_ROOT,
    OFF_STATUS, OFF_VIEW, POOL_LEN, PROOF_LEN, STATUS_OPEN, STATUS_SOLD, TAG_LISTING, TAG_NOTE,
};

const SELLER_SECRET: [u8; 32] = [4u8; 32];
const SELLER: [u8; 32] = [7u8; 32];
const BIDDER: [u8; 32] = [8u8; 32];
const OTHER: [u8; 32] = [6u8; 32];
const LISTING_KEY: [u8; 32] = [3u8; 32];
const MINT: [u8; 32] = [9u8; 32];
const SHIELDED: u64 = 0x0011_2233_4455_6677;
const BID: u64 = 0x0000_0102_0304_0506;
const NOW: i64 = 10;
const DEADLINE: i64 = 50;
const SELLER_AT: usize = 4;
const DEADLINE_AT: usize = 68;
const POOL_BUMP: u8 = 1;
const VAULT_BUMP: u8 = 2;
const BID_BUMP: u8 = 2;
const NONCE: [u8; 12] = [1u8; 12];

/// BN254 scalar modulus, little-endian.
const MODULUS: Field = [
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// Pool bytes and the tree a note holder keeps beside them.
struct Book {
    pool: Vec<u8>,
    tree: NoteTree,
    listing: [u8; LISTING_LEN],
}

/// A spend ready to submit: the public instance and its proof.
#[derive(Clone)]
struct Spend {
    instance: Instance,
    proof: [u8; PROOF_LEN],
    output: Opening,
    change: Opening,
}

impl Book {
    fn new() -> Self {
        let mut pool = vec![0u8; POOL_LEN];
        init_pool(&mut pool, POOL_BUMP, VAULT_BUMP, &MINT).expect("empty pool");
        Self { pool, tree: NoteTree::new(), listing: open_listing() }
    }

    fn shield(&mut self, owner: &[u8; 32], amount: u64) -> (Opening, u32) {
        let opening = Opening::balance(amount, owner, &MINT);
        let (commitment, index) = shield(&mut self.pool, amount, &opening.inner().expect("inner")).expect("shield");
        assert_eq!(commitment, opening.commitment().expect("commitment"));
        assert_eq!(self.tree.append(commitment), index);
        assert_eq!(self.tree.root().expect("root"), root(&self.pool));
        (opening, index)
    }

    fn record(&mut self, spend: &Spend) -> u32 {
        let index = self.tree.append(spend.instance.output);
        self.tree.append(spend.instance.change);
        assert_eq!(self.tree.root().expect("root"), root(&self.pool), "client tree diverged from the pool");
        index
    }

    fn record_exit(&mut self, spend: &Spend) {
        self.tree.append(spend.instance.change);
        assert_eq!(self.tree.root().expect("root"), root(&self.pool), "client tree diverged from the pool");
    }

    #[allow(clippy::too_many_arguments)]
    fn prove(&self, input: &Opening, index: u32, output: Opening, change: Opening, mode: u8, seller: [u8; 32], bound: Field, pub_amount: u64) -> Spend {
        let (siblings, bits) = self.tree.path(index).expect("path");
        let unshield = mode == MODE_UNSHIELD;
        let witness = SpendWitness {
            input: input.clone(),
            output: output.clone(),
            change: change.clone(),
            seller,
            siblings,
            bits,
            auction: if unshield { [0u8; 32] } else { LISTING_KEY },
            mode,
            bound,
            pub_amount,
            old_root: self.tree.root().expect("root"),
        };
        let (proof, instance) = prove(&witness).expect("proof");
        Spend { instance, proof, output, change }
    }

    fn bid_spend(&self, balance: &Opening, index: u32, amount: u64) -> Spend {
        let output = bid_note(amount);
        let change = Opening::balance(balance.amount - amount, &BIDDER, &MINT);
        self.prove(balance, index, output, change, MODE_BID, SELLER, [0u8; 32], 0)
    }

    fn settle_spend(&self, bid: &Opening, index: u32, to: &[u8; 32], mode: u8, seller: [u8; 32]) -> Spend {
        let output = Opening::balance(bid.amount, to, &MINT);
        let change = Opening::balance(0, &BIDDER, &MINT);
        let bound = bid.commitment().expect("commitment");
        self.prove(bid, index, output, change, mode, seller, bound, 0)
    }
}

fn bid_note(amount: u64) -> Opening {
    Opening { amount, blinding: random_field(), secret: random_field(), owner: BIDDER, listing: LISTING_KEY, mint: MINT, kind: KIND_BID }
}

fn sealed_for(note: &Opening) -> [u8; pbid::SEAL_LEN] {
    seal(&view_key(&SELLER_SECRET), note.amount, &note.blinding, &note.secret, &random_field(), &NONCE).expect("seal")
}

fn outputs(spend: &Spend) -> Outputs {
    Outputs { output: spend.instance.output, change: spend.instance.change }
}

fn place<'a>(listing: &'a [u8], spend: &'a Spend, sealed: &'a [u8], fresh: bool) -> Place<'a> {
    Place {
        listing,
        listing_key: &LISTING_KEY,
        bidder: &BIDDER,
        nullifier: &spend.instance.nullifier,
        outputs: outputs(spend),
        seal: sealed,
        proof: &spend.proof,
        now: NOW,
        bidder_signed: true,
        bump: BID_BUMP,
        nullifier_fresh: fresh,
    }
}

fn settle<'a>(spend: &'a Spend, signer: &'a [u8; 32]) -> Settle<'a> {
    Settle {
        listing_key: &LISTING_KEY,
        signer,
        nullifier: &spend.instance.nullifier,
        outputs: outputs(spend),
        proof: &spend.proof,
        signed: true,
        nullifier_fresh: true,
    }
}

/// Shields `SHIELDED` for the bidder and places a `BID` note on the listing.
fn placed_bid(book: &mut Book) -> ([u8; NOTE_BID_LEN], Spend, u32) {
    let (balance, index) = book.shield(&BIDDER, SHIELDED);
    let spend = book.bid_spend(&balance, index, BID);
    let sealed = sealed_for(&spend.output);
    let mut bid = [0u8; NOTE_BID_LEN];
    place_note(&mut bid, &mut book.pool, &place(&book.listing, &spend, &sealed, true)).expect("place");
    let at = book.record(&spend);
    (bid, spend, at)
}

#[test]
fn the_shipped_verifying_key_is_the_prover_key() {
    let live = proving_key_vk_bytes().expect("proving key");
    assert_eq!(live, &include_bytes!("../src/vk.bin")[..]);
}

#[test]
fn the_client_tree_matches_the_pool_frontier() {
    let mut book = Book::new();
    assert_eq!(book.tree.root().expect("root"), root(&book.pool));
    for step in 0..3u64 {
        book.shield(&BIDDER, 10 + step);
    }
    assert_eq!(deposited(&book.pool), 10 + 11 + 12);
}

#[test]
fn a_bid_keeps_its_amount_and_change_private_and_the_seller_reads_it() {
    let mut book = Book::new();
    let (balance, index) = book.shield(&BIDDER, SHIELDED);
    let before = book.pool.clone();
    let spend = book.bid_spend(&balance, index, BID);
    assert_eq!(spend.instance.pub_amount, 0);
    assert_eq!(spend.instance.mode, MODE_BID);
    let sealed = sealed_for(&spend.output);
    let mut bid = [0u8; NOTE_BID_LEN];
    place_note(&mut bid, &mut book.pool, &place(&book.listing, &spend, &sealed, true)).expect("place");
    book.record(&spend);

    assert_eq!(deposited(&book.pool), deposited(&before), "a bid moved no tokens");
    assert_eq!(bid[0], TAG_NOTE);
    assert_eq!(bid[1], BID_LOCKED);
    assert_eq!(&bid[OFF_NOTE_COMMIT..OFF_NOTE_COMMIT + 32], &spend.instance.output);
    for amount in [BID, SHIELDED - BID] {
        let needle = amount.to_le_bytes();
        assert!(bid.windows(8).all(|window| window != needle), "{amount} is readable on the bid account");
        assert!(book.pool.windows(8).all(|window| window != needle), "{amount} is readable on the pool");
    }
    let (opened, blinding, secret) = open(&SELLER_SECRET, &bid[OFF_NOTE_SEAL..]).expect("seller opens");
    assert_eq!((opened, blinding, secret), (BID, spend.output.blinding, spend.output.secret));
    assert_eq!(open(&OTHER, &bid[OFF_NOTE_SEAL..]).unwrap_err(), BidError::BadCiphertext);
}

#[test]
fn a_forged_output_or_change_is_refused_and_leaves_the_pool() {
    let mut book = Book::new();
    let (balance, index) = book.shield(&BIDDER, SHIELDED);
    let spend = book.bid_spend(&balance, index, BID);
    let sealed = sealed_for(&spend.output);
    let before = book.pool.clone();
    for target in [0usize, 1] {
        let mut forged = spend.clone();
        // A field element the circuit did not commit to, still canonical.
        let other = Opening::balance(SHIELDED, &BIDDER, &MINT).commitment().expect("commitment");
        if target == 0 {
            forged.instance.output = other;
        } else {
            forged.instance.change = other;
        }
        let mut bid = [0u8; NOTE_BID_LEN];
        let err = place_note(&mut bid, &mut book.pool, &place(&book.listing, &forged, &sealed, true)).unwrap_err();
        assert_eq!(err, BidError::BadProof);
        assert_eq!(book.pool, before);
        assert_eq!(bid, [0u8; NOTE_BID_LEN]);
    }
}

#[test]
fn a_spent_or_non_canonical_nullifier_is_refused() {
    let mut book = Book::new();
    let (balance, index) = book.shield(&BIDDER, SHIELDED);
    let spend = book.bid_spend(&balance, index, BID);
    let sealed = sealed_for(&spend.output);
    let mut bid = [0u8; NOTE_BID_LEN];
    let err = place_note(&mut bid, &mut book.pool, &place(&book.listing, &spend, &sealed, false)).unwrap_err();
    assert_eq!(err, BidError::NoteSpent);

    let mut shadow = spend.clone();
    shadow.instance.nullifier = add_modulus(&spend.instance.nullifier);
    let err = place_note(&mut bid, &mut book.pool, &place(&book.listing, &shadow, &sealed, true)).unwrap_err();
    assert_eq!(err, BidError::NonCanonical);
}

#[test]
fn only_the_seller_accepts_and_a_failed_transfer_changes_nothing() {
    let mut book = Book::new();
    let (mut bid, placed, at) = placed_bid(&mut book);

    let to_seller = book.settle_spend(&placed.output, at, &SELLER, MODE_ACCEPT, SELLER);
    let err = accept_note(&mut book.listing, &mut bid, &mut book.pool, &settle(&to_seller, &OTHER), NOW, &mut |_| Ok(())).unwrap_err();
    assert_eq!(err, BidError::NotSigner);

    // A proof bound to another seller does not verify for this listing.
    let wrong = book.settle_spend(&placed.output, at, &OTHER, MODE_ACCEPT, OTHER);
    let mut sent = false;
    let err = accept_note(&mut book.listing, &mut bid, &mut book.pool, &settle(&wrong, &SELLER), NOW, &mut |_| {
        sent = true;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(err, BidError::BadProof);
    assert!(!sent);

    let locked = bid;
    let pool = book.pool.clone();
    let err = accept_note(&mut book.listing, &mut bid, &mut book.pool, &settle(&to_seller, &SELLER), NOW, &mut |_| Err(BidError::TransferFailed))
        .unwrap_err();
    assert_eq!(err, BidError::TransferFailed);
    assert_eq!((bid, book.listing[OFF_STATUS]), (locked, STATUS_OPEN));
    assert_eq!(book.pool, pool);

    let mut to = None;
    accept_note(&mut book.listing, &mut bid, &mut book.pool, &settle(&to_seller, &SELLER), NOW, &mut |bidder| {
        to = Some(bidder);
        Ok(())
    })
    .expect("accept");
    book.record(&to_seller);
    assert_eq!(to, Some(BIDDER));
    assert_eq!(book.listing[OFF_STATUS], STATUS_SOLD);
    assert_eq!(&book.listing[OFF_ACCEPTED..OFF_ACCEPTED + 32], &placed.instance.output);
    assert_eq!(bid[1], BID_ACCEPTED);
    assert_eq!(deposited(&book.pool), SHIELDED);

    let refund = book.settle_spend(&placed.output, at, &BIDDER, MODE_REFUND, SELLER);
    let err = refund_note(&book.listing, &mut bid, &mut book.pool, &settle(&refund, &BIDDER)).unwrap_err();
    assert_eq!(err, BidError::BidNotLocked);
}

#[test]
fn a_refund_frees_the_slot_for_a_new_bid_and_unshield_keeps_the_change_shielded() {
    let mut book = Book::new();
    let (mut bid, placed, at) = placed_bid(&mut book);

    let refund = book.settle_spend(&placed.output, at, &BIDDER, MODE_REFUND, SELLER);
    let err = refund_note(&book.listing, &mut bid, &mut book.pool, &settle(&refund, &OTHER)).unwrap_err();
    assert_eq!(err, BidError::WrongBidder);
    assert_eq!(bid[1], BID_LOCKED);
    refund_note(&book.listing, &mut bid, &mut book.pool, &settle(&refund, &BIDDER)).expect("refund");
    let back_at = book.record(&refund);
    assert_eq!(bid[1], BID_REFUNDED);
    assert_eq!(deposited(&book.pool), SHIELDED);

    let seller_try = book.settle_spend(&placed.output, at, &SELLER, MODE_ACCEPT, SELLER);
    let err = accept_note(&mut book.listing, &mut bid, &mut book.pool, &settle(&seller_try, &SELLER), NOW, &mut |_| Ok(())).unwrap_err();
    assert_eq!(err, BidError::BidNotLocked);

    let rebid = book.bid_spend(&refund.output, back_at, BID / 2);
    let sealed = sealed_for(&rebid.output);
    place_note(&mut bid, &mut book.pool, &place(&book.listing, &rebid, &sealed, true)).expect("a refunded slot takes a new bid");
    book.record(&rebid);
    assert_eq!(bid[1], BID_LOCKED);

    let exit_amount = rebid.change.amount / 2;
    let change_at = book.tree.position(&rebid.instance.change).expect("change note");
    let rest = Opening::balance(rebid.change.amount - exit_amount, &BIDDER, &MINT);
    let exit = book.prove(&rebid.change, change_at, Opening::empty(), rest, MODE_UNSHIELD, [0u8; 32], [0u8; 32], exit_amount);
    assert_eq!(exit.instance.output, [0u8; 32]);
    let leave = |owner: &'static [u8; 32], fresh: bool| Exit {
        owner,
        mint: &MINT,
        nullifier: &exit.instance.nullifier,
        change: &exit.instance.change,
        amount: exit_amount,
        proof: &exit.proof,
        owner_signed: true,
        nullifier_fresh: fresh,
    };
    assert_eq!(unshield(&mut book.pool, &leave(&OTHER, true)).unwrap_err(), BidError::BadProof);
    unshield(&mut book.pool, &leave(&BIDDER, true)).expect("unshield");
    book.record_exit(&exit);
    assert_eq!(deposited(&book.pool), SHIELDED - exit_amount);
    assert_eq!(unshield(&mut book.pool, &leave(&BIDDER, false)).unwrap_err(), BidError::NoteSpent);
}

fn open_listing() -> [u8; LISTING_LEN] {
    let mut data = [0u8; LISTING_LEN];
    data[0] = TAG_LISTING;
    data[OFF_STATUS] = STATUS_OPEN;
    data[SELLER_AT..SELLER_AT + 32].copy_from_slice(&SELLER);
    data[DEADLINE_AT..DEADLINE_AT + 8].copy_from_slice(&DEADLINE.to_le_bytes());
    data[OFF_VIEW..OFF_VIEW + 32].copy_from_slice(&view_key(&SELLER_SECRET));
    data
}

fn root(pool: &[u8]) -> Field {
    pool[OFF_POOL_ROOT..OFF_POOL_ROOT + 32].try_into().expect("32 bytes")
}

fn deposited(pool: &[u8]) -> u64 {
    u64::from_le_bytes(pool[OFF_POOL_DEPOSITED..OFF_POOL_DEPOSITED + 8].try_into().expect("8 bytes"))
}

fn add_modulus(value: &Field) -> Field {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(value[index]) + u16::from(MODULUS[index]) + carry;
        out[index] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "n + r still fits in 32 bytes");
    out
}
