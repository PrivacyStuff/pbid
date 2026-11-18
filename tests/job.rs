//! The prover refuses a job before it builds a proof when the job does not
//! match the pool or the note. These checks keep a wallet from signing an
//! instruction the program would reject, or one bound to a forged tree.

use pbid::job::{hex, run, unhex, Action, Job, JobError, JobResult, Leaf, NoteJson};
use pbid::{commitment_from_inner, NoteTree, KIND_BALANCE, KIND_BID, SHIELD_IX_LEN};

const MINT: [u8; 32] = [9u8; 32];
const OWNER: [u8; 32] = [8u8; 32];
const LISTING: [u8; 32] = [3u8; 32];
const SELLER: [u8; 32] = [7u8; 32];
const SHIELDED: u64 = 1_000;
/// Above the BN254 scalar modulus in its top byte.
const NON_CANONICAL_TOP: u8 = 0xff;
const INNER_AT: std::ops::Range<usize> = 9..41;

fn job(action: Action, leaves: Vec<Leaf>) -> Job {
    let mut tree = NoteTree::new();
    for leaf in &leaves {
        tree.append(commitment_of(leaf));
    }
    Job {
        action,
        mint: hex(&MINT),
        root: Some(hex(&tree.root().expect("root"))),
        leaves,
        amount: None,
        owner: None,
        note: None,
        listing: Some(hex(&LISTING)),
        seller: Some(hex(&SELLER)),
        seller_view: Some(hex(&[5u8; 32])),
    }
}

fn commitment_of(leaf: &Leaf) -> [u8; 32] {
    match leaf {
        Leaf::Shield { amount, inner } => {
            let inner: [u8; 32] = unhex(inner).expect("hex").try_into().expect("32 bytes");
            commitment_from_inner(amount.parse().expect("amount"), &MINT, KIND_BALANCE, &inner).expect("hash")
        }
        Leaf::Commitment { commitment } => unhex(commitment).expect("hex").try_into().expect("32 bytes"),
    }
}

/// A shield job, and the leaf the program appends for it.
fn shielded() -> (NoteJson, Leaf) {
    let (note, leaf, _) = shield_run();
    (note, leaf)
}

fn shield_run() -> (NoteJson, Leaf, String) {
    let mut shield = job(Action::Shield, Vec::new());
    shield.amount = Some(SHIELDED.to_string());
    shield.owner = Some(hex(&OWNER));
    let result: JobResult = run(&shield).expect("shield");
    let data = unhex(&result.data).expect("hex");
    assert_eq!(data.len(), SHIELD_IX_LEN);
    let leaf = Leaf::Shield { amount: SHIELDED.to_string(), inner: hex(&data[INNER_AT]) };
    (result.output.expect("shield note"), leaf, result.data)
}

#[test]
fn a_shield_publishes_the_amount_and_one_hash_and_its_leaf_is_the_note() {
    let (note, leaf, data) = shield_run();
    assert_eq!(hex(&commitment_of(&leaf)), note.commitment);
    assert_eq!(note.amount, SHIELDED.to_string());
    for secret in [&note.secret, &note.blinding, &note.owner] {
        assert!(!data.contains(secret.as_str()), "a shield publishes no note secret and no owner");
    }
}

#[test]
fn a_job_against_another_root_is_refused() {
    let (note, leaf) = shielded();
    let mut place = job(Action::Place, vec![leaf]);
    place.root = Some(hex(&[1u8; 32]));
    place.note = Some(note);
    place.amount = Some("10".to_string());
    assert_eq!(run(&place).unwrap_err(), JobError::StaleTree);
}

#[test]
fn a_note_missing_from_the_tree_is_refused() {
    let (note, _) = shielded();
    let (_, other) = shielded();
    let mut place = job(Action::Place, vec![other]);
    place.note = Some(note);
    place.amount = Some("10".to_string());
    assert_eq!(run(&place).unwrap_err(), JobError::NoteNotInTree);
}

#[test]
fn a_note_has_to_match_the_action_and_its_commitment() {
    let (note, leaf) = shielded();
    let mut accept = job(Action::Accept, vec![leaf.clone()]);
    accept.note = Some(note.clone());
    assert_eq!(run(&accept).unwrap_err(), JobError::WrongNote, "a balance note is not a bid");

    let mut place = job(Action::Place, vec![leaf.clone()]);
    place.amount = Some("10".to_string());
    place.note = Some(NoteJson { kind: KIND_BID, ..note.clone() });
    assert_eq!(run(&place).unwrap_err(), JobError::WrongNote);

    place.note = Some(NoteJson { amount: (SHIELDED * 2).to_string(), ..note.clone() });
    assert_eq!(run(&place).unwrap_err(), JobError::WrongNote, "the amount is bound by the commitment");

    let mut blinding = unhex(&note.blinding).expect("hex");
    blinding[31] = NON_CANONICAL_TOP;
    place.note = Some(NoteJson { blinding: hex(&blinding), ..note });
    assert_eq!(run(&place).unwrap_err(), JobError::BadHex);
}

#[test]
fn an_amount_has_to_be_positive_and_within_the_note() {
    let (note, leaf) = shielded();
    for amount in ["0", "-1", "1.5", "", &(SHIELDED + 1).to_string(), "18446744073709551616"] {
        let mut place = job(Action::Place, vec![leaf.clone()]);
        place.note = Some(note.clone());
        place.amount = Some(amount.to_string());
        assert_eq!(run(&place).unwrap_err(), JobError::BadAmount, "{amount:?}");
    }
}

#[test]
fn a_job_with_an_unknown_field_is_not_parsed() {
    let raw = r#"{"action":"shield","mint":"00","leaves":[],"debug":true}"#;
    assert!(serde_json::from_str::<Job>(raw).is_err());
    let leaf = r#"{"action":"place","mint":"00","root":"00","leaves":[{"kind":"shield","amount":"1","inner":"00","secret":"00"}]}"#;
    assert!(serde_json::from_str::<Job>(leaf).is_err(), "a leaf never carries a secret");
}

#[test]
fn a_spend_without_its_note_or_listing_is_refused() {
    let (note, leaf) = shielded();
    let mut place = job(Action::Place, vec![leaf.clone()]);
    place.amount = Some("10".to_string());
    assert_eq!(run(&place).unwrap_err(), JobError::MissingField);
    place.note = Some(note);
    place.seller_view = None;
    assert_eq!(run(&place).unwrap_err(), JobError::MissingField);
    place.root = None;
    assert_eq!(run(&place).unwrap_err(), JobError::MissingField, "a spend needs the pool root");
}
