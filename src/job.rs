//! Client-side note jobs. A job names an action, the pool leaves, and the note
//! it spends. The result is the exact instruction data the program parses and
//! the openings of every note it creates, so a wallet never packs bytes itself.
//!
//! The leaves have to rebuild the root the caller read from the pool account.
//! A job against a stale or forged tree is refused before any proof is built.

use serde::{Deserialize, Serialize};

use crate::circuit::{prove, random_field, Opening, SpendWitness};
use crate::merkle::NoteTree;
use crate::poseidon::{commitment_from_inner, is_canonical, Field};
use crate::seal::seal;
use crate::state::{
    IX_ACCEPT, IX_PLACE, IX_REFUND, IX_SHIELD, IX_UNSHIELD, KIND_BALANCE, KIND_BID, MODE_ACCEPT, MODE_BID,
    MODE_REFUND, MODE_UNSHIELD, PLACE_IX_LEN, SHIELD_IX_LEN, SPEND_IX_LEN, UNSHIELD_IX_LEN,
};

const NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobError {
    BadHex,
    BadAmount,
    StaleTree,
    NoteNotInTree,
    WrongNote,
    MissingField,
    ProofFailed,
}

impl JobError {
    pub fn as_str(self) -> &'static str {
        match self {
            JobError::BadHex => "A key or note field is not 32 bytes of hex.",
            JobError::BadAmount => "The amount has to be a whole number above zero and within the note.",
            JobError::StaleTree => "The pool leaves do not rebuild the pool root. Reload the pool and try again.",
            JobError::NoteNotInTree => "The note is not in the pool.",
            JobError::WrongNote => "This note cannot be spent by this action.",
            JobError::MissingField => "The job is missing a field this action needs.",
            JobError::ProofFailed => "The proof could not be built.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Shield,
    Place,
    Accept,
    Refund,
    Unshield,
}

/// One pool leaf as an indexer replays it from instruction data.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Leaf {
    /// A shield instruction: the public amount and the published inner hash.
    Shield { amount: String, inner: String },
    /// An output or change commitment from a spend instruction.
    Commitment { commitment: String },
}

/// Everything needed to open a note. Only its holder has the blinding and secret.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoteJson {
    pub amount: String,
    pub blinding: String,
    pub secret: String,
    pub owner: String,
    pub listing: String,
    pub mint: String,
    pub kind: u8,
    pub commitment: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub action: Action,
    pub mint: String,
    /// The root stored in the pool account, read by the caller from chain.
    /// A shield proves nothing against the tree and leaves it out.
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub leaves: Vec<Leaf>,
    /// Shield amount, bid amount, or unshield amount.
    #[serde(default)]
    pub amount: Option<String>,
    /// Shield: the note owner, which can differ from the funding wallet.
    #[serde(default)]
    pub owner: Option<String>,
    /// The note a spend consumes.
    #[serde(default)]
    pub note: Option<NoteJson>,
    #[serde(default)]
    pub listing: Option<String>,
    #[serde(default)]
    pub seller: Option<String>,
    #[serde(default)]
    pub seller_view: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobResult {
    pub action: Action,
    /// Instruction data, ready for the transaction.
    pub data: String,
    /// Seeds the nullifier PDA. Absent for a shield.
    pub nullifier: Option<String>,
    /// The bid, the seller's payment, the refunded balance, or the shield note.
    pub output: Option<NoteJson>,
    pub change: Option<NoteJson>,
}

pub fn run(job: &Job) -> Result<JobResult, JobError> {
    let mint = hex32(&job.mint)?;
    if job.action == Action::Shield {
        return shield_job(job, &mint);
    }
    let tree = rebuild(&job.leaves, &mint)?;
    let root = tree.root().map_err(|_| JobError::ProofFailed)?;
    if root != required(&job.root)? {
        return Err(JobError::StaleTree);
    }
    match job.action {
        Action::Shield => shield_job(job, &mint),
        Action::Place => place_job(job, &tree, &mint),
        Action::Accept => settle_job(job, &tree, &mint, MODE_ACCEPT),
        Action::Refund => settle_job(job, &tree, &mint, MODE_REFUND),
        Action::Unshield => unshield_job(job, &tree, &mint),
    }
}

fn shield_job(job: &Job, mint: &[u8; 32]) -> Result<JobResult, JobError> {
    let amount = positive(job.amount.as_deref())?;
    let owner = hex32(job.owner.as_deref().ok_or(JobError::MissingField)?)?;
    let note = Opening::balance(amount, &owner, mint);
    let inner = note.inner().map_err(|_| JobError::ProofFailed)?;
    let mut data = Vec::with_capacity(SHIELD_IX_LEN);
    data.push(IX_SHIELD);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&inner);
    Ok(JobResult { action: Action::Shield, data: hex(&data), nullifier: None, output: Some(note_json(&note)?), change: None })
}

fn place_job(job: &Job, tree: &NoteTree, mint: &[u8; 32]) -> Result<JobResult, JobError> {
    let (input, index) = held(job, tree, mint, KIND_BALANCE, &[0u8; 32])?;
    let amount = within(job.amount.as_deref(), input.amount)?;
    let listing = required(&job.listing)?;
    let seller = required(&job.seller)?;
    let view = required(&job.seller_view)?;
    let output = Opening {
        amount,
        blinding: random_field(),
        secret: random_field(),
        owner: input.owner,
        listing,
        mint: *mint,
        kind: KIND_BID,
    };
    let change = Opening::balance(input.amount - amount, &input.owner, mint);
    let spend = Spend { input: &input, index, output: &output, change: &change, mode: MODE_BID, seller, listing, bound: [0u8; 32], pub_amount: 0 };
    let (proof, nullifier, output_c, change_c) = spend.prove(tree)?;
    let nonce_source = random_field();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_source[..NONCE_LEN]);
    let sealed = seal(&view, amount, &output.blinding, &output.secret, &random_field(), &nonce).map_err(|_| JobError::ProofFailed)?;
    let mut data = Vec::with_capacity(PLACE_IX_LEN);
    data.push(IX_PLACE);
    data.extend_from_slice(&nullifier);
    data.extend_from_slice(&output_c);
    data.extend_from_slice(&change_c);
    data.extend_from_slice(&sealed);
    data.extend_from_slice(&proof);
    spent(Action::Place, &data, &nullifier, Some(&output), &change)
}

/// Accept pays the seller. Refund returns the amount to the bidder. Both
/// consume the whole bid note, so the change is an empty note for the bidder.
fn settle_job(job: &Job, tree: &NoteTree, mint: &[u8; 32], mode: u8) -> Result<JobResult, JobError> {
    let listing = required(&job.listing)?;
    let seller = required(&job.seller)?;
    let (input, index) = held(job, tree, mint, KIND_BID, &listing)?;
    let to = if mode == MODE_ACCEPT { seller } else { input.owner };
    let output = Opening::balance(input.amount, &to, mint);
    let change = Opening::balance(0, &input.owner, mint);
    let bound = input.commitment().map_err(|_| JobError::ProofFailed)?;
    let spend = Spend { input: &input, index, output: &output, change: &change, mode, seller, listing, bound, pub_amount: 0 };
    let (proof, nullifier, output_c, change_c) = spend.prove(tree)?;
    let tag = if mode == MODE_ACCEPT { IX_ACCEPT } else { IX_REFUND };
    let mut data = Vec::with_capacity(SPEND_IX_LEN);
    data.push(tag);
    data.extend_from_slice(&nullifier);
    data.extend_from_slice(&output_c);
    data.extend_from_slice(&change_c);
    data.extend_from_slice(&proof);
    let action = if mode == MODE_ACCEPT { Action::Accept } else { Action::Refund };
    spent(action, &data, &nullifier, Some(&output), &change)
}

fn unshield_job(job: &Job, tree: &NoteTree, mint: &[u8; 32]) -> Result<JobResult, JobError> {
    let (input, index) = held(job, tree, mint, KIND_BALANCE, &[0u8; 32])?;
    let amount = within(job.amount.as_deref(), input.amount)?;
    let change = Opening::balance(input.amount - amount, &input.owner, mint);
    let empty = Opening::empty();
    let spend = Spend {
        input: &input,
        index,
        output: &empty,
        change: &change,
        mode: MODE_UNSHIELD,
        seller: [0u8; 32],
        listing: [0u8; 32],
        bound: [0u8; 32],
        pub_amount: amount,
    };
    let (proof, nullifier, _, change_c) = spend.prove(tree)?;
    let mut data = Vec::with_capacity(UNSHIELD_IX_LEN);
    data.push(IX_UNSHIELD);
    data.extend_from_slice(&nullifier);
    data.extend_from_slice(&change_c);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&proof);
    spent(Action::Unshield, &data, &nullifier, None, &change)
}

struct Spend<'a> {
    input: &'a Opening,
    index: u32,
    output: &'a Opening,
    change: &'a Opening,
    mode: u8,
    seller: [u8; 32],
    listing: [u8; 32],
    bound: Field,
    pub_amount: u64,
}

impl Spend<'_> {
    fn prove(&self, tree: &NoteTree) -> Result<([u8; crate::state::PROOF_LEN], Field, Field, Field), JobError> {
        let (siblings, bits) = tree.path(self.index).map_err(|_| JobError::NoteNotInTree)?;
        let witness = SpendWitness {
            input: self.input.clone(),
            output: self.output.clone(),
            change: self.change.clone(),
            seller: self.seller,
            siblings,
            bits,
            auction: self.listing,
            mode: self.mode,
            bound: self.bound,
            pub_amount: self.pub_amount,
            old_root: tree.root().map_err(|_| JobError::ProofFailed)?,
        };
        let (proof, instance) = prove(&witness).map_err(|_| JobError::ProofFailed)?;
        Ok((proof, instance.nullifier, instance.output, instance.change))
    }
}

fn spent(action: Action, data: &[u8], nullifier: &Field, output: Option<&Opening>, change: &Opening) -> Result<JobResult, JobError> {
    Ok(JobResult {
        action,
        data: hex(data),
        nullifier: Some(hex(nullifier)),
        output: output.map(note_json).transpose()?,
        change: Some(note_json(change)?),
    })
}

fn rebuild(leaves: &[Leaf], mint: &[u8; 32]) -> Result<NoteTree, JobError> {
    let mut tree = NoteTree::new();
    for leaf in leaves {
        let commitment = match leaf {
            Leaf::Shield { amount, inner } => {
                let amount = positive(Some(amount))?;
                commitment_from_inner(amount, mint, KIND_BALANCE, &field(inner)?).map_err(|_| JobError::BadHex)?
            }
            Leaf::Commitment { commitment } => field(commitment)?,
        };
        tree.append(commitment);
    }
    Ok(tree)
}

/// The job's note, checked against the tree and against what the action spends.
fn held(job: &Job, tree: &NoteTree, mint: &[u8; 32], kind: u8, listing: &[u8; 32]) -> Result<(Opening, u32), JobError> {
    let json = job.note.as_ref().ok_or(JobError::MissingField)?;
    let note = opening_of(json)?;
    if note.mint != *mint || note.kind != kind || note.listing != *listing || note.amount == 0 {
        return Err(JobError::WrongNote);
    }
    let commitment = note.commitment().map_err(|_| JobError::WrongNote)?;
    if field(&json.commitment)? != commitment {
        return Err(JobError::WrongNote);
    }
    let index = tree.position(&commitment).ok_or(JobError::NoteNotInTree)?;
    Ok((note, index))
}

fn opening_of(json: &NoteJson) -> Result<Opening, JobError> {
    Ok(Opening {
        amount: whole(&json.amount)?,
        blinding: field(&json.blinding)?,
        secret: field(&json.secret)?,
        owner: hex32(&json.owner)?,
        listing: hex32(&json.listing)?,
        mint: hex32(&json.mint)?,
        kind: json.kind,
    })
}

fn note_json(note: &Opening) -> Result<NoteJson, JobError> {
    Ok(NoteJson {
        amount: note.amount.to_string(),
        blinding: hex(&note.blinding),
        secret: hex(&note.secret),
        owner: hex(&note.owner),
        listing: hex(&note.listing),
        mint: hex(&note.mint),
        kind: note.kind,
        commitment: hex(&note.commitment().map_err(|_| JobError::ProofFailed)?),
    })
}

fn required(value: &Option<String>) -> Result<[u8; 32], JobError> {
    hex32(value.as_deref().ok_or(JobError::MissingField)?)
}

fn whole(value: &str) -> Result<u64, JobError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(JobError::BadAmount);
    }
    value.parse::<u64>().map_err(|_| JobError::BadAmount)
}

fn positive(value: Option<&str>) -> Result<u64, JobError> {
    match whole(value.ok_or(JobError::MissingField)?)? {
        0 => Err(JobError::BadAmount),
        amount => Ok(amount),
    }
}

fn within(value: Option<&str>, limit: u64) -> Result<u64, JobError> {
    let amount = positive(value)?;
    if amount > limit {
        return Err(JobError::BadAmount);
    }
    Ok(amount)
}

/// A note field has to be below the scalar modulus, or two encodings would open one note.
fn field(value: &str) -> Result<Field, JobError> {
    let bytes = hex32(value)?;
    if !is_canonical(&bytes) {
        return Err(JobError::BadHex);
    }
    Ok(bytes)
}

fn hex32(value: &str) -> Result<[u8; 32], JobError> {
    let bytes = unhex(value)?;
    bytes.as_slice().try_into().map_err(|_| JobError::BadHex)
}

pub fn unhex(value: &str) -> Result<Vec<u8>, JobError> {
    if !value.len().is_multiple_of(2) {
        return Err(JobError::BadHex);
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(byte: u8) -> Result<u8, JobError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(JobError::BadHex),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}
