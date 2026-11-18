//! Groth16 join-split over circom Poseidon. One note goes in; a primary output
//! and a change note come out, and the amounts balance. Public inputs are the
//! fields of `Instance`. Amounts stay witnesses, except an unshield's payout.
//!
//! The proving key is read from disk and the verifying key is `src/vk.bin`.
//! `cargo run --example gen_vk` creates both from OS entropy. Whoever runs that
//! setup could forge proofs, so a production deployment replaces it with a
//! multi-party ceremony and ships only its output.

use std::path::PathBuf;
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::ToBitsGadget;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use light_poseidon::PoseidonParameters;
use rand_core::OsRng;

use crate::error::BidError;
use crate::instance::{Instance, PUBLIC_INPUTS};
use crate::poseidon::{self, limbs, Field, DOM_NULL, DOM_SELLER};
use crate::state::{KIND_BALANCE, KIND_BID, MERKLE_DEPTH, MODE_ACCEPT, MODE_BID, MODE_REFUND, MODE_UNSHIELD, PROOF_LEN};

const SHIPPED_VK: &[u8] = include_bytes!("vk.bin");
const PROVING_KEY_ENV: &str = "PBID_PROVING_KEY";
const PROVING_KEY_DEFAULT: &str = "keys/pbid_pk.bin";
const SBOX: u64 = 5;
const AMOUNT_BITS: usize = 64;
/// Clearing the top three bits keeps a random value below the 254-bit modulus.
const RANDOM_TOP_MASK: u8 = 0x1f;
const MAX_WIDTH: usize = 13;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub amount: u64,
    pub blinding: Field,
    pub secret: Field,
    pub owner: [u8; 32],
    pub listing: [u8; 32],
    pub mint: [u8; 32],
    pub kind: u8,
}

impl Opening {
    pub fn commitment(&self) -> Result<Field, BidError> {
        poseidon::note_commitment(self.amount, &self.blinding, &self.secret, &self.owner, &self.listing, &self.mint, self.kind)
    }

    pub fn inner(&self) -> Result<Field, BidError> {
        poseidon::note_inner(&self.blinding, &self.secret, &self.owner, &self.listing)
    }

    pub fn nullifier(&self) -> Result<Field, BidError> {
        poseidon::nullifier(&self.secret, &self.commitment()?)
    }

    /// A fresh balance note. The blinding and secret come from OS entropy.
    pub fn balance(amount: u64, owner: &[u8; 32], mint: &[u8; 32]) -> Self {
        Self {
            amount,
            blinding: random_field(),
            secret: random_field(),
            owner: *owner,
            listing: [0u8; 32],
            mint: *mint,
            kind: KIND_BALANCE,
        }
    }

    pub fn empty() -> Self {
        Self { amount: 0, blinding: [0u8; 32], secret: [0u8; 32], owner: [0u8; 32], listing: [0u8; 32], mint: [0u8; 32], kind: KIND_BALANCE }
    }
}

#[derive(Clone)]
pub struct SpendWitness {
    pub input: Opening,
    /// Ignored for an unshield, whose public output is zero.
    pub output: Opening,
    /// Always appended. A balance note back to the input owner.
    pub change: Opening,
    pub seller: [u8; 32],
    pub siblings: [Field; MERKLE_DEPTH],
    pub bits: [bool; MERKLE_DEPTH],
    /// The listing a bid, accept, or refund is bound to. Zero for an unshield.
    pub auction: [u8; 32],
    pub mode: u8,
    pub bound: Field,
    pub pub_amount: u64,
    pub old_root: Field,
}

pub fn random_field() -> Field {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out[31] &= RANDOM_TOP_MASK;
    out
}

pub fn instance_of(witness: &SpendWitness) -> Result<Instance, BidError> {
    let output = if witness.mode == MODE_UNSHIELD { [0u8; 32] } else { witness.output.commitment()? };
    Ok(Instance {
        old_root: witness.old_root,
        nullifier: witness.input.nullifier()?,
        output,
        change: witness.change.commitment()?,
        mode: witness.mode,
        listing: witness.auction,
        bidder: witness.input.owner,
        seller: witness.seller,
        mint: witness.input.mint,
        bound: witness.bound,
        pub_amount: witness.pub_amount,
    })
}

pub fn prove(witness: &SpendWitness) -> Result<([u8; PROOF_LEN], Instance), BidError> {
    let instance = instance_of(witness)?;
    let pk = proving_key()?;
    let proof = Groth16::<Bn254>::prove(pk, JoinSplit { witness: witness.clone() }, &mut OsRng).map_err(|_| BidError::BadProof)?;
    let mut bytes = alloc::vec::Vec::with_capacity(PROOF_LEN);
    proof.serialize_uncompressed(&mut bytes).map_err(|_| BidError::BadProof)?;
    let sized: [u8; PROOF_LEN] = bytes.as_slice().try_into().map_err(|_| BidError::BadProof)?;
    Ok((sized, instance))
}

pub fn verify(instance: &Instance, proof: &[u8]) -> Result<(), BidError> {
    if proof.len() != PROOF_LEN {
        return Err(BidError::BadProof);
    }
    let parsed = ark_groth16::Proof::<Bn254>::deserialize_uncompressed(proof).map_err(|_| BidError::BadProof)?;
    let public: alloc::vec::Vec<Fr> = instance.field_bytes()?.iter().map(|bytes| Fr::from_le_bytes_mod_order(bytes)).collect();
    Groth16::<Bn254>::verify_with_processed_vk(shipped_vk()?, &public, &parsed)
        .map_err(|_| BidError::BadProof)?
        .then_some(())
        .ok_or(BidError::BadProof)
}

/// Fresh keys for this circuit: (proving key, verifying key), uncompressed.
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), BidError> {
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(JoinSplit { witness: dummy()? }, rng).map_err(|_| BidError::BadProof)?;
    let mut pk_bytes = alloc::vec::Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes).map_err(|_| BidError::BadProof)?;
    let mut vk_bytes = alloc::vec::Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).map_err(|_| BidError::BadProof)?;
    Ok((pk_bytes, vk_bytes))
}

pub fn proving_key_path() -> PathBuf {
    match std::env::var_os(PROVING_KEY_ENV) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVING_KEY_DEFAULT),
    }
}

/// The verifying key inside the proving key on disk, serialized like `vk.bin`.
pub fn proving_key_vk_bytes() -> Result<alloc::vec::Vec<u8>, BidError> {
    let mut bytes = alloc::vec::Vec::new();
    proving_key()?.vk.serialize_uncompressed(&mut bytes).map_err(|_| BidError::BadProof)?;
    Ok(bytes)
}

fn proving_key() -> Result<&'static ProvingKey<Bn254>, BidError> {
    static CELL: OnceLock<Option<ProvingKey<Bn254>>> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read(proving_key_path()).ok()?;
        // The file is this machine's own setup output. A corrupt key yields
        // proofs that fail verification against `vk.bin`; it cannot pass one.
        ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(raw.as_slice()).ok()
    })
    .as_ref()
    .ok_or(BidError::BadProof)
}

fn shipped_vk() -> Result<&'static PreparedVerifyingKey<Bn254>, BidError> {
    static CELL: OnceLock<Option<PreparedVerifyingKey<Bn254>>> = OnceLock::new();
    CELL.get_or_init(|| {
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(SHIPPED_VK).ok()?;
        if vk.gamma_abc_g1.len() != PUBLIC_INPUTS + 1 {
            return None;
        }
        Groth16::<Bn254>::process_vk(&vk).ok()
    })
    .as_ref()
    .ok_or(BidError::BadProof)
}

fn dummy() -> Result<SpendWitness, BidError> {
    let owner = [1u8; 32];
    let mint = [2u8; 32];
    let input = Opening { amount: 1, blinding: [4u8; 32], secret: [3u8; 32], owner, listing: [0u8; 32], mint, kind: KIND_BALANCE };
    let mut tree = crate::merkle::NoteTree::new();
    tree.append(input.commitment()?);
    let (siblings, bits) = tree.path(0)?;
    Ok(SpendWitness {
        input,
        output: Opening::empty(),
        change: Opening { amount: 0, blinding: [5u8; 32], secret: [6u8; 32], owner, listing: [0u8; 32], mint, kind: KIND_BALANCE },
        seller: [0u8; 32],
        siblings,
        bits,
        auction: [0u8; 32],
        mode: MODE_UNSHIELD,
        bound: [0u8; 32],
        pub_amount: 1,
        old_root: tree.root()?,
    })
}

struct JoinSplit {
    witness: SpendWitness,
}

struct Publics {
    old_root: FpVar<Fr>,
    nullifier: FpVar<Fr>,
    output: FpVar<Fr>,
    change: FpVar<Fr>,
    mode: FpVar<Fr>,
    listing: (FpVar<Fr>, FpVar<Fr>),
    bidder: (FpVar<Fr>, FpVar<Fr>),
    seller_mix: FpVar<Fr>,
    mint: (FpVar<Fr>, FpVar<Fr>),
    bound: FpVar<Fr>,
    pub_amount: FpVar<Fr>,
}

struct Modes {
    bid: Boolean<Fr>,
    accept: Boolean<Fr>,
    refund: Boolean<Fr>,
    unshield: Boolean<Fr>,
}

struct OpenVar {
    amount: FpVar<Fr>,
    blinding: FpVar<Fr>,
    secret: FpVar<Fr>,
    owner: (FpVar<Fr>, FpVar<Fr>),
    listing: (FpVar<Fr>, FpVar<Fr>),
    mint: (FpVar<Fr>, FpVar<Fr>),
    kind: FpVar<Fr>,
}

impl ConstraintSynthesizer<Fr> for JoinSplit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w = self.witness;
        let publics = alloc_publics(&cs, &w)?;
        let modes = one_hot_modes(&publics.mode)?;
        let input = open_witness(&cs, &w.input)?;
        let output = open_witness(&cs, &w.output)?;
        let change = open_witness(&cs, &w.change)?;
        let seller = key_witness(&cs, &w.seller)?;

        let in_commit = commit_var(&input)?;
        enforce_membership(&cs, &w, &in_commit, &publics.old_root)?;
        let tag = FpVar::constant(Fr::from(DOM_NULL));
        poseidon_var(&[tag, input.secret.clone(), in_commit.clone()])?.enforce_equal(&publics.nullifier)?;
        let seller_tag = FpVar::constant(Fr::from(DOM_SELLER));
        poseidon_var(&[seller_tag, seller.0.clone(), seller.1.clone()])?.enforce_equal(&publics.seller_mix)?;

        let not_unshield = modes.unshield.not();
        commit_var(&output)?.conditional_enforce_equal(&publics.output, &not_unshield)?;
        publics.output.conditional_enforce_equal(&FpVar::zero(), &modes.unshield)?;
        commit_var(&change)?.enforce_equal(&publics.change)?;

        enforce_amounts(&input, &output, &change, &publics, &modes)?;
        enforce_bound(&in_commit, &publics, &modes)?;
        enforce_kinds(&input, &output, &change, &modes)?;
        enforce_keys(&input, &output, &change, &seller, &publics, &modes)?;
        Ok(())
    }
}

fn alloc_publics(cs: &ConstraintSystemRef<Fr>, w: &SpendWitness) -> Result<Publics, SynthesisError> {
    let fields = instance_of(w)
        .and_then(|instance| instance.field_bytes())
        .map_err(|_| SynthesisError::AssignmentMissing)?;
    let mut vars = alloc::vec::Vec::with_capacity(PUBLIC_INPUTS);
    for bytes in fields {
        vars.push(FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&bytes)))?);
    }
    let v = |at: usize| vars[at].clone();
    Ok(Publics {
        old_root: v(0),
        nullifier: v(1),
        output: v(2),
        change: v(3),
        mode: v(4),
        listing: (v(5), v(6)),
        bidder: (v(7), v(8)),
        seller_mix: v(9),
        mint: (v(10), v(11)),
        bound: v(12),
        pub_amount: v(13),
    })
}

fn one_hot_modes(mode: &FpVar<Fr>) -> Result<Modes, SynthesisError> {
    let is = |value: u8| mode.is_eq(&FpVar::constant(Fr::from(u64::from(value))));
    let modes = Modes { bid: is(MODE_BID)?, accept: is(MODE_ACCEPT)?, refund: is(MODE_REFUND)?, unshield: is(MODE_UNSHIELD)? };
    let mut count = FpVar::from(modes.bid.clone());
    count += FpVar::from(modes.accept.clone());
    count += FpVar::from(modes.refund.clone());
    count += FpVar::from(modes.unshield.clone());
    count.enforce_equal(&FpVar::one())?;
    Ok(modes)
}

fn enforce_membership(
    cs: &ConstraintSystemRef<Fr>,
    w: &SpendWitness,
    leaf: &FpVar<Fr>,
    root: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let mut node = leaf.clone();
    for level in 0..MERKLE_DEPTH {
        let sibling = FpVar::new_witness(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&w.siblings[level])))?;
        let bit = Boolean::new_witness(cs.clone(), || Ok(w.bits[level]))?;
        let left = FpVar::conditionally_select(&bit, &sibling, &node)?;
        let right = FpVar::conditionally_select(&bit, &node, &sibling)?;
        node = poseidon_var(&[left, right])?;
    }
    node.enforce_equal(root)
}

fn enforce_amounts(input: &OpenVar, output: &OpenVar, change: &OpenVar, p: &Publics, m: &Modes) -> Result<(), SynthesisError> {
    for amount in [&input.amount, &output.amount, &change.amount, &p.pub_amount] {
        fits_u64(amount)?;
    }
    let inverse = input.amount.inverse()?;
    input.amount.mul_equals(&inverse, &FpVar::one())?;
    let spent = FpVar::conditionally_select(&m.unshield, &p.pub_amount, &output.amount)?;
    input.amount.enforce_equal(&(spent + &change.amount))?;
    p.pub_amount.conditional_enforce_equal(&FpVar::zero(), &m.unshield.not())?;
    change.amount.conditional_enforce_equal(&FpVar::zero(), &m.accept.or(&m.refund)?)?;
    Ok(())
}

fn enforce_bound(in_commit: &FpVar<Fr>, p: &Publics, m: &Modes) -> Result<(), SynthesisError> {
    in_commit.conditional_enforce_equal(&p.bound, &m.accept.or(&m.refund)?)?;
    p.bound.conditional_enforce_equal(&FpVar::zero(), &m.bid.or(&m.unshield)?)?;
    Ok(())
}

fn enforce_kinds(input: &OpenVar, output: &OpenVar, change: &OpenVar, m: &Modes) -> Result<(), SynthesisError> {
    let balance = FpVar::constant(Fr::from(u64::from(KIND_BALANCE)));
    let bid = FpVar::constant(Fr::from(u64::from(KIND_BID)));
    let spends_bid = m.accept.or(&m.refund)?;
    input.kind.conditional_enforce_equal(&balance, &m.bid.or(&m.unshield)?)?;
    input.kind.conditional_enforce_equal(&bid, &spends_bid)?;
    output.kind.conditional_enforce_equal(&bid, &m.bid)?;
    output.kind.conditional_enforce_equal(&balance, &spends_bid)?;
    change.kind.enforce_equal(&balance)?;
    Ok(())
}

fn enforce_keys(
    input: &OpenVar,
    output: &OpenVar,
    change: &OpenVar,
    seller: &(FpVar<Fr>, FpVar<Fr>),
    p: &Publics,
    m: &Modes,
) -> Result<(), SynthesisError> {
    let zero = (FpVar::zero(), FpVar::zero());
    let always = Boolean::TRUE;
    let spends_bid = m.accept.or(&m.refund)?;
    key_eq(&input.owner, &p.bidder, &always)?;
    key_eq(&input.mint, &p.mint, &always)?;
    key_eq(&input.listing, &zero, &m.bid.or(&m.unshield)?)?;
    key_eq(&input.listing, &p.listing, &spends_bid)?;

    key_eq(&output.owner, &p.bidder, &m.bid.or(&m.refund)?)?;
    key_eq(&output.owner, seller, &m.accept)?;
    key_eq(&output.listing, &p.listing, &m.bid)?;
    key_eq(&output.listing, &zero, &spends_bid)?;
    key_eq(&output.mint, &p.mint, &m.unshield.not())?;

    key_eq(&change.owner, &p.bidder, &always)?;
    key_eq(&change.listing, &zero, &always)?;
    key_eq(&change.mint, &p.mint, &always)?;
    Ok(())
}

fn open_witness(cs: &ConstraintSystemRef<Fr>, open: &Opening) -> Result<OpenVar, SynthesisError> {
    let field = |value: Fr| FpVar::new_witness(cs.clone(), || Ok(value));
    Ok(OpenVar {
        amount: field(Fr::from(open.amount))?,
        blinding: field(Fr::from_le_bytes_mod_order(&open.blinding))?,
        secret: field(Fr::from_le_bytes_mod_order(&open.secret))?,
        owner: key_witness(cs, &open.owner)?,
        listing: key_witness(cs, &open.listing)?,
        mint: key_witness(cs, &open.mint)?,
        kind: field(Fr::from(u64::from(open.kind)))?,
    })
}

fn key_witness(cs: &ConstraintSystemRef<Fr>, key: &[u8; 32]) -> Result<(FpVar<Fr>, FpVar<Fr>), SynthesisError> {
    let (lo, hi) = limbs(key);
    Ok((
        FpVar::new_witness(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&lo)))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&hi)))?,
    ))
}

fn commit_var(open: &OpenVar) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = poseidon_var(&[
        open.blinding.clone(),
        open.secret.clone(),
        open.owner.0.clone(),
        open.owner.1.clone(),
        open.listing.0.clone(),
        open.listing.1.clone(),
    ])?;
    poseidon_var(&[open.amount.clone(), open.mint.0.clone(), open.mint.1.clone(), open.kind.clone(), inner])
}

fn key_eq(
    key: &(FpVar<Fr>, FpVar<Fr>),
    other: &(FpVar<Fr>, FpVar<Fr>),
    flag: &Boolean<Fr>,
) -> Result<(), SynthesisError> {
    key.0.conditional_enforce_equal(&other.0, flag)?;
    key.1.conditional_enforce_equal(&other.1, flag)
}

fn fits_u64(amount: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let bits = amount.to_bits_le()?;
    for bit in bits.iter().skip(AMOUNT_BITS) {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

fn circom_params(width: usize) -> Result<&'static PoseidonParameters<Fr>, SynthesisError> {
    static CELLS: [OnceLock<Option<PoseidonParameters<Fr>>>; MAX_WIDTH + 1] = [const { OnceLock::new() }; MAX_WIDTH + 1];
    let cell = CELLS.get(width).ok_or(SynthesisError::Unsatisfiable)?;
    cell.get_or_init(|| {
        let width = u8::try_from(width).ok()?;
        light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(width).ok()
    })
    .as_ref()
    .ok_or(SynthesisError::Unsatisfiable)
}

/// Same rounds as `light_poseidon::Poseidon::hash`: capacity zero, then the inputs.
fn poseidon_var(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let params = circom_params(inputs.len() + 1)?;
    let width = params.width;
    let mut state: alloc::vec::Vec<FpVar<Fr>> = core::iter::once(FpVar::zero()).chain(inputs.iter().cloned()).collect();
    let half = params.full_rounds / 2;
    let rounds = params.full_rounds + params.partial_rounds;
    for round in 0..rounds {
        for (index, value) in state.iter_mut().enumerate() {
            *value += params.ark[round * width + index];
        }
        let full = round < half || round >= half + params.partial_rounds;
        if full {
            for value in state.iter_mut() {
                *value = value.pow_by_constant([SBOX])?;
            }
        } else {
            state[0] = state[0].pow_by_constant([SBOX])?;
        }
        let mut mixed = alloc::vec::Vec::with_capacity(width);
        for row in params.mds.iter().take(width) {
            let mut sum = FpVar::zero();
            for (value, coefficient) in state.iter().zip(row) {
                sum += value * *coefficient;
            }
            mixed.push(sum);
        }
        state = mixed;
    }
    Ok(state[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn the_gadget_matches_the_syscall_hash() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        for arity in [2usize, 3, 5, 6] {
            let bytes: alloc::vec::Vec<Field> = (0..arity).map(|at| [at as u8 + 1; 32]).collect();
            let refs: alloc::vec::Vec<&Field> = bytes.iter().collect();
            let expected = poseidon::hash(&refs).unwrap();
            let vars: alloc::vec::Vec<FpVar<Fr>> = bytes
                .iter()
                .map(|value| FpVar::new_witness(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(value))).unwrap())
                .collect();
            let got = poseidon_var(&vars).unwrap().value().unwrap();
            assert_eq!(got, Fr::from_le_bytes_mod_order(&expected), "arity {arity}");
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn random_fields_are_canonical() {
        for _ in 0..64 {
            assert!(poseidon::is_canonical(&random_field()));
        }
    }
}
