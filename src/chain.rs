//! Groth16 check for the join-split. Proof bytes are the ark uncompressed
//! encoding. `sol_alt_bn128_group_op` wants Ethereum big-endian points, and a
//! G2 point swaps its two base-field limbs. The first proof point is negated
//! so the product of the four pairings is one.

use crate::error::BidError;
use crate::instance::{Instance, PUBLIC_INPUTS};
use crate::state::PROOF_LEN;

const VK: &[u8] = include_bytes!("vk.bin");
const G1: usize = 64;
const G2: usize = 128;
const ALPHA: usize = 0;
const BETA: usize = G1;
const GAMMA: usize = BETA + G2;
const DELTA: usize = GAMMA + G2;
const ABC_LEN: usize = DELTA + G2;
const ABC: usize = ABC_LEN + 8;
const ABC_COUNT: usize = PUBLIC_INPUTS + 1;
const VK_LEN: usize = ABC + ABC_COUNT * G1;
/// -A·B, prepared inputs·gamma, C·delta, alpha·beta.
const PAIRS: usize = 4;

const BASE_FIELD: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

// Agave group_op values. Subtraction sits at 1, so multiplication is 2 and pairing is 3.
const OP_ADD: u64 = 0;
const OP_MUL: u64 = 2;
const OP_PAIRING: u64 = 3;

extern "C" {
    fn sol_alt_bn128_group_op(op: u64, input: *const u8, input_size: u64, result: *mut u8) -> u64;
}

// Each step keeps its own frame. Inlined together they pass the 4KiB BPF frame.
#[inline(never)]
pub fn verify(instance: &Instance, proof: &[u8]) -> Result<(), BidError> {
    if proof.len() != PROOF_LEN || VK.len() != VK_LEN {
        return Err(BidError::BadProof);
    }
    let mut count = [0u8; 8];
    count.copy_from_slice(&VK[ABC_LEN..ABC]);
    if u64::from_le_bytes(count) != ABC_COUNT as u64 {
        return Err(BidError::BadProof);
    }
    let acc = prepare(instance)?;
    let input = pairing_input(proof, &acc)?;
    let mut result = [0u8; 32];
    let rc = unsafe {
        sol_alt_bn128_group_op(OP_PAIRING, input.as_ptr(), input.len() as u64, result.as_mut_ptr())
    };
    if rc != 0 || result != pairing_one() {
        return Err(BidError::BadProof);
    }
    Ok(())
}

#[inline(never)]
fn pairing_input(proof: &[u8], acc: &[u8; G1]) -> Result<alloc::vec::Vec<u8>, BidError> {
    let mut negated = *slice_g1(&proof[..G1])?;
    negate_g1(&mut negated)?;
    let mut input = alloc::vec![0u8; PAIRS * (G1 + G2)];
    write_pair(&mut input, 0, &g1_eth(&negated), &g2_eth(slice_g2(&proof[G1..G1 + G2])?));
    write_pair(&mut input, 1, acc, &g2_eth(slice_g2(&VK[GAMMA..DELTA])?));
    write_pair(&mut input, 2, &g1_eth(slice_g1(&proof[G1 + G2..])?), &g2_eth(slice_g2(&VK[DELTA..ABC_LEN])?));
    write_pair(&mut input, 3, &g1_eth(slice_g1(&VK[ALPHA..BETA])?), &g2_eth(slice_g2(&VK[BETA..GAMMA])?));
    Ok(input)
}

#[inline(never)]
fn prepare(instance: &Instance) -> Result<[u8; G1], BidError> {
    let mut acc = g1_eth(slice_g1(&VK[ABC..ABC + G1])?);
    for (index, scalar) in instance.field_bytes()?.into_iter().enumerate() {
        let start = ABC + (index + 1) * G1;
        let point = g1_eth(slice_g1(&VK[start..start + G1])?);
        let term = mul(&point, &reverse(&scalar))?;
        acc = add(&acc, &term)?;
    }
    Ok(acc)
}

fn mul(point: &[u8; G1], scalar: &[u8; 32]) -> Result<[u8; G1], BidError> {
    let mut input = [0u8; G1 + 32];
    input[..G1].copy_from_slice(point);
    input[G1..].copy_from_slice(scalar);
    group(OP_MUL, &input)
}

fn add(left: &[u8; G1], right: &[u8; G1]) -> Result<[u8; G1], BidError> {
    let mut input = [0u8; G1 + G1];
    input[..G1].copy_from_slice(left);
    input[G1..].copy_from_slice(right);
    group(OP_ADD, &input)
}

fn group(op: u64, input: &[u8]) -> Result<[u8; G1], BidError> {
    let mut result = [0u8; G1];
    let rc = unsafe { sol_alt_bn128_group_op(op, input.as_ptr(), input.len() as u64, result.as_mut_ptr()) };
    if rc == 0 {
        Ok(result)
    } else {
        Err(BidError::BadProof)
    }
}

fn write_pair(out: &mut [u8], index: usize, g1: &[u8; G1], g2: &[u8; G2]) {
    let at = index * (G1 + G2);
    out[at..at + G1].copy_from_slice(g1);
    out[at + G1..at + G1 + G2].copy_from_slice(g2);
}

fn negate_g1(point: &mut [u8; G1]) -> Result<(), BidError> {
    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..]);
    if y == [0u8; 32] {
        return Ok(());
    }
    let negated = sub_be(&BASE_FIELD, &reverse(&y));
    if negated == BASE_FIELD {
        return Err(BidError::BadProof);
    }
    point[32..].copy_from_slice(&reverse(&negated));
    Ok(())
}

fn g1_eth(point: &[u8; G1]) -> [u8; G1] {
    let mut out = [0u8; G1];
    out[..32].copy_from_slice(&reverse_at(point, 0));
    out[32..].copy_from_slice(&reverse_at(point, 32));
    out
}

fn g2_eth(point: &[u8; G2]) -> [u8; G2] {
    let mut out = [0u8; G2];
    out[..32].copy_from_slice(&reverse_at(point, 32));
    out[32..64].copy_from_slice(&reverse_at(point, 0));
    out[64..96].copy_from_slice(&reverse_at(point, 96));
    out[96..].copy_from_slice(&reverse_at(point, 64));
    out
}

fn sub_be(modulus: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let diff = modulus[index] as i16 - value[index] as i16 - borrow;
        if diff < 0 {
            out[index] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[index] = diff as u8;
            borrow = 0;
        }
    }
    out
}

fn reverse(bytes: &[u8; 32]) -> [u8; 32] {
    reverse_at(bytes, 0)
}

fn reverse_at(bytes: &[u8], at: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    for index in 0..32 {
        out[index] = bytes[at + 31 - index];
    }
    out
}

fn slice_g1(bytes: &[u8]) -> Result<&[u8; G1], BidError> {
    bytes.try_into().map_err(|_| BidError::BadProof)
}

fn slice_g2(bytes: &[u8]) -> Result<&[u8; G2], BidError> {
    bytes.try_into().map_err(|_| BidError::BadProof)
}

fn pairing_one() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = 1;
    out
}
