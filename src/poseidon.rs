//! Circom Poseidon over BN254 with x^5, the parameters behind the
//! `sol_poseidon` syscall. Every value is a 32-byte little-endian field
//! element below the scalar modulus. The program hashes through the syscall;
//! host code hashes through light-poseidon, which is the syscall's own
//! implementation. The join-split circuit uses the same round constants.
//!
//! Arity keeps the hashes apart: a merkle node takes 2 inputs, the tagged
//! nullifier and seller hashes take 3, a commitment 5, and a note secret 6.

use crate::error::BidError;
use crate::state::MERKLE_DEPTH;

pub type Field = [u8; 32];

pub const DOM_NULL: u64 = 1;
pub const DOM_SELLER: u64 = 2;

/// BN254 scalar modulus r, little-endian.
const MODULUS: Field = [
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];
const LIMB: usize = 16;

pub fn is_canonical(value: &Field) -> bool {
    for index in (0..32).rev() {
        if value[index] != MODULUS[index] {
            return value[index] < MODULUS[index];
        }
    }
    false
}

pub fn require_canonical(value: &Field) -> Result<(), BidError> {
    if is_canonical(value) {
        Ok(())
    } else {
        Err(BidError::NonCanonical)
    }
}

pub fn u64_field(value: u64) -> Field {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    out
}

/// A 32-byte key as two 128-bit field elements, low half first.
pub fn limbs(key: &[u8; 32]) -> (Field, Field) {
    let mut lo = [0u8; 32];
    let mut hi = [0u8; 32];
    lo[..LIMB].copy_from_slice(&key[..LIMB]);
    hi[..LIMB].copy_from_slice(&key[LIMB..]);
    (lo, hi)
}

#[cfg(target_os = "solana")]
pub fn hash(inputs: &[&Field]) -> Result<Field, BidError> {
    const BN254_X5: u64 = 0;
    const LITTLE_ENDIAN: u64 = 1;
    extern "C" {
        fn sol_poseidon(parameters: u64, endianness: u64, vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
    }
    let mut slices: [&[u8]; 12] = [&[]; 12];
    if inputs.is_empty() || inputs.len() > slices.len() {
        return Err(BidError::HashFailed);
    }
    for (slot, input) in slices.iter_mut().zip(inputs) {
        *slot = &input[..];
    }
    let mut out = [0u8; 32];
    // Safety: `slices` holds `inputs.len()` fat pointers to live 32-byte
    // arrays, which is the `&[&[u8]]` layout the syscall translates. `out` is
    // the 32 bytes the syscall writes.
    let rc = unsafe {
        sol_poseidon(
            BN254_X5,
            LITTLE_ENDIAN,
            slices.as_ptr() as *const u8,
            inputs.len() as u64,
            out.as_mut_ptr(),
        )
    };
    if rc == 0 {
        Ok(out)
    } else {
        Err(BidError::HashFailed)
    }
}

#[cfg(not(target_os = "solana"))]
pub fn hash(inputs: &[&Field]) -> Result<Field, BidError> {
    use light_poseidon::{Poseidon, PoseidonBytesHasher};
    let mut hasher = Poseidon::<ark_bn254::Fr>::new_circom(inputs.len()).map_err(|_| BidError::HashFailed)?;
    let slices: alloc::vec::Vec<&[u8]> = inputs.iter().map(|input| &input[..]).collect();
    hasher.hash_bytes_le(&slices).map_err(|_| BidError::HashFailed)
}

pub fn merkle_node(left: &Field, right: &Field) -> Result<Field, BidError> {
    hash(&[left, right])
}

/// The part of a note only its holder knows. A shield publishes this hash,
/// never the blinding or the secret.
pub fn note_inner(blinding: &Field, secret: &Field, owner: &[u8; 32], listing: &[u8; 32]) -> Result<Field, BidError> {
    let (owner_lo, owner_hi) = limbs(owner);
    let (listing_lo, listing_hi) = limbs(listing);
    hash(&[blinding, secret, &owner_lo, &owner_hi, &listing_lo, &listing_hi])
}

pub fn commitment_from_inner(amount: u64, mint: &[u8; 32], kind: u8, inner: &Field) -> Result<Field, BidError> {
    let (mint_lo, mint_hi) = limbs(mint);
    hash(&[&u64_field(amount), &mint_lo, &mint_hi, &u64_field(u64::from(kind)), inner])
}

pub fn note_commitment(
    amount: u64,
    blinding: &Field,
    secret: &Field,
    owner: &[u8; 32],
    listing: &[u8; 32],
    mint: &[u8; 32],
    kind: u8,
) -> Result<Field, BidError> {
    let inner = note_inner(blinding, secret, owner, listing)?;
    commitment_from_inner(amount, mint, kind, &inner)
}

pub fn nullifier(secret: &Field, commitment: &Field) -> Result<Field, BidError> {
    hash(&[&u64_field(DOM_NULL), secret, commitment])
}

pub fn note_nullifier(
    amount: u64,
    blinding: &Field,
    secret: &Field,
    owner: &[u8; 32],
    listing: &[u8; 32],
    mint: &[u8; 32],
    kind: u8,
) -> Result<Field, BidError> {
    let commitment = note_commitment(amount, blinding, secret, owner, listing, mint, kind)?;
    nullifier(secret, &commitment)
}

/// The seller is a witness in the circuit. The public input is this hash.
pub fn seller_mix(seller: &[u8; 32]) -> Result<Field, BidError> {
    let (lo, hi) = limbs(seller);
    hash(&[&u64_field(DOM_SELLER), &lo, &hi])
}

/// Roots of empty subtrees. Level 0 is the empty leaf, zero.
pub fn zero_nodes() -> Result<[Field; MERKLE_DEPTH + 1], BidError> {
    let mut nodes = [[0u8; 32]; MERKLE_DEPTH + 1];
    for level in 0..MERKLE_DEPTH {
        nodes[level + 1] = merkle_node(&nodes[level], &nodes[level])?;
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_modulus_and_above_are_not_canonical() {
        assert!(!is_canonical(&MODULUS));
        let mut below = MODULUS;
        below[0] = 0;
        assert!(is_canonical(&below));
        assert!(!is_canonical(&[0xff; 32]));
        assert!(require_canonical(&MODULUS).is_err());
    }

    #[test]
    fn host_hash_is_circom_poseidon() {
        // light-poseidon's documented vector for inputs [1; 32] and [2; 32], little-endian.
        let expected: Field = [
            144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99, 242, 85, 3, 94,
            235, 125, 28, 140, 138, 143, 147, 225, 84, 13,
        ];
        assert_eq!(merkle_node(&[1u8; 32], &[2u8; 32]).unwrap(), expected);
    }

    #[test]
    fn arity_separates_node_and_tagged_hashes() {
        let a = [3u8; 32];
        assert_ne!(merkle_node(&u64_field(DOM_NULL), &a).unwrap(), nullifier(&a, &[0u8; 32]).unwrap());
    }
}
