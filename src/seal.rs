//! Ciphertext stored on the bid. The seller's X25519 key opens it. Other
//! bidders see the bytes and not the amount. The program never decrypts.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::BidError;
use crate::state::{SEAL_LEN, SEAL_PLAIN};

pub fn view_key(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

pub fn seal(
    seller_view: &[u8; 32],
    amount: u64,
    blinding: &[u8; 32],
    secret: &[u8; 32],
    ephemeral: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<[u8; SEAL_LEN], BidError> {
    let plain = plain(amount, blinding, secret);
    let shared = StaticSecret::from(*ephemeral).diffie_hellman(&PublicKey::from(*seller_view));
    let cipher = ChaCha20Poly1305::new_from_slice(shared.as_bytes()).map_err(|_| BidError::BadCiphertext)?;
    let tag_and_body = cipher
        .encrypt(Nonce::from_slice(nonce), plain.as_slice())
        .map_err(|_| BidError::BadCiphertext)?;
    if tag_and_body.len() != SEAL_PLAIN + 16 {
        return Err(BidError::BadCiphertext);
    }
    let mut out = [0u8; SEAL_LEN];
    out[..32].copy_from_slice(PublicKey::from(&StaticSecret::from(*ephemeral)).as_bytes());
    out[32..44].copy_from_slice(nonce);
    out[44..].copy_from_slice(&tag_and_body);
    Ok(out)
}

pub fn open(
    seller_secret: &[u8; 32],
    sealed: &[u8],
) -> Result<(u64, [u8; 32], [u8; 32]), BidError> {
    if sealed.len() != SEAL_LEN {
        return Err(BidError::BadCiphertext);
    }
    let mut ephem = [0u8; 32];
    ephem.copy_from_slice(&sealed[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[32..44]);
    let shared = StaticSecret::from(*seller_secret).diffie_hellman(&PublicKey::from(ephem));
    let cipher = ChaCha20Poly1305::new_from_slice(shared.as_bytes()).map_err(|_| BidError::BadCiphertext)?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), &sealed[44..])
        .map_err(|_| BidError::BadCiphertext)?;
    if plain.len() != SEAL_PLAIN {
        return Err(BidError::BadCiphertext);
    }
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&plain[..8]);
    let mut blinding = [0u8; 32];
    let mut secret = [0u8; 32];
    blinding.copy_from_slice(&plain[8..40]);
    secret.copy_from_slice(&plain[40..72]);
    Ok((u64::from_le_bytes(amount), blinding, secret))
}

fn plain(amount: u64, blinding: &[u8; 32], secret: &[u8; 32]) -> [u8; SEAL_PLAIN] {
    let mut out = [0u8; SEAL_PLAIN];
    out[..8].copy_from_slice(&amount.to_le_bytes());
    out[8..40].copy_from_slice(blinding);
    out[40..72].copy_from_slice(secret);
    out
}
