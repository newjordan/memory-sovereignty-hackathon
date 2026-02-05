use anyhow::Context;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand_core::RngCore;

pub type Hash32 = [u8; 32];

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn b64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode")
}

pub fn blake3_hash(data: &[u8]) -> Hash32 {
    blake3::hash(data).into()
}

pub fn now_rfc3339() -> String {
    // RFC3339 with offset; UTC is fine for ordering.
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub fn encrypt_xchacha20poly1305(
    key32: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    mut rng: impl RngCore,
) -> anyhow::Result<([u8; 24], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key32.into());
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .context("encrypt")?;
    Ok((nonce, ciphertext))
}

pub fn decrypt_xchacha20poly1305(
    key32: &[u8; 32],
    nonce24: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key32.into());
    let pt = cipher
        .decrypt(
            nonce24.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .context("decrypt")?;
    Ok(pt)
}
