use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct IdentityKeys {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

/// Key material for one home directory.
///
/// Dropping this value zeroes the Ed25519 seed and the content key.
/// [`Debug`] redacts both. The content key is independent of the seed:
/// it is 32 bytes from the supplied CSPRNG, not a password hash and not
/// a conversion of the signing key.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoredKeys {
    /// 32-byte Ed25519 seed.
    pub ed25519_secret: [u8; 32],
    pub ed25519_public: [u8; 32],
    /// 32-byte XChaCha20-Poly1305 key.
    pub content_key: [u8; 32],
}

impl std::fmt::Debug for StoredKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKeys")
            .field("ed25519_public", &self.ed25519_public)
            .field("ed25519_secret", &"<redacted>")
            .field("content_key", &"<redacted>")
            .finish()
    }
}

impl StoredKeys {
    pub fn identity(&self) -> anyhow::Result<IdentityKeys> {
        let signing = SigningKey::from_bytes(&self.ed25519_secret);
        let verifying = signing.verifying_key();
        if verifying.to_bytes() != self.ed25519_public {
            anyhow::bail!("stored public key does not match secret key");
        }
        Ok(IdentityKeys { signing, verifying })
    }

    pub fn generate(rng: &mut impl CryptoRng) -> anyhow::Result<Self> {
        let signing = SigningKey::generate(rng);
        let verifying = signing.verifying_key();
        let mut content_key = [0u8; 32];
        rng.fill_bytes(&mut content_key);

        // An all-zero buffer means the generator did not supply entropy.
        // A real CSPRNG hits this with probability 2^-256.
        if signing.to_bytes() == [0u8; 32] || content_key == [0u8; 32] {
            content_key.zeroize();
            anyhow::bail!("CSPRNG returned an all-zero key");
        }

        Ok(Self {
            ed25519_secret: signing.to_bytes(),
            ed25519_public: verifying.to_bytes(),
            content_key,
        })
    }
}

pub fn fingerprint_pubkey(pubkey: &[u8; 32]) -> String {
    let hash = blake3::hash(pubkey);
    let hex = hash.to_hex();
    format!("{}{}", &hex[..12], "…")
}

pub fn write_file_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf);
    if let Some(parent) = &parent {
        std::fs::create_dir_all(parent).with_context(|| format!("create dir {parent:?}"))?;
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path {path:?} has no file name"))?;
    let tmp = path.with_file_name(format!(".{}.tmp", file_name.to_string_lossy()));

    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("create {tmp:?}"))?;
        file.write_all(bytes).context("write")?;
        file.sync_all().context("sync")?;
    }

    std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp:?} -> {path:?}"))?;
    if let Some(parent) = parent {
        if let Ok(dir) = std::fs::File::open(&parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

pub fn read_exact_32(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut bytes = std::fs::read(path).with_context(|| format!("read {path:?}"))?;
    if bytes.len() != 32 {
        let len = bytes.len();
        bytes.zeroize();
        anyhow::bail!("expected 32 bytes in {path:?}, got {len}");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}
