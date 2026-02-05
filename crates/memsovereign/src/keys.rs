use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct IdentityKeys {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeys {
    /// 32-byte ed25519 secret key seed.
    pub ed25519_secret: [u8; 32],
    pub ed25519_public: [u8; 32],
    pub content_key: [u8; 32],
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

    pub fn generate(mut rng: impl CryptoRngCore) -> Self {
        let signing = SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();

        let mut content_key = [0u8; 32];
        rng.fill_bytes(&mut content_key);

        Self {
            ed25519_secret: signing.to_bytes(),
            ed25519_public: verifying.to_bytes(),
            content_key,
        }
    }

    pub fn zeroize_secrets(&mut self) {
        self.ed25519_secret.zeroize();
        self.content_key.zeroize();
    }
}

pub fn fingerprint_pubkey(pubkey: &[u8; 32]) -> String {
    let hash = blake3::hash(pubkey);
    let hex = hash.to_hex();
    format!("{}{}", &hex[..12], "…")
}

pub fn write_file_atomic(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create dir {parent:?}"))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
        f.write_all(bytes).context("write")?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .context("set permissions")?;
    }

    std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp:?} -> {path:?}"))?;
    Ok(())
}

pub fn read_exact_32(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("read {path:?}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes in {path:?}, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
