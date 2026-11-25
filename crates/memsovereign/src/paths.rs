use std::path::{Path, PathBuf};

/// Resolve the memsovereign home directory.
///
/// Precedence:
/// 1) provided `home_override`
/// 2) environment variable `MEMSOVEREIGN_HOME`
/// 3) platform config dir (~/.config/memsovereign)
pub fn resolve_home(home_override: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = home_override {
        return Ok(p.to_path_buf());
    }
    if let Ok(val) = std::env::var("MEMSOVEREIGN_HOME") {
        return Ok(PathBuf::from(val));
    }
    let base = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("could not resolve config dir"))?;
    Ok(base.join("memsovereign"))
}

pub fn keys_dir(home: &Path) -> PathBuf {
    home.join("keys")
}

pub fn log_dir(home: &Path) -> PathBuf {
    home.join("log")
}

pub fn entries_path(home: &Path) -> PathBuf {
    log_dir(home).join("entries.jsonl")
}

pub fn head_path(home: &Path) -> PathBuf {
    log_dir(home).join("HEAD.json")
}

pub fn lock_path(home: &Path) -> PathBuf {
    log_dir(home).join("LOCK")
}

pub fn receipts_dir(home: &Path) -> PathBuf {
    log_dir(home).join("receipts")
}

pub fn receipt_path(home: &Path, index: u64) -> PathBuf {
    receipts_dir(home).join(format!("receipt_{index}.json"))
}

pub fn checkpoints_dir(home: &Path) -> PathBuf {
    home.join("checkpoints")
}
