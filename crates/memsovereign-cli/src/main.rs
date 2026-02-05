use anyhow::Context;
use clap::{Parser, Subcommand};
use memsovereign::paths;
use memsovereign::types::{Attachment, Provenance};
use rand_core::OsRng;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "memsovereign", version, about)]
struct Cli {
    /// Override home directory (otherwise ~/.config/memsovereign or $MEMSOVEREIGN_HOME)
    #[arg(long)]
    home: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize keys
    Init {
        /// Overwrite existing keys
        #[arg(long)]
        force: bool,
    },

    /// Append a memory entry and print a signed receipt (JSON)
    Append {
        /// Entry content (plaintext)
        #[arg(long)]
        content: String,

        /// Optional path to also write the receipt JSON.
        #[arg(long)]
        receipt_out: Option<PathBuf>,

        #[arg(long)]
        source_type: Option<String>,
        #[arg(long)]
        source_ref: Option<String>,
        #[arg(long)]
        message_id: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        tool_name: Option<String>,

        /// Attach a local file (metadata only; sha256 computed and stored)
        #[arg(long, value_name = "PATH")]
        attach_file: Vec<PathBuf>,

        /// Attach a URL (metadata only; no fetch)
        #[arg(long, value_name = "URL")]
        attach_url: Vec<String>,

        /// Attach an opaque reference (e.g. ipfs://..., ar://..., openclaw:...)
        #[arg(long, value_name = "REF")]
        attach_ref: Vec<String>,
    },

    /// Verify the full hash chain in the local log
    VerifyChain,

    /// Write a signed checkpoint statement for the current chain head.
    ///
    /// The checkpoint is stored at $HOME/checkpoints/checkpoint_<label>.json by default.
    Checkpoint {
        /// Label to use in the checkpoint filename and statement (default: today's YYYY-MM-DD).
        #[arg(long)]
        label: Option<String>,

        /// Optional path to also write the checkpoint JSON (in addition to the default store path).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify a checkpoint JSON file (signature + statement hash) AND ensure it matches the current chain head.
    VerifyCheckpoint { path: PathBuf },

    /// Verify a receipt JSON file (signature only)
    VerifyReceipt { path: PathBuf },

    /// Verify a receipt AND the local chain up to its index
    Verify { path: PathBuf },

    /// Import/export receipts stored under the local home directory
    Receipt {
        #[command(subcommand)]
        cmd: ReceiptCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    /// Export a locally-stored receipt by index (prints to stdout by default)
    Export {
        index: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Import a receipt JSON file into the local receipt store
    Import {
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = paths::resolve_home(cli.home.as_deref())?;

    match cli.cmd {
        Command::Init { force } => {
            let res = memsovereign::init_keys(&home, force, OsRng)
                .with_context(|| format!("init in {:?}", home))?;
            eprintln!("Initialized memsovereign at {:?}", res.home);
            eprintln!("Public key fingerprint: {}", res.pubkey_fingerprint);
        }
        Command::Append {
            content,
            receipt_out,
            source_type,
            source_ref,
            message_id,
            url,
            tool_name,
            attach_file,
            attach_url,
            attach_ref,
        } => {
            let prov = Provenance {
                source_type,
                source_ref,
                message_id,
                url,
                tool_name,
            };

            let mut attachments: Vec<Attachment> = Vec::new();

            // Files: compute sha256 + size + content-type.
            for path in attach_file {
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("read attachment file {:?}", path))?;
                let mut hasher = sha2::Sha256::new();
                use sha2::Digest;
                hasher.update(&bytes);
                let digest = hasher.finalize();
                let sha256_b64 = memsovereign::crypto::b64(digest.as_slice());
                let size_bytes = Some(bytes.len() as u64);
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.to_string_lossy().to_string());
                let content_type = mime_guess::from_path(&path)
                    .first_raw()
                    .map(|s| s.to_string());
                attachments.push(Attachment {
                    kind: "file".to_string(),
                    name,
                    locator: format!("file:{}", path.to_string_lossy()),
                    sha256_b64: Some(sha256_b64),
                    size_bytes,
                    content_type,
                });
            }

            for u in attach_url {
                let name = u.clone();
                attachments.push(Attachment {
                    kind: "url".to_string(),
                    name,
                    locator: u,
                    sha256_b64: None,
                    size_bytes: None,
                    content_type: None,
                });
            }

            for r in attach_ref {
                let name = r.clone();
                attachments.push(Attachment {
                    kind: "ref".to_string(),
                    name,
                    locator: r,
                    sha256_b64: None,
                    size_bytes: None,
                    content_type: None,
                });
            }

            let (_entry, receipt) =
                memsovereign::append_entry(&home, &content, prov, attachments, OsRng)?;

            if let Some(out) = receipt_out {
                let json = serde_json::to_vec_pretty(&receipt)?;
                std::fs::write(&out, json).with_context(|| format!("write {out:?}"))?;
            }

            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::VerifyChain => {
            memsovereign::verify::verify_chain(&home)?;
            eprintln!("OK");
        }
        Command::Checkpoint { label, out } => {
            let (checkpoint, path) = memsovereign::create_checkpoint(&home, label.as_deref())?;
            if let Some(extra_out) = out {
                let json = serde_json::to_vec_pretty(&checkpoint)?;
                std::fs::write(&extra_out, json).with_context(|| format!("write {extra_out:?}"))?;
            }
            eprintln!("Wrote checkpoint -> {:?}", path);
            println!("{}", serde_json::to_string_pretty(&checkpoint)?);
        }
        Command::VerifyCheckpoint { path } => {
            let bytes = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
            let checkpoint: memsovereign::Checkpoint =
                serde_json::from_str(&bytes).context("parse checkpoint")?;
            memsovereign::verify::verify_checkpoint_matches_chain(&home, &checkpoint)?;
            eprintln!("OK");
        }
        Command::VerifyReceipt { path } => {
            let bytes = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
            let receipt: memsovereign::Receipt =
                serde_json::from_str(&bytes).context("parse receipt")?;
            memsovereign::verify::verify_receipt(&receipt)?;
            eprintln!("OK");
        }
        Command::Verify { path } => {
            let bytes = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
            let receipt: memsovereign::Receipt =
                serde_json::from_str(&bytes).context("parse receipt")?;
            memsovereign::verify::verify_receipt(&receipt)?;
            memsovereign::verify::verify_chain_up_to(&home, Some(receipt.index))?;
            eprintln!("OK");
        }
        Command::Receipt { cmd } => match cmd {
            ReceiptCommand::Export { index, out } => {
                let receipt = memsovereign::load_receipt(&home, index)?;
                let json = serde_json::to_string_pretty(&receipt)?;
                if let Some(out) = out {
                    std::fs::write(&out, json).with_context(|| format!("write {out:?}"))?;
                } else {
                    println!("{json}");
                }
            }
            ReceiptCommand::Import { path, force } => {
                let bytes =
                    std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
                let receipt: memsovereign::Receipt =
                    serde_json::from_str(&bytes).context("parse receipt")?;
                let dst = memsovereign::paths::receipt_path(&home, receipt.index);
                if dst.exists() && !force {
                    anyhow::bail!("receipt already exists at {dst:?} (use --force to overwrite)");
                }
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create {parent:?}"))?;
                }
                std::fs::write(&dst, bytes).with_context(|| format!("write {dst:?}"))?;
                eprintln!("Imported receipt for index {} -> {:?}", receipt.index, dst);
            }
        },
    }

    Ok(())
}
