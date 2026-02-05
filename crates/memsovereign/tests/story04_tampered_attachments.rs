use memsovereign::types::{Attachment, Provenance};
use rand_core::OsRng;

#[test]
fn verify_chain_detects_tampered_attachment_metadata() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path();

    memsovereign::init_keys(home, false, OsRng).unwrap();

    // Create a small file and attach it.
    let p = home.join("sample.txt");
    std::fs::write(&p, b"hello attachments").unwrap();

    // Compute sha256 for metadata.
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(b"hello attachments");
    let digest = hasher.finalize();
    let sha256_b64 = memsovereign::crypto::b64(digest.as_slice());

    let attachments = vec![Attachment {
        kind: "file".to_string(),
        name: "sample.txt".to_string(),
        locator: format!("file:{}", p.to_string_lossy()),
        sha256_b64: Some(sha256_b64),
        size_bytes: Some(17),
        content_type: Some("text/plain".to_string()),
    }];

    memsovereign::append_entry(
        home,
        "entry with attachment",
        Provenance::default(),
        attachments,
        OsRng,
    )
    .unwrap();

    memsovereign::verify::verify_chain(home).unwrap();

    // Tamper the stored attachment metadata in the log.
    let path = memsovereign::paths::entries_path(home);
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(lines.len(), 1);

    // Change the attachment name.
    lines[0] = lines[0].replace("sample.txt", "sample-TAMPERED.txt");
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = memsovereign::verify::verify_chain(home).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("mismatch"));
}
