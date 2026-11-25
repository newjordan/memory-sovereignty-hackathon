use memsovereign::crypto::{b64, entry_hash};
use memsovereign::types::{Entry, EntryUnsigned, Provenance};

fn init_home(home: &std::path::Path) {
    memsovereign::init_keys(home, false, &mut memsovereign::os_rng()).unwrap();
}

fn append(home: &std::path::Path, content: &str) {
    memsovereign::append_entry(home, content, Provenance::default(), Vec::new()).unwrap();
}

#[test]
fn recomputed_hash_without_a_new_signature_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    init_home(home);
    append(home, "original");

    let path = memsovereign::paths::entries_path(home);
    let mut entry: Entry = serde_json::from_str(
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    entry.created_at = "2000-01-01T00:00:00Z".into();
    let digest = entry_hash(&EntryUnsigned::from_entry(&entry)).unwrap();
    entry.entry_hash_b64 = b64(&digest);
    std::fs::write(&path, serde_json::to_string(&entry).unwrap() + "\n").unwrap();

    let err = memsovereign::verify::verify_chain(home).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("signature"),
        "rewritten hash must fail the entry signature, got {msg}"
    );
}

#[test]
fn truncating_the_log_fails_the_signed_head() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    init_home(home);
    append(home, "one");
    append(home, "two");
    memsovereign::verify::verify_chain(home).unwrap();

    let path = memsovereign::paths::entries_path(home);
    let lines: Vec<_> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 2);
    std::fs::write(&path, lines[0].clone() + "\n").unwrap();

    let err = memsovereign::verify::verify_chain(home).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("head"),
        "truncation must fail the signed head, got {msg}"
    );
}

#[test]
fn missing_head_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    init_home(home);
    append(home, "one");
    std::fs::remove_file(memsovereign::paths::head_path(home)).unwrap();
    let err = memsovereign::verify::verify_chain(home).unwrap_err();
    assert!(format!("{err:#}").contains("head"));
}

#[test]
fn one_signed_entry_ahead_of_a_saved_head_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    init_home(home);
    append(home, "one");
    let saved_head = std::fs::read(memsovereign::paths::head_path(home)).unwrap();
    append(home, "two");
    std::fs::write(memsovereign::paths::head_path(home), saved_head).unwrap();
    memsovereign::verify::verify_chain(home).unwrap();
}

#[test]
fn receipt_must_match_the_local_entry() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    init_home(dir_a.path());
    init_home(dir_b.path());
    let (_entry, receipt) =
        memsovereign::append_entry(dir_a.path(), "alpha", Provenance::default(), Vec::new())
            .unwrap();
    memsovereign::append_entry(dir_b.path(), "beta", Provenance::default(), Vec::new()).unwrap();

    memsovereign::verify::verify_receipt_against_log(dir_a.path(), &receipt).unwrap();
    let err = memsovereign::verify::verify_receipt_against_log(dir_b.path(), &receipt).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("public key") || msg.contains("does not match"),
        "foreign receipt must not verify against another log, got {msg}"
    );
}

#[test]
fn bitflip_in_the_log_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    init_home(home);
    append(home, "payload");
    let path = memsovereign::paths::entries_path(home);
    let mut bytes = std::fs::read(&path).unwrap();
    let index = bytes.len() / 2;
    bytes[index] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();
    assert!(memsovereign::verify::verify_chain(home).is_err());
}
