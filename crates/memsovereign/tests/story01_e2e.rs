use memsovereign::types::Provenance;

#[test]
fn init_creates_keys_and_refuses_overwrite_without_force() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path();

    let res = memsovereign::init_keys(home, false, &mut memsovereign::os_rng()).unwrap();
    assert!(res.pubkey_fingerprint.len() > 5);

    // Second init should fail without --force.
    let err = memsovereign::init_keys(home, false, &mut memsovereign::os_rng()).unwrap_err();
    assert!(format!("{err:#}").contains("keys already exist"));

    // With --force it should succeed.
    memsovereign::init_keys(home, true, &mut memsovereign::os_rng()).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let secret = home.join("keys/identity_ed25519");
        let mode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(home.join("keys"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
}

#[test]
fn minimal_end_to_end_init_append_verify_chain_and_detect_tamper() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path();

    memsovereign::init_keys(home, false, &mut memsovereign::os_rng()).unwrap();
    memsovereign::verify::verify_chain(home).unwrap();

    let prov = Provenance {
        source_type: Some("test".into()),
        ..Default::default()
    };
    let (_e1, r1) = memsovereign::append_entry(home, "hello", prov.clone(), Vec::new()).unwrap();
    memsovereign::verify::verify_receipt(&r1).unwrap();

    let (_e2, r2) = memsovereign::append_entry(home, "world", prov, Vec::new()).unwrap();
    memsovereign::verify::verify_receipt(&r2).unwrap();

    memsovereign::verify::verify_chain(home).unwrap();

    // Tamper with the first line of the log.
    let path = memsovereign::paths::entries_path(home);
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|s| s.to_string())
        .collect();
    assert!(lines.len() >= 2);
    lines[0] = lines[0].replace("hello", "hxllo"); // might not exist due to encryption, but ensures change.
                                                   // If plaintext isn't present (it shouldn't be), alter a JSON field safely:
    if lines[0].contains("\"source_type\":\"test\"") {
        lines[0] = lines[0].replace("\"test\"", "\"tamper\"");
    } else {
        // Fall back: flip a base64 char in ciphertext.
        lines[0] = lines[0].replacen("ciphertext_b64\":\"", "ciphertext_b64\":\"A", 1);
    }
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = memsovereign::verify::verify_chain(home).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("mismatch"));
}
