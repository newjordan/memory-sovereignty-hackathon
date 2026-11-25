use memsovereign::types::Provenance;

#[test]
fn verify_receipt_rejects_tampered_signature() {
    let td = tempfile::tempdir().unwrap();
    let home = td.path();

    memsovereign::init_keys(home, false, &mut memsovereign::os_rng()).unwrap();

    let (_entry, mut receipt) =
        memsovereign::append_entry(home, "hello", Provenance::default(), Vec::new()).unwrap();
    memsovereign::verify::verify_receipt(&receipt).unwrap();

    // Flip one bit of the signature.
    let mut sig = memsovereign::crypto::b64_decode(&receipt.signature_b64).unwrap();
    assert!(!sig.is_empty());
    sig[0] ^= 0b0000_0001;
    receipt.signature_b64 = memsovereign::crypto::b64(&sig);

    let err = memsovereign::verify::verify_receipt(&receipt).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("signature"));
}
