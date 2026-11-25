use memsovereign::crypto::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305};
use memsovereign::types::Provenance;

fn key() -> [u8; 32] {
    [0x11; 32]
}

#[test]
fn encryption_round_trip_rejects_wrong_key_and_tampering() {
    let key = key();
    let aad = b"memsovereign-test-aad";
    let plaintext = b"local memory";
    let (nonce, ciphertext) = encrypt_xchacha20poly1305(&key, plaintext, aad).unwrap();
    let opened = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(opened, plaintext);

    let mut wrong_key = key;
    wrong_key[0] ^= 0xff;
    assert!(decrypt_xchacha20poly1305(&wrong_key, &nonce, &ciphertext, aad).is_err());

    let mut bad_ciphertext = ciphertext.clone();
    bad_ciphertext[0] ^= 0x01;
    assert!(decrypt_xchacha20poly1305(&key, &nonce, &bad_ciphertext, aad).is_err());

    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 0x01;
    assert!(decrypt_xchacha20poly1305(&key, &bad_nonce, &ciphertext, aad).is_err());

    assert!(decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, b"other aad").is_err());
}

#[test]
fn two_seals_use_distinct_nonces() {
    let key = key();
    let (nonce_a, ct_a) = encrypt_xchacha20poly1305(&key, b"same", b"aad").unwrap();
    let (nonce_b, ct_b) = encrypt_xchacha20poly1305(&key, b"same", b"aad").unwrap();
    assert_ne!(nonce_a, nonce_b);
    assert_ne!(ct_a, ct_b);
}

#[test]
fn open_entry_round_trip_and_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    memsovereign::init_keys(home, false, &mut memsovereign::os_rng()).unwrap();
    memsovereign::append_entry(home, "hello", Provenance::default(), Vec::new()).unwrap();

    let keys = memsovereign::load_keys(home).unwrap();
    let entry = &memsovereign::read_entries(home).unwrap()[0];
    let opened = memsovereign::open_entry(&keys.content_key, entry).unwrap();
    assert_eq!(opened, b"hello");

    let mut wrong = keys.content_key;
    wrong[3] ^= 0x5a;
    assert!(memsovereign::open_entry(&wrong, entry).is_err());

    let mut tampered = entry.clone();
    tampered.provenance.source_type = Some("changed".into());
    assert!(memsovereign::open_entry(&keys.content_key, &tampered).is_err());
}
