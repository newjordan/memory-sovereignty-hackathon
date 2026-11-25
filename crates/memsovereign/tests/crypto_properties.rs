use memsovereign::crypto::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305};
use memsovereign::types::Provenance;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_seal_round_trip_wrong_key_and_tamper(
        key in proptest::collection::vec(any::<u8>(), 32),
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        aad in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let key: [u8; 32] = key.as_slice().try_into().unwrap();
        let (nonce, ciphertext) = encrypt_xchacha20poly1305(&key, &plaintext, &aad).unwrap();
        let opened = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, &aad).unwrap();
        prop_assert_eq!(&opened, &plaintext);

        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        prop_assert!(decrypt_xchacha20poly1305(&wrong_key, &nonce, &ciphertext, &aad).is_err());

        let mut bad_ciphertext = ciphertext.clone();
        let flip_at = ciphertext.len() / 2;
        bad_ciphertext[flip_at] ^= 0x01;
        prop_assert!(decrypt_xchacha20poly1305(&key, &nonce, &bad_ciphertext, &aad).is_err());

        let mut bad_aad = aad.clone();
        bad_aad.push(1);
        prop_assert!(decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, &bad_aad).is_err());

        let (nonce2, ciphertext2) = encrypt_xchacha20poly1305(&key, &plaintext, &aad).unwrap();
        prop_assert_ne!(nonce, nonce2);
        prop_assert_ne!(ciphertext, ciphertext2);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_log_round_trip_and_byte_tamper(contents in prop::collection::vec("[ -~]{0,60}", 1..5)) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        memsovereign::init_keys(home, false, &mut memsovereign::os_rng()).unwrap();
        for content in &contents {
            memsovereign::append_entry(home, content, Provenance::default(), Vec::new()).unwrap();
        }
        memsovereign::verify::verify_chain(home).unwrap();

        let keys = memsovereign::load_keys(home).unwrap();
        let entries = memsovereign::read_entries(home).unwrap();
        prop_assert_eq!(entries.len(), contents.len());
        for (entry, expected) in entries.iter().zip(contents.iter()) {
            let opened = memsovereign::open_entry(&keys.content_key, entry).unwrap();
            prop_assert_eq!(opened, expected.as_bytes());
        }

        let mut wrong = keys.content_key;
        wrong[7] ^= 0xa5;
        prop_assert!(memsovereign::open_entry(&wrong, &entries[0]).is_err());

        let path = memsovereign::paths::entries_path(home);
        let mut raw = std::fs::read(&path).unwrap();
        let flip_at = raw.len() / 2;
        raw[flip_at] ^= 0x01;
        std::fs::write(&path, raw).unwrap();
        prop_assert!(memsovereign::verify::verify_chain(home).is_err());
    }
}
