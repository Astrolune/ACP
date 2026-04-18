#![no_main]

use libfuzzer_sys::fuzz_target;
use acp_core::{Algorithm, Key, Session};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Split data into key material and plaintext
    let (key_bytes, plaintext) = data.split_at(32);

    // Try both algorithms
    for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
        if let Ok(key) = Key::from_bytes(key_bytes.to_vec(), algorithm) {
            if let Ok(session) = Session::new(&key, "fuzz-session".to_string()) {
                // Encrypt
                if let Ok(ciphertext) = session.encrypt(plaintext) {
                    // Decrypt
                    let _ = session.decrypt(&ciphertext);
                }

                // Try with AAD
                if plaintext.len() > 16 {
                    let (pt, aad) = plaintext.split_at(plaintext.len() / 2);
                    if let Ok(ciphertext) = session.encrypt_with_aad(pt, aad) {
                        let _ = session.decrypt_with_aad(&ciphertext, aad);
                    }
                }
            }
        }
    }
});
