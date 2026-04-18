#![no_main]

use libfuzzer_sys::fuzz_target;
use acp_core::{Algorithm, Key};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Try key generation (should never panic)
    let _ = Key::generate(Algorithm::Aes256Gcm);
    let _ = Key::generate(Algorithm::ChaCha20Poly1305);

    // Try key derivation with fuzzed inputs
    let (password, rest) = data.split_at(data.len() / 2);
    if rest.len() >= 16 {
        let salt = &rest[..16];
        let _ = Key::derive(password, salt, Algorithm::Aes256Gcm);
        let _ = Key::derive(password, salt, Algorithm::ChaCha20Poly1305);
    }

    // Try creating keys from arbitrary bytes
    if data.len() >= 32 {
        let _ = Key::from_bytes(data[..32].to_vec(), Algorithm::Aes256Gcm);
        let _ = Key::from_bytes(data[..32].to_vec(), Algorithm::ChaCha20Poly1305);
    }
});
