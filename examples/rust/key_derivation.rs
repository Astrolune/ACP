//! Key derivation example

use acp_core::{Algorithm, Key};
use acp_core::primitives::kdf::{argon2_derive, hkdf_derive};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ACP Key Derivation Example\n");

    // Argon2 key derivation
    println!("=== Argon2 Key Derivation ===");
    let password = b"my_secure_password";
    let salt = b"random_salt_1234";

    let key1 = argon2_derive(password, salt, Algorithm::Aes256Gcm)?;
    println!("Derived key (Argon2): {} bytes", key1.as_bytes().len());
    println!("Key (hex): {}\n", hex::encode(key1.as_bytes()));

    // HKDF key derivation
    println!("=== HKDF Key Derivation ===");
    let ikm = b"input_key_material";
    let salt = b"hkdf_salt";
    let info = b"application_context";

    let key2 = hkdf_derive(ikm, Some(salt), info, Algorithm::ChaCha20Poly1305)?;
    println!("Derived key (HKDF): {} bytes", key2.as_bytes().len());
    println!("Key (hex): {}\n", hex::encode(key2.as_bytes()));

    // Verify determinism
    println!("=== Verifying Determinism ===");
    let key1_again = argon2_derive(password, salt, Algorithm::Aes256Gcm)?;
    assert_eq!(key1.as_bytes(), key1_again.as_bytes());
    println!("✓ Argon2 derivation is deterministic");

    let key2_again = hkdf_derive(ikm, Some(salt), info, Algorithm::ChaCha20Poly1305)?;
    assert_eq!(key2.as_bytes(), key2_again.as_bytes());
    println!("✓ HKDF derivation is deterministic");

    Ok(())
}
