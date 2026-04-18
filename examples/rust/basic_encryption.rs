//! Basic encryption example

use acp_core::{Algorithm, Key, Session};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ACP Basic Encryption Example\n");

    // Generate a key
    println!("Generating AES-256-GCM key...");
    let key = Key::generate(Algorithm::Aes256Gcm)?;
    println!("Key generated: {} bytes\n", key.as_bytes().len());

    // Create a session
    println!("Creating encryption session...");
    let session = Session::new(&key, "example-session".to_string())?;
    println!("Session created: {}\n", session.metadata().id);

    // Encrypt data
    let plaintext = b"Hello, ACP! This is a secret message.";
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    let ciphertext = session.encrypt(plaintext)?;
    println!("Ciphertext: {} bytes", ciphertext.len());
    println!("Ciphertext (hex): {}\n", hex::encode(&ciphertext));

    // Decrypt data
    println!("Decrypting...");
    let decrypted = session.decrypt(&ciphertext)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Verify
    assert_eq!(plaintext, decrypted.as_slice());
    println!("\n✓ Encryption/decryption successful!");

    Ok(())
}
