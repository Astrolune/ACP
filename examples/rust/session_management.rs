//! Session management example

use acp_core::{Algorithm, InMemoryKeyManager, Key, KeyManager, Session};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ACP Session Management Example\n");

    // Create key manager
    let mut key_manager = InMemoryKeyManager::new();
    println!("Key manager created\n");

    // Generate and store keys
    println!("=== Generating Keys ===");
    key_manager.generate_key("session-1", Algorithm::Aes256Gcm)?;
    key_manager.generate_key("session-2", Algorithm::ChaCha20Poly1305)?;
    println!("✓ Generated 2 keys\n");

    // Create sessions
    println!("=== Creating Sessions ===");
    let key1 = key_manager.get_key("session-1")?;
    let session1 = Session::new(&key1, "session-1".to_string())?;
    println!("Session 1: {} ({})", session1.metadata().id, format!("{:?}", session1.metadata().algorithm));

    let key2 = key_manager.get_key("session-2")?;
    let session2 = Session::new(&key2, "session-2".to_string())?;
    println!("Session 2: {} ({})\n", session2.metadata().id, format!("{:?}", session2.metadata().algorithm));

    // Use sessions
    println!("=== Using Sessions ===");
    let message1 = b"Message for session 1";
    let ciphertext1 = session1.encrypt(message1)?;
    println!("Session 1 encrypted: {} bytes", ciphertext1.len());

    let message2 = b"Message for session 2";
    let ciphertext2 = session2.encrypt(message2)?;
    println!("Session 2 encrypted: {} bytes\n", ciphertext2.len());

    // Decrypt
    println!("=== Decrypting ===");
    let decrypted1 = session1.decrypt(&ciphertext1)?;
    println!("Session 1: {}", String::from_utf8_lossy(&decrypted1));

    let decrypted2 = session2.decrypt(&ciphertext2)?;
    println!("Session 2: {}\n", String::from_utf8_lossy(&decrypted2));

    // Verify
    assert_eq!(message1, decrypted1.as_slice());
    assert_eq!(message2, decrypted2.as_slice());
    println!("✓ All sessions working correctly");

    // Cleanup
    key_manager.delete_key("session-1")?;
    key_manager.delete_key("session-2")?;
    println!("✓ Keys cleaned up");

    Ok(())
}
