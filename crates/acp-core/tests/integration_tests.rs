//! Integration tests for acp-core

use acp_core::{Algorithm, InMemoryKeyManager, Key, KeyManager, Session};

#[test]
fn test_full_encryption_flow() {
    let key = Key::generate(Algorithm::Aes256Gcm).unwrap();
    let session = Session::new(&key, "test-session".to_string()).unwrap();

    let plaintext = b"Integration test message";
    let ciphertext = session.encrypt(plaintext).unwrap();
    let decrypted = session.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_cross_algorithm_isolation() {
    let key1 = Key::generate(Algorithm::Aes256Gcm).unwrap();
    let key2 = Key::generate(Algorithm::ChaCha20Poly1305).unwrap();

    let session1 = Session::new(&key1, "session-1".to_string()).unwrap();
    let session2 = Session::new(&key2, "session-2".to_string()).unwrap();

    let plaintext = b"Test message";

    let ciphertext1 = session1.encrypt(plaintext).unwrap();
    let ciphertext2 = session2.encrypt(plaintext).unwrap();

    // Ciphertexts should be different
    assert_ne!(ciphertext1, ciphertext2);

    // Each session can decrypt its own ciphertext
    assert_eq!(plaintext, session1.decrypt(&ciphertext1).unwrap().as_slice());
    assert_eq!(plaintext, session2.decrypt(&ciphertext2).unwrap().as_slice());

    // Cross-decryption should fail
    assert!(session1.decrypt(&ciphertext2).is_err());
    assert!(session2.decrypt(&ciphertext1).is_err());
}

#[test]
fn test_key_manager_workflow() {
    let mut manager = InMemoryKeyManager::new();

    // Generate keys
    manager.generate_key("key1", Algorithm::Aes256Gcm).unwrap();
    manager.generate_key("key2", Algorithm::ChaCha20Poly1305).unwrap();

    assert!(manager.has_key("key1"));
    assert!(manager.has_key("key2"));

    // Use keys
    let key1 = manager.get_key("key1").unwrap();
    let session1 = Session::new(&key1, "session-1".to_string()).unwrap();

    let plaintext = b"Key manager test";
    let ciphertext = session1.encrypt(plaintext).unwrap();
    let decrypted = session1.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());

    // Delete keys
    manager.delete_key("key1").unwrap();
    assert!(!manager.has_key("key1"));
    assert!(manager.get_key("key1").is_err());
}

#[test]
fn test_aad_authentication() {
    let key = Key::generate(Algorithm::Aes256Gcm).unwrap();
    let session = Session::new(&key, "aad-test".to_string()).unwrap();

    let plaintext = b"Message with AAD";
    let aad = b"metadata";
    let wrong_aad = b"wrong_metadata";

    let ciphertext = session.encrypt_with_aad(plaintext, aad).unwrap();

    // Correct AAD should work
    let decrypted = session.decrypt_with_aad(&ciphertext, aad).unwrap();
    assert_eq!(plaintext, decrypted.as_slice());

    // Wrong AAD should fail
    assert!(session.decrypt_with_aad(&ciphertext, wrong_aad).is_err());
}

#[test]
fn test_key_derivation_determinism() {
    let password = b"test_password";
    let salt = b"test_salt_123456";

    let key1 = Key::derive(password, salt, Algorithm::Aes256Gcm).unwrap();
    let key2 = Key::derive(password, salt, Algorithm::Aes256Gcm).unwrap();

    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_empty_plaintext() {
    let key = Key::generate(Algorithm::ChaCha20Poly1305).unwrap();
    let session = Session::new(&key, "empty-test".to_string()).unwrap();

    let plaintext = b"";
    let ciphertext = session.encrypt(plaintext).unwrap();
    let decrypted = session.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_large_plaintext() {
    let key = Key::generate(Algorithm::Aes256Gcm).unwrap();
    let session = Session::new(&key, "large-test".to_string()).unwrap();

    let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MB
    let ciphertext = session.encrypt(&plaintext).unwrap();
    let decrypted = session.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, decrypted);
}
