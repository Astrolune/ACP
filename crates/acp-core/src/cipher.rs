//! Cipher traits and implementations

use crate::error::CipherError;

/// Core cipher trait for encryption/decryption operations
pub trait Cipher: Send + Sync {
    /// Encrypt plaintext with optional additional authenticated data (AAD)
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError>;

    /// Decrypt ciphertext with optional additional authenticated data (AAD)
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError>;
}

/// Factory trait for creating cipher instances
pub trait CipherFactory {
    /// The cipher type this factory creates
    type Cipher: Cipher;

    /// Create a new cipher instance with the given key
    fn create(&self, key: &crate::key::Key) -> Result<Self::Cipher, CipherError>;
}
