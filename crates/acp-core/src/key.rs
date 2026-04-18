//! Key management and derivation

use crate::error::KeyError;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::BTreeMap;

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl Algorithm {
    /// Returns the required key size in bytes
    pub const fn key_size(self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 32,
            Algorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Returns the nonce size in bytes
    pub const fn nonce_size(self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 12,
        }
    }
}

/// Cryptographic key with automatic zeroing
pub struct Key {
    bytes: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
}

impl Key {
    /// Generate a new random key for the specified algorithm
    pub fn generate(algorithm: Algorithm) -> Result<Self, KeyError> {
        use aes_gcm::aead::OsRng;
        use aes_gcm::aead::rand_core::RngCore;

        let key_size = algorithm.key_size();
        let mut bytes = vec![0u8; key_size];
        OsRng.fill_bytes(&mut bytes);

        Ok(Self {
            bytes: Zeroizing::new(bytes),
            algorithm,
        })
    }

    /// Create a key from raw bytes
    pub fn from_bytes(bytes: Vec<u8>, algorithm: Algorithm) -> Result<Self, KeyError> {
        if bytes.len() != algorithm.key_size() {
            return Err(KeyError::InvalidFormat);
        }

        Ok(Self {
            bytes: Zeroizing::new(bytes),
            algorithm,
        })
    }

    /// Derive a key from a password using Argon2
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, KeyError> {
        use argon2::Argon2;

        let mut output = vec![0u8; algorithm.key_size()];

        Argon2::default()
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| KeyError::DerivationFailed(e.to_string()))?;

        Ok(Self {
            bytes: Zeroizing::new(output),
            algorithm,
        })
    }

    /// Get key bytes as slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the algorithm this key is for
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Key manager trait for storing and retrieving keys
pub trait KeyManager: Send + Sync {
    /// Generate and store a new key
    fn generate_key(&mut self, id: &str, algorithm: Algorithm) -> Result<(), KeyError>;

    /// Retrieve a key by ID
    fn get_key(&self, id: &str) -> Result<Key, KeyError>;

    /// Delete a key by ID
    fn delete_key(&mut self, id: &str) -> Result<(), KeyError>;

    /// Check if a key exists
    fn has_key(&self, id: &str) -> bool;
}

/// In-memory key manager implementation
#[cfg(feature = "std")]
pub struct InMemoryKeyManager {
    keys: HashMap<String, Key>,
}

#[cfg(feature = "std")]
impl InMemoryKeyManager {
    /// Create a new in-memory key manager
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

#[cfg(feature = "std")]
impl Default for InMemoryKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl KeyManager for InMemoryKeyManager {
    fn generate_key(&mut self, id: &str, algorithm: Algorithm) -> Result<(), KeyError> {
        if self.keys.contains_key(id) {
            return Err(KeyError::AlreadyExists(id.to_string()));
        }

        let key = Key::generate(algorithm)?;
        self.keys.insert(id.to_string(), key);
        Ok(())
    }

    fn get_key(&self, id: &str) -> Result<Key, KeyError> {
        self.keys
            .get(id)
            .map(|k| Key::from_bytes(k.as_bytes().to_vec(), k.algorithm()))
            .transpose()?
            .ok_or_else(|| KeyError::NotFound(id.to_string()))
    }

    fn delete_key(&mut self, id: &str) -> Result<(), KeyError> {
        self.keys
            .remove(id)
            .ok_or_else(|| KeyError::NotFound(id.to_string()))?;
        Ok(())
    }

    fn has_key(&self, id: &str) -> bool {
        self.keys.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Key::generate(Algorithm::Aes256Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_derivation() {
        let password = b"test_password";
        let salt = b"test_salt_16byte";

        let key = Key::derive(password, salt, Algorithm::Aes256Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_manager() {
        let mut manager = InMemoryKeyManager::new();

        manager.generate_key("test", Algorithm::Aes256Gcm).unwrap();
        assert!(manager.has_key("test"));

        let key = manager.get_key("test").unwrap();
        assert_eq!(key.algorithm(), Algorithm::Aes256Gcm);

        manager.delete_key("test").unwrap();
        assert!(!manager.has_key("test"));
    }
}
