//! Session management

use crate::cipher::Cipher;
use crate::error::SessionError;
use crate::key::{Algorithm, Key};
use crate::primitives::{Aes256GcmCipher, ChaCha20Poly1305Cipher};

/// Session metadata
#[derive(Debug, Clone)]
pub struct SessionMetadata {
    /// Session identifier
    pub id: String,
    /// Algorithm used
    pub algorithm: Algorithm,
    /// Creation timestamp (Unix epoch)
    pub created_at: u64,
}

/// Encryption session
pub struct Session {
    cipher: Box<dyn Cipher>,
    metadata: SessionMetadata,
}

impl Session {
    /// Create a new session with the given key and algorithm
    pub fn new(key: &Key, id: String) -> Result<Self, SessionError> {
        let algorithm = key.algorithm();

        let cipher: Box<dyn Cipher> = match algorithm {
            Algorithm::Aes256Gcm => {
                Box::new(Aes256GcmCipher::new(key).map_err(|e| {
                    SessionError::CreationFailed(format!("Failed to create AES-GCM cipher: {}", e))
                })?)
            }
            Algorithm::ChaCha20Poly1305 => {
                Box::new(ChaCha20Poly1305Cipher::new(key).map_err(|e| {
                    SessionError::CreationFailed(format!(
                        "Failed to create ChaCha20-Poly1305 cipher: {}",
                        e
                    ))
                })?)
            }
        };

        let metadata = SessionMetadata {
            id,
            algorithm,
            created_at: current_timestamp(),
        };

        Ok(Self { cipher, metadata })
    }

    /// Encrypt plaintext
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.cipher.encrypt(plaintext, &[]).map_err(Into::into)
    }

    /// Encrypt plaintext with additional authenticated data
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.cipher.encrypt(plaintext, aad).map_err(Into::into)
    }

    /// Decrypt ciphertext
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.cipher.decrypt(ciphertext, &[]).map_err(Into::into)
    }

    /// Decrypt ciphertext with additional authenticated data
    pub fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        self.cipher.decrypt(ciphertext, aad).map_err(Into::into)
    }

    /// Get session metadata
    pub fn metadata(&self) -> &SessionMetadata {
        &self.metadata
    }
}

#[cfg(feature = "std")]
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(not(feature = "std"))]
fn current_timestamp() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_encrypt_decrypt() {
        let key = Key::generate(Algorithm::Aes256Gcm).unwrap();
        let session = Session::new(&key, "test-session".to_string()).unwrap();

        let plaintext = b"Hello, Session!";
        let ciphertext = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_session_with_aad() {
        let key = Key::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let session = Session::new(&key, "test-session".to_string()).unwrap();

        let plaintext = b"Hello, Session!";
        let aad = b"metadata";

        let ciphertext = session.encrypt_with_aad(plaintext, aad).unwrap();
        let decrypted = session.decrypt_with_aad(&ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
