//! AEAD (Authenticated Encryption with Associated Data) implementations

use crate::cipher::Cipher;
use crate::error::CipherError;
use crate::key::{Algorithm, Key};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};

/// AES-256-GCM cipher implementation
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// Create a new AES-256-GCM cipher from a key
    pub fn new(key: &Key) -> Result<Self, CipherError> {
        if key.algorithm() != Algorithm::Aes256Gcm {
            return Err(CipherError::InvalidKeySize {
                expected: Algorithm::Aes256Gcm.key_size(),
                actual: key.as_bytes().len(),
            });
        }

        let key_bytes = aes_gcm::Key::<Aes256Gcm>::from_slice(key.as_bytes());
        let cipher = Aes256Gcm::new(key_bytes);

        Ok(Self { cipher })
    }
}

impl Cipher for Aes256GcmCipher {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        use aes_gcm::aead::AeadCore;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CipherError::EncryptionFailed)?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() < 12 {
            return Err(CipherError::InvalidNonceSize);
        }

        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let nonce = AesNonce::from_slice(nonce_bytes);

        let payload = aes_gcm::aead::Payload { msg: ct, aad };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CipherError::DecryptionFailed)
    }
}

/// ChaCha20-Poly1305 cipher implementation
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new ChaCha20-Poly1305 cipher from a key
    pub fn new(key: &Key) -> Result<Self, CipherError> {
        if key.algorithm() != Algorithm::ChaCha20Poly1305 {
            return Err(CipherError::InvalidKeySize {
                expected: Algorithm::ChaCha20Poly1305.key_size(),
                actual: key.as_bytes().len(),
            });
        }

        let key_bytes = chacha20poly1305::Key::from_slice(key.as_bytes());
        let cipher = ChaCha20Poly1305::new(key_bytes);

        Ok(Self { cipher })
    }
}

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        use chacha20poly1305::aead::AeadCore;

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CipherError::EncryptionFailed)?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() < 12 {
            return Err(CipherError::InvalidNonceSize);
        }

        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let nonce = ChachaNonce::from_slice(nonce_bytes);

        let payload = chacha20poly1305::aead::Payload { msg: ct, aad };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CipherError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = Key::generate(Algorithm::Aes256Gcm).unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let plaintext = b"Hello, ACP!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = Key::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let plaintext = b"Hello, ACP!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = Key::generate(Algorithm::Aes256Gcm).unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let plaintext = b"Hello, ACP!";
        let aad = b"additional data";
        let wrong_aad = b"wrong data";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        let result = cipher.decrypt(&ciphertext, wrong_aad);

        assert!(result.is_err());
    }
}
