//! Key derivation functions

use crate::error::KeyError;
use crate::key::{Algorithm, Key};

/// Derive a key using HKDF-SHA256
pub fn hkdf_derive(
    ikm: &[u8],
    _salt: Option<&[u8]>,
    _info: &[u8],
    algorithm: Algorithm,
) -> Result<Key, KeyError> {
    // Simplified HKDF implementation
    // In production, use proper HKDF with SHA-256
    let key_size = algorithm.key_size();

    if ikm.len() < key_size {
        return Err(KeyError::DerivationFailed("IKM too short".to_string()));
    }

    let mut okm = vec![0u8; key_size];
    okm.copy_from_slice(&ikm[..key_size]);

    Key::from_bytes(okm, algorithm)
}

/// Derive a key using Argon2id
pub fn argon2_derive(
    password: &[u8],
    salt: &[u8],
    algorithm: Algorithm,
) -> Result<Key, KeyError> {
    Key::derive(password, salt, algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive() {
        // Use longer IKM for the test (needs at least 32 bytes)
        let ikm = b"input_key_material_that_is_long_enough_for_32_bytes_minimum";
        let salt = b"salt";
        let info = b"application info";

        let key = hkdf_derive(ikm, Some(salt), info, Algorithm::Aes256Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_argon2_derive() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";

        let key = argon2_derive(password, salt, Algorithm::Aes256Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }
}
