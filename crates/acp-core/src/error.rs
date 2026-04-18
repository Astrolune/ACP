//! Error types for ACP operations

use thiserror::Error;

/// Top-level ACP error type
#[derive(Debug, Error)]
pub enum AcpError {
    /// Cipher operation error
    #[error("Cipher error: {0}")]
    Cipher(#[from] CipherError),

    /// Key management error
    #[error("Key error: {0}")]
    Key(#[from] KeyError),

    /// Session error
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
}

/// Cipher operation errors
#[derive(Debug, Error)]
pub enum CipherError {
    /// Encryption operation failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Decryption operation failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Invalid key size for algorithm
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Invalid nonce size
    #[error("Invalid nonce size")]
    InvalidNonceSize,

    /// Authentication tag verification failed
    #[error("Authentication failed")]
    AuthenticationFailed,
}

/// Key management errors
#[derive(Debug, Error)]
pub enum KeyError {
    /// Key generation failed
    #[error("Key generation failed")]
    GenerationFailed,

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),

    /// Invalid key format
    #[error("Invalid key format")]
    InvalidFormat,

    /// Key not found
    #[error("Key not found: {0}")]
    NotFound(String),

    /// Key already exists
    #[error("Key already exists: {0}")]
    AlreadyExists(String),
}

/// Session errors
#[derive(Debug, Error)]
pub enum SessionError {
    /// Session creation failed
    #[error("Session creation failed: {0}")]
    CreationFailed(String),

    /// Session is closed
    #[error("Session is closed")]
    Closed,

    /// Invalid session state
    #[error("Invalid session state")]
    InvalidState,

    /// Cipher error in session
    #[error("Cipher error: {0}")]
    Cipher(#[from] CipherError),
}
